import { Node, SyntaxKind, type SourceFile } from "ts-morph"
import { getCallCalleeName, lineContentOf, lineOf } from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// Math.random() returns a pseudo-random number suitable for shuffles and
// game logic — NOT for security tokens. Its state is predictable from a
// few observed outputs (v8 uses xorshift128+), so any value used as an
// auth/session/CSRF token is forgeable. AI assistants generate this
// pattern when asked to "create a random token" because it's the
// shortest answer they know.

// Identifier / property names that signal the random output is being
// used in a security context. We REQUIRE one of these to be in scope to
// avoid FP on shuffle / animation / test seed uses.
const SECURITY_TOKEN_NAMES = new Set([
  "token",
  "secret",
  "session",
  "sessionid",
  "session_id",
  "sessionId",
  "csrf",
  "csrftoken",
  "csrf_token",
  "csrfToken",
  "nonce",
  "salt",
  "apiKey",
  "api_key",
  "apikey",
  "resetToken",
  "reset_token",
  "verificationCode",
  "verification_code",
  "otp",
  "magicLink",
  "magic_link",
  "uuid",
])

function nameMatches(name: string, isFunctionName: boolean): boolean {
  const lower = name.toLowerCase()
  if (SECURITY_TOKEN_NAMES.has(name) || SECURITY_TOKEN_NAMES.has(lower)) return true
  // Function names commonly take the form generateOtp / makeSessionId /
  // createNonce — substring-match for those slots only, since prefixes
  // like "generate" / "make" / "create" are extremely common.
  if (isFunctionName) {
    for (const tok of SECURITY_TOKEN_NAMES) {
      if (lower.includes(tok.toLowerCase())) return true
    }
  }
  return false
}

// Find the nearest enclosing variable declaration or property assignment
// so we can read the LHS identifier name. If the Math.random call is
// embedded in a larger expression, walk up until we find a context that
// names what the result becomes.
type HostContext = { name: string; isFunctionName: boolean }

function nameOfHostContext(node: Node): HostContext | null {
  let current: Node | undefined = node
  while (current) {
    if (current.isKind(SyntaxKind.VariableDeclaration)) {
      const nameNode = current.getNameNode()
      if (nameNode.isKind(SyntaxKind.Identifier)) {
        return { name: nameNode.getText(), isFunctionName: false }
      }
      return null
    }
    if (current.isKind(SyntaxKind.PropertyAssignment)) {
      return { name: current.getName(), isFunctionName: false }
    }
    if (current.isKind(SyntaxKind.BinaryExpression)) {
      // Assignment: `obj.token = Math.random()...`
      if (current.getOperatorToken().getKind() === SyntaxKind.EqualsToken) {
        const left = current.getLeft()
        if (left.isKind(SyntaxKind.PropertyAccessExpression)) {
          return { name: left.getName(), isFunctionName: false }
        }
        if (left.isKind(SyntaxKind.Identifier)) {
          return { name: left.getText(), isFunctionName: false }
        }
      }
    }
    // Function: `function generateOtp() { return Math.random()... }`
    if (current.isKind(SyntaxKind.FunctionDeclaration)) {
      const nm = current.getName()
      if (nm) return { name: nm, isFunctionName: true }
    }
    current = current.getParent()
  }
  return null
}

const MATH_RANDOM_RULE: AstRule = {
  id: "ast/math-random-for-security-token",
  name: "Insecure randomness: Math.random() used to generate a security token",
  severity: "critical",
  category: "weak-crypto",
  cwe: "CWE-338",
  description:
    "Math.random() is a pseudo-random number generator with predictable state — V8 uses xorshift128+, and a handful of observed outputs lets an attacker reproduce the entire stream. Using it for a token / session / csrf / nonce / salt / api-key / reset-token / otp / uuid means the value is forgeable. Use crypto.randomBytes(N).toString('hex') in Node, or crypto.getRandomValues(new Uint8Array(N)) in the browser / edge runtime. For uuids specifically use crypto.randomUUID().",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const name = getCallCalleeName(call)
      if (name !== "Math.random") continue
      const host = nameOfHostContext(call)
      if (!host) continue
      if (!nameMatches(host.name, host.isFunctionName)) continue
      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(MATH_RANDOM_RULE)

export { MATH_RANDOM_RULE }
