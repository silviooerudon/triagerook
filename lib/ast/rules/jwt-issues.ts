import { Node, SyntaxKind, type SourceFile } from "ts-morph"
import { getCallCalleeName, lineContentOf, lineOf } from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// jsonwebtoken.sign signature: sign(payload, secretOrPrivateKey, [options]).
// We flag two issues independently so the SARIF rule id distinguishes
// them: the absence of expiresAt in options, and the use of a literal
// string as the secret.

function getOptionsArg(call: Node): Node | null {
  if (!call.isKind(SyntaxKind.CallExpression)) return null
  const args = call.getArguments()
  if (args.length < 3) return null
  return args[2]
}

function optionsObjectHasExpiresIn(opts: Node): boolean {
  if (!opts.isKind(SyntaxKind.ObjectLiteralExpression)) return true // unknown shape — don't flag
  for (const prop of opts.getProperties()) {
    if (!prop.isKind(SyntaxKind.PropertyAssignment)) {
      // Shorthand `{ expiresIn }` is a ShorthandPropertyAssignment.
      if (prop.isKind(SyntaxKind.ShorthandPropertyAssignment)) {
        if (prop.getName() === "expiresIn") return true
      }
      continue
    }
    if (prop.getName() === "expiresIn") return true
  }
  return false
}

// True for callees like jwt.sign / jsonwebtoken.sign / jwt.encode where
// the LAST segment is `sign`. We don't try to bind-resolve which jwt
// library — the surface is consistent across them.
function isJwtSignCall(call: Node): boolean {
  if (!call.isKind(SyntaxKind.CallExpression)) return false
  const name = getCallCalleeName(call)
  if (!name) return false
  const parts = name.split(".")
  if (parts.length !== 2) return false
  const [obj, method] = parts
  if (method !== "sign") return false
  return obj === "jwt" || obj === "jsonwebtoken" || obj === "JWT"
}

const JWT_NO_EXPIRES_IN: AstRule = {
  id: "ast/jwt-sign-no-expires-in",
  name: "JWT signed without expiresIn — token lives forever",
  severity: "high",
  category: "jwt",
  cwe: "CWE-613",
  description:
    "jwt.sign(payload, secret) was called without an `expiresIn` option (or with no options object at all). A JWT without expiry stays valid until the secret is rotated — a compromised token has no natural decay. Pass `{ expiresIn: '15m' }` (or your chosen window) as the third argument. Refresh-token flows should use short access tokens explicitly.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (!isJwtSignCall(call)) continue
      const opts = getOptionsArg(call)
      if (!opts) {
        // No options arg at all → no expiresIn → flag.
        hits.push({
          lineNumber: lineOf(call),
          lineContent: lineContentOf(call, sourceFile),
        })
        continue
      }
      if (optionsObjectHasExpiresIn(opts)) continue
      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }
    return hits
  },
}

const JWT_HARDCODED_SECRET: AstRule = {
  id: "ast/jwt-sign-hardcoded-secret",
  name: "JWT signed with a hardcoded string secret",
  severity: "critical",
  category: "hardcoded-creds",
  cwe: "CWE-798",
  description:
    "jwt.sign(payload, '<string literal>') was called with the signing secret hard-coded into the source. Any reader of the repo (or the bundled JS in browser dev tools) can forge tokens. Load the secret from process.env at runtime, and rotate it the moment any committed-secret leak is suspected.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (!isJwtSignCall(call)) continue
      const args = call.getArguments()
      if (args.length < 2) continue
      const secretArg = args[1]
      if (
        !secretArg.isKind(SyntaxKind.StringLiteral) &&
        !secretArg.isKind(SyntaxKind.NoSubstitutionTemplateLiteral)
      ) {
        continue
      }
      // Common placeholder fixtures we DON'T want to flag in test files —
      // empty string already isn't a literal secret. We do flag short
      // strings though because real apps DO ship "secret" or "key".
      const text = secretArg.getLiteralText()
      if (text.length === 0) continue

      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(JWT_NO_EXPIRES_IN)
registerAstRule(JWT_HARDCODED_SECRET)

export { JWT_NO_EXPIRES_IN, JWT_HARDCODED_SECRET }
