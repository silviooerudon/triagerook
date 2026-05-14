import { Node, SyntaxKind, type SourceFile } from "ts-morph"
import { lineContentOf, lineOf } from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// Identifier / property names whose `==` comparison is timing-attackable.
// We flag direct `===` / `==` because the JS string comparison short-
// circuits on the first differing byte — an attacker can shape the
// remote response time to learn the secret one byte at a time.
const TIMING_SENSITIVE_NAMES = new Set([
  "password",
  "passwd",
  "pwd",
  "secret",
  "token",
  "apiKey",
  "api_key",
  "accessToken",
  "access_token",
  "refreshToken",
  "refresh_token",
  "sessionToken",
  "session_token",
  "csrf",
  "csrfToken",
  "hmac",
  "signature",
  "mac",
  "auth",
  "authorization",
])

function nameOf(node: Node): string | null {
  if (node.isKind(SyntaxKind.Identifier)) return node.getText()
  if (node.isKind(SyntaxKind.PropertyAccessExpression)) return node.getName()
  return null
}

function isTimingSensitive(node: Node): boolean {
  const n = nameOf(node)
  if (!n) return false
  return TIMING_SENSITIVE_NAMES.has(n)
}

const TIMING_UNSAFE_RULE: AstRule = {
  id: "ast/timing-unsafe-credential-compare",
  name: "Timing attack: credential compared with == / === instead of constant-time compare",
  severity: "high",
  category: "timing-attack",
  cwe: "CWE-208",
  description:
    "A `===` or `==` comparison was used against an identifier or property named like a credential (password / token / secret / signature / hmac / apiKey / csrf / etc). JavaScript string equality short-circuits on the first differing character — an attacker measuring response time can deduce the secret one byte at a time. Use `crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))` (after equal-length check) or a library helper like `@noble/hashes/utils.equalBytes`.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const bin of sourceFile.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
      const op = bin.getOperatorToken().getKind()
      if (op !== SyntaxKind.EqualsEqualsToken && op !== SyntaxKind.EqualsEqualsEqualsToken) {
        continue
      }
      if (!isTimingSensitive(bin.getLeft()) && !isTimingSensitive(bin.getRight())) continue
      hits.push({
        lineNumber: lineOf(bin),
        lineContent: lineContentOf(bin, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(TIMING_UNSAFE_RULE)

export { TIMING_UNSAFE_RULE }
