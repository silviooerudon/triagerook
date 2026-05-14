import { SyntaxKind, type Node, type SourceFile } from "ts-morph"
import { getCallCalleeName, lineContentOf, lineOf } from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// jwt.decode(token) returns the payload WITHOUT verifying the signature.
// Code paths that authenticate the user from the decoded payload trust
// a token an attacker can mint with any header/payload — the signature
// step is the entire point of JWT, and `decode` skips it.
//
// We flag jwt.decode(...) / jsonwebtoken.decode(...) / JWT.decode(...).
// The `jwt-decode` browser library is a separate concern (it ONLY
// decodes — you can't verify a JWT from a browser without a secret),
// so we don't flag bare `jwtDecode(...)` calls. If users want that
// flagged, the regex layer can pick it up at lower confidence.

const JWT_DECODE_OBJECTS = new Set(["jwt", "jsonwebtoken", "JWT"])

function isJwtDecodeCall(call: Node): boolean {
  if (!call.isKind(SyntaxKind.CallExpression)) return false
  const name = getCallCalleeName(call)
  if (!name) return false
  const parts = name.split(".")
  if (parts.length !== 2) return false
  const [obj, method] = parts
  if (method !== "decode") return false
  return JWT_DECODE_OBJECTS.has(obj)
}

const JWT_DECODE_NO_VERIFY_RULE: AstRule = {
  id: "ast/jwt-decode-without-verify",
  name: "JWT decoded without signature verification",
  severity: "high",
  category: "jwt",
  cwe: "CWE-347",
  description:
    "jwt.decode(token) (or jsonwebtoken.decode) parses the JWT payload without checking the signature. An attacker can craft a token with arbitrary claims (`{ \"sub\": \"admin\" }`) and your code will trust it. If you're authenticating the user from the decoded payload, switch to jwt.verify(token, secret, options) — that throws on a bad signature. Reserve .decode strictly for non-trust use cases like reading metadata before deciding which secret to verify with.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (!isJwtDecodeCall(call)) continue
      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(JWT_DECODE_NO_VERIFY_RULE)

export { JWT_DECODE_NO_VERIFY_RULE }
