import { Node, SyntaxKind, type SourceFile } from "ts-morph"
import {
  getCallCalleeName,
  lineContentOf,
  lineOf,
} from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// Algorithms with no remaining cryptographic security. SHA-1 was retired
// in 2017 (NIST), MD5 way earlier. Other crypto-broken alternatives
// (md2/md4) are too rare in real code to be worth listing.
const WEAK_HASH_ALGOS = new Set([
  "md5",
  "md4",
  "md2",
  "sha1",
  "sha-1",
  "sha-224",  // questionable for password contexts but ok elsewhere; flag
  "sha224",
])

// Identifier / property names that signal the hash is being used for a
// security purpose (password storage, session token, signed data). MD5
// is fine for cache keys; not fine for hashing credentials.
const SECURITY_NAMES = /\b(?:password|passwd|pwd|secret|token|credential|auth|session|otp|api[_-]?key)\b/i

function looksSecurityRelated(node: Node): boolean {
  // Walk a small radius: the .update() arg AND the surrounding variable
  // declaration / assignment. Conservative: avoid full data-flow.
  const text = node.getText()
  if (SECURITY_NAMES.test(text)) return true

  const parent = node.getParent()
  if (parent && SECURITY_NAMES.test(parent.getText().slice(0, 200))) return true

  return false
}

// Detect a chain anchored on `createHash(WEAK_ALGO)` and walk forward to
// find an `.update(<arg>)` call. The walk handles the typical idiom:
//   crypto.createHash('md5').update(password).digest('hex')
// AND broken-up version:
//   const h = crypto.createHash('md5'); h.update(password); h.digest('hex')
// only when the .update is on the same expression (no variable tracking).
function findUpdateArgInChain(callNode: Node): Node | null {
  if (!callNode.isKind(SyntaxKind.CallExpression)) return null

  let current: Node = callNode
  // Walk up the call chain: createHash(...).update(...).digest(...)
  while (true) {
    const parent: Node | undefined = current.getParent()
    if (!parent) return null
    if (!parent.isKind(SyntaxKind.PropertyAccessExpression)) return null
    const grandparent: Node | undefined = parent.getParent()
    if (!grandparent || !grandparent.isKind(SyntaxKind.CallExpression)) return null
    if (parent.getName() === "update") {
      const updateArgs = grandparent.getArguments()
      if (updateArgs.length === 0) return null
      return updateArgs[0]
    }
    current = grandparent
  }
}

const WEAK_CRYPTO_RULE: AstRule = {
  id: "ast/weak-crypto-hash-for-secrets",
  name: "Weak crypto: MD5 / SHA-1 used for security-sensitive hashing",
  severity: "high",
  category: "weak-crypto",
  cwe: "CWE-327",
  description:
    "Node crypto.createHash() was called with a broken algorithm (md5 / sha1 / md4 / md2 / sha-224) and the hashed value carries a security-related identifier (password / token / secret / session / api_key / etc). These algorithms have no preimage or collision resistance for the security use cases people most often grab them for. For password storage use bcrypt/scrypt/argon2; for tokens use a CSPRNG output via crypto.randomBytes; for HMAC use SHA-256+. If the use case is non-security (file content hash, cache key) suppress via .repoguardignore.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const name = getCallCalleeName(call)
      if (!name) continue
      const last = name.split(".").pop() ?? ""
      if (last !== "createHash") continue

      const args = call.getArguments()
      if (args.length === 0) continue
      const algoArg = args[0]
      if (!algoArg.isKind(SyntaxKind.StringLiteral) && !algoArg.isKind(SyntaxKind.NoSubstitutionTemplateLiteral)) {
        continue
      }
      const algo = algoArg.getLiteralText().toLowerCase()
      if (!WEAK_HASH_ALGOS.has(algo)) continue

      // Look downstream for the .update(<arg>) call so we can decide if
      // the hash is being used for a security-shaped input.
      const updateArg = findUpdateArgInChain(call)
      if (!updateArg) continue
      if (!looksSecurityRelated(updateArg)) continue

      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(WEAK_CRYPTO_RULE)

export { WEAK_CRYPTO_RULE }
