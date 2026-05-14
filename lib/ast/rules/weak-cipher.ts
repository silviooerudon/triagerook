import { Node, SyntaxKind, type SourceFile } from "ts-morph"
import { getCallCalleeName, lineContentOf, lineOf } from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// Two cipher misuse patterns AI generates often:
//   (1) crypto.createCipher(...) — deprecated in Node since v10, broken
//       because the key is derived from a password via EVP_BytesToKey
//       with weak parameters and the IV is zeroed.
//   (2) crypto.createCipheriv('aes-256-ecb', ...) — ECB mode leaks
//       plaintext structure for any data with repeating blocks.
//
// Both surface in the same call site, so one rule covers both with a
// description that names which specific issue applied.

const ECB_MODE = /^aes-\d+-ecb$/i

const WEAK_CIPHER_RULE: AstRule = {
  id: "ast/weak-cipher-mode-or-deprecated-api",
  name: "Weak crypto: createCipher() or ECB mode",
  severity: "high",
  category: "weak-crypto",
  cwe: "CWE-327",
  description:
    "crypto.createCipher() is deprecated since Node 10 — it derives the key from a password via EVP_BytesToKey with weak parameters and uses a zeroed IV, so two encryptions of the same plaintext are identical. Use crypto.createCipheriv() with a key from crypto.randomBytes and a fresh IV per message. Separately: createCipheriv('aes-???-ecb', ...) — ECB mode encrypts each block independently, so repeating plaintext blocks (e.g. fixed JSON structure) produce repeating ciphertext blocks — visually obvious in the famous Tux penguin demo. Use GCM or CBC with HMAC instead.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const name = getCallCalleeName(call)
      if (!name) continue
      const last = name.split(".").pop() ?? ""

      // (1) Deprecated createCipher
      if (last === "createCipher" || last === "createDecipher") {
        hits.push({
          lineNumber: lineOf(call),
          lineContent: lineContentOf(call, sourceFile),
        })
        continue
      }

      // (2) ECB mode via createCipheriv
      if (last === "createCipheriv" || last === "createDecipheriv") {
        const args = call.getArguments()
        if (args.length === 0) continue
        const algoArg = args[0]
        if (
          !algoArg.isKind(SyntaxKind.StringLiteral) &&
          !algoArg.isKind(SyntaxKind.NoSubstitutionTemplateLiteral)
        ) {
          continue
        }
        const algo = algoArg.getLiteralText()
        if (!ECB_MODE.test(algo)) continue
        hits.push({
          lineNumber: lineOf(call),
          lineContent: lineContentOf(call, sourceFile),
        })
      }
    }
    return hits
  },
}

registerAstRule(WEAK_CIPHER_RULE)

export { WEAK_CIPHER_RULE }
