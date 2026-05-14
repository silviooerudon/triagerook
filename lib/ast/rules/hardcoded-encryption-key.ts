import { Node, SyntaxKind, type SourceFile } from "ts-morph"
import { getCallCalleeName, lineContentOf, lineOf } from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// crypto.createCipheriv(algorithm, key, iv) where the `key` arg is a
// string literal — committed into source, retrievable by anyone with
// repo read. The fix is process.env.ENCRYPTION_KEY + rotate.
//
// Conservative: we only flag when the key is a STRING LITERAL or
// no-substitution template literal of meaningful length. Buffer.from(),
// crypto.randomBytes(), and identifiers resolving to env vars pass.

function isMeaningfulLiteralKey(node: Node): boolean {
  if (
    node.isKind(SyntaxKind.StringLiteral) ||
    node.isKind(SyntaxKind.NoSubstitutionTemplateLiteral)
  ) {
    return node.getLiteralText().length >= 8
  }
  return false
}

const HARDCODED_KEY_RULE: AstRule = {
  id: "ast/hardcoded-encryption-key",
  name: "Hardcoded encryption key passed to createCipheriv",
  severity: "critical",
  category: "hardcoded-creds",
  cwe: "CWE-798",
  description:
    "crypto.createCipheriv / createDecipheriv was called with a string-literal key. Any reader of the repo can decrypt all data ever encrypted with it. Move the key to process.env and rotate every value already encrypted under the committed key (you cannot recover from this incident by changing the source file alone — the leaked key remains valid on existing ciphertext). For new code use crypto.randomBytes(32) at deploy time and store the hex in your secret manager.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const name = getCallCalleeName(call)
      if (!name) continue
      const last = name.split(".").pop() ?? ""
      if (last !== "createCipheriv" && last !== "createDecipheriv") continue
      const args = call.getArguments()
      if (args.length < 2) continue
      if (!isMeaningfulLiteralKey(args[1])) continue
      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(HARDCODED_KEY_RULE)

export { HARDCODED_KEY_RULE }
