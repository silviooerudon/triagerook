import { Node, SyntaxKind, type SourceFile } from "ts-morph"
import { lineContentOf, lineOf } from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// Detect the canonical "demo login" patterns AI assistants emit when
// asked for a quick auth check:
//   if (username === 'admin' && password === 'admin') return ok()
//   if (user === 'root' && pass === 'password') login()
// These ship to prod surprisingly often — the "// TODO replace this"
// comment never gets read.

// Usernames that look like admin / superuser accounts. We match against
// the literal text being compared to.
const ADMIN_USERNAMES = new Set([
  "admin",
  "administrator",
  "root",
  "superuser",
  "super",
  "test",
  "guest",
])

// Passwords that are obviously placeholders. Any password string compared
// to an identifier named like a password is suspicious — these patterns
// say "this is definitely a demo cred and definitely ships to prod".
const PLACEHOLDER_PASSWORDS = new Set([
  "admin",
  "password",
  "password123",
  "123456",
  "qwerty",
  "letmein",
  "changeme",
  "default",
  "root",
  "secret",
  "test",
  "demo",
])

// Identifier-name slots that, when compared with `===`/`==` against a
// string literal, suggest a credential-check site.
const USERNAME_NAMES = new Set([
  "username",
  "user",
  "userId",
  "user_id",
  "login",
  "email",
  "account",
])
const PASSWORD_NAMES = new Set([
  "password",
  "passwd",
  "pwd",
  "pass",
])

function readEqualityCompare(node: Node): {
  leftName: string | null
  literalText: string | null
} | null {
  if (!node.isKind(SyntaxKind.BinaryExpression)) return null
  const op = node.getOperatorToken().getKind()
  if (op !== SyntaxKind.EqualsEqualsToken && op !== SyntaxKind.EqualsEqualsEqualsToken) {
    return null
  }
  const left = node.getLeft()
  const right = node.getRight()

  const leftIdent = identifierName(left)
  const rightIdent = identifierName(right)
  const leftLit = stringLiteralText(left)
  const rightLit = stringLiteralText(right)

  if (leftIdent && rightLit !== null) return { leftName: leftIdent, literalText: rightLit }
  if (rightIdent && leftLit !== null) return { leftName: rightIdent, literalText: leftLit }
  return null
}

function identifierName(node: Node): string | null {
  if (node.isKind(SyntaxKind.Identifier)) return node.getText()
  if (node.isKind(SyntaxKind.PropertyAccessExpression)) return node.getName()
  return null
}

function stringLiteralText(node: Node): string | null {
  if (node.isKind(SyntaxKind.StringLiteral)) return node.getLiteralText()
  if (node.isKind(SyntaxKind.NoSubstitutionTemplateLiteral)) return node.getLiteralText()
  return null
}

// True if a binary compares a USERNAME-shaped slot to one of the admin
// names.
function isAdminUsernameCompare(node: Node): boolean {
  const cmp = readEqualityCompare(node)
  if (!cmp || !cmp.leftName || cmp.literalText === null) return false
  if (!USERNAME_NAMES.has(cmp.leftName)) return false
  return ADMIN_USERNAMES.has(cmp.literalText.toLowerCase())
}

// True if a binary compares a PASSWORD-shaped slot to a placeholder.
function isPlaceholderPasswordCompare(node: Node): boolean {
  const cmp = readEqualityCompare(node)
  if (!cmp || !cmp.leftName || cmp.literalText === null) return false
  if (!PASSWORD_NAMES.has(cmp.leftName)) return false
  return PLACEHOLDER_PASSWORDS.has(cmp.literalText.toLowerCase())
}

const HARDCODED_ADMIN_RULE: AstRule = {
  id: "ast/hardcoded-admin-credentials",
  name: "Hardcoded admin credentials: equality check against literal placeholder username + password",
  severity: "critical",
  category: "hardcoded-creds",
  cwe: "CWE-798",
  description:
    "An equality check compares a username-shaped identifier (username / user / login / email / account) to a literal admin-shaped name ('admin' / 'root' / 'administrator' / 'superuser' / 'guest' / 'test'), AND/OR compares a password-shaped identifier (password / pwd / pass / passwd) to a placeholder literal ('admin' / 'password' / '123456' / 'changeme' / etc). These patterns ship as demo logins and then never get replaced. Move credentials to env vars and rotate the placeholder values now.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const bin of sourceFile.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
      const op = bin.getOperatorToken().getKind()
      if (op !== SyntaxKind.EqualsEqualsToken && op !== SyntaxKind.EqualsEqualsEqualsToken) {
        continue
      }
      if (!isAdminUsernameCompare(bin) && !isPlaceholderPasswordCompare(bin)) continue
      hits.push({
        lineNumber: lineOf(bin),
        lineContent: lineContentOf(bin, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(HARDCODED_ADMIN_RULE)

export { HARDCODED_ADMIN_RULE }
