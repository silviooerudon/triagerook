import { Node, SyntaxKind, type SourceFile } from "ts-morph"
import { getCallCalleeName, lineContentOf, lineOf } from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// Detect express-session / cookie-session / koa-session calls where the
// secret is a string literal OR the cookie config is dangerous in prod
// (httpOnly: false, secure: false, sameSite: 'none' without secure).
//
// Single rule keyed on the same callee surface — the description
// enumerates the failure modes the user can fix.

type SessionConfigIssue =
  | "hardcoded-secret"
  | "http-only-false"
  | "secure-false"

function isSessionFactoryCall(call: Node): boolean {
  if (!call.isKind(SyntaxKind.CallExpression)) return false
  const name = getCallCalleeName(call)
  if (!name) return false
  // Bare function call: session(...)  cookieSession(...)  koaSession(...)
  if (name === "session" || name === "cookieSession" || name === "expressSession") return true
  return false
}

function evaluateSessionConfig(opts: Node): Set<SessionConfigIssue> {
  const issues = new Set<SessionConfigIssue>()
  if (!opts.isKind(SyntaxKind.ObjectLiteralExpression)) return issues

  for (const prop of opts.getProperties()) {
    if (!prop.isKind(SyntaxKind.PropertyAssignment)) continue
    const name = prop.getName()
    const init = prop.getInitializer()
    if (!init) continue

    if (name === "secret") {
      if (
        init.isKind(SyntaxKind.StringLiteral) ||
        init.isKind(SyntaxKind.NoSubstitutionTemplateLiteral)
      ) {
        const text = init.getLiteralText()
        if (text.length > 0) issues.add("hardcoded-secret")
      }
    }

    if (name === "cookie") {
      if (init.isKind(SyntaxKind.ObjectLiteralExpression)) {
        for (const cookieProp of init.getProperties()) {
          if (!cookieProp.isKind(SyntaxKind.PropertyAssignment)) continue
          const cn = cookieProp.getName()
          const cv = cookieProp.getInitializer()
          if (!cv) continue
          if (cn === "httpOnly" && cv.getKind() === SyntaxKind.FalseKeyword) {
            issues.add("http-only-false")
          }
          if (cn === "secure" && cv.getKind() === SyntaxKind.FalseKeyword) {
            issues.add("secure-false")
          }
        }
      }
    }
  }
  return issues
}

const SESSION_CONFIG_RULE: AstRule = {
  id: "ast/insecure-session-config",
  name: "Insecure session configuration: hardcoded secret or cookie security off",
  severity: "high",
  category: "weak-session",
  cwe: "CWE-614",
  description:
    "A session() / cookieSession() / expressSession() factory was called with one of: a string-literal `secret` (hardcoded — any reader of the repo can forge session cookies), `cookie.httpOnly: false` (JavaScript on the page can read the cookie), or `cookie.secure: false` (cookie travels over plain HTTP). Load the secret from process.env, and set httpOnly and secure to true in production.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (!isSessionFactoryCall(call)) continue
      const args = call.getArguments()
      if (args.length === 0) continue
      const issues = evaluateSessionConfig(args[0])
      if (issues.size === 0) continue
      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(SESSION_CONFIG_RULE)

export { SESSION_CONFIG_RULE }
