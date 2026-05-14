import { Node, SyntaxKind, type SourceFile } from "ts-morph"
import { getCallCalleeName, lineContentOf, lineOf } from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// res.cookie(name, value) without options OR with explicit httpOnly:
// false / secure: false. The Express default is no httpOnly + no
// secure, so omitting options is also a leak surface — JavaScript can
// read the cookie and it travels over plain HTTP.

const COOKIE_SETTER_LAST_SEGMENT = "cookie"
const COOKIE_SETTER_OBJECTS = new Set(["res", "response", "ctx", "context"])

type CookieIssue = "no-options" | "http-only-false" | "secure-false"

function isCookieSetterCall(call: Node): boolean {
  if (!call.isKind(SyntaxKind.CallExpression)) return false
  const name = getCallCalleeName(call)
  if (!name) return false
  const parts = name.split(".")
  if (parts.length !== 2) return false
  const [obj, method] = parts
  if (!COOKIE_SETTER_OBJECTS.has(obj)) return false
  return method === COOKIE_SETTER_LAST_SEGMENT
}

function classifyCookieOptions(opts: Node | undefined): Set<CookieIssue> {
  const issues = new Set<CookieIssue>()
  if (!opts) {
    issues.add("no-options")
    return issues
  }
  if (!opts.isKind(SyntaxKind.ObjectLiteralExpression)) return issues

  let sawHttpOnlyTrue = false
  let sawSecureTrue = false

  for (const prop of opts.getProperties()) {
    if (!prop.isKind(SyntaxKind.PropertyAssignment)) continue
    const name = prop.getName()
    const init = prop.getInitializer()
    if (!init) continue
    if (name === "httpOnly") {
      if (init.getKind() === SyntaxKind.FalseKeyword) issues.add("http-only-false")
      if (init.getKind() === SyntaxKind.TrueKeyword) sawHttpOnlyTrue = true
    }
    if (name === "secure") {
      if (init.getKind() === SyntaxKind.FalseKeyword) issues.add("secure-false")
      if (init.getKind() === SyntaxKind.TrueKeyword) sawSecureTrue = true
    }
  }

  if (!sawHttpOnlyTrue) issues.add("http-only-false")
  if (!sawSecureTrue) issues.add("secure-false")

  return issues
}

const INSECURE_COOKIE_RULE: AstRule = {
  id: "ast/insecure-cookie-set",
  name: "Insecure cookie: httpOnly and/or secure not explicitly set to true",
  severity: "high",
  category: "insecure-cookie",
  cwe: "CWE-1004",
  description:
    "res.cookie / ctx.cookie was called without options, OR with httpOnly: false or secure: false. Express defaults both to false — that means the cookie is readable by JavaScript on the page (cookie-stealing XSS becomes session takeover) and travels over plain HTTP (cookie sniffable on a coffee-shop Wi-Fi). Pass `{ httpOnly: true, secure: true, sameSite: 'lax' }` (or 'strict' if you can). In dev where HTTPS isn't set up, gate `secure` on process.env.NODE_ENV.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (!isCookieSetterCall(call)) continue
      const args = call.getArguments()
      // res.cookie(name, value)               — 2 args, no options → issue
      // res.cookie(name, value, options)      — 3 args, parse options
      if (args.length < 2) continue
      const optsArg = args.length >= 3 ? args[2] : undefined
      const issues = classifyCookieOptions(optsArg)
      if (issues.size === 0) continue
      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(INSECURE_COOKIE_RULE)

export { INSECURE_COOKIE_RULE }
