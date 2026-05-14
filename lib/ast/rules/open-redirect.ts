import { Node, SyntaxKind, type SourceFile } from "ts-morph"
import {
  findUserInputInBinaryConcat,
  findUserInputInTemplate,
  getCallCalleeName,
  isUserInputExpression,
  lineContentOf,
  lineOf,
} from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// Detect res.redirect(<user input>) and NextResponse.redirect(<user input>).
// Open redirect lets an attacker bounce the victim through a trusted
// origin to phishing — high-leverage on auth flows (post-login redirect
// to `?next=<url>`).

const REDIRECT_CALLER_LAST = /^(?:redirect|writeHead)$/

function urlArgIsUserControlled(arg: Node): boolean {
  if (isUserInputExpression(arg)) return true
  if (arg.isKind(SyntaxKind.TemplateExpression) && findUserInputInTemplate(arg)) return true
  if (arg.isKind(SyntaxKind.BinaryExpression) && findUserInputInBinaryConcat(arg)) return true
  return false
}

function isRedirectCall(call: Node): boolean {
  if (!call.isKind(SyntaxKind.CallExpression)) return false
  const name = getCallCalleeName(call)
  if (!name) return false

  // res.redirect / response.redirect / ctx.redirect
  const parts = name.split(".")
  if (parts.length !== 2) return false
  const [obj, method] = parts

  // NextResponse.redirect — static method, similar surface
  if (obj === "NextResponse" && method === "redirect") return true
  // res / response / ctx pattern
  if (!REDIRECT_CALLER_LAST.test(method)) return false
  if (obj !== "res" && obj !== "response" && obj !== "ctx" && obj !== "context") return false
  return true
}

const OPEN_REDIRECT_RULE: AstRule = {
  id: "ast/open-redirect-user-url",
  name: "Open redirect: response.redirect called with user-controlled URL",
  severity: "high",
  category: "open-redirect",
  cwe: "CWE-601",
  description:
    "A redirect target was sourced from req.body, req.query, req.params, req.headers, ctx.request, or `userInput`. Attackers craft links like /login?next=https://evil.example.com that bounce the victim through your trusted domain and into a phishing page. Validate the redirect target against an allow-list of paths or hosts before issuing the redirect — for relative paths, also check the value starts with '/' but NOT '//' (protocol-relative).",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (!isRedirectCall(call)) continue
      const args = call.getArguments()
      if (args.length === 0) continue
      // Express form: res.redirect(url) OR res.redirect(status, url)
      // We check both positions defensively.
      const tainted = args.some((a) => urlArgIsUserControlled(a))
      if (!tainted) continue
      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(OPEN_REDIRECT_RULE)

export { OPEN_REDIRECT_RULE }
