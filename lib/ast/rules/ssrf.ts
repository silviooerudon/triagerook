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

// HTTP-client surface that takes a URL as the first arg. We match by last
// dotted segment to compose namespace imports (`axios.get`), bare imports
// (`got(...)`), and the `node-fetch`-style default-export form.
const HTTP_CALL_LAST_SEGMENT =
  /^(?:fetch|get|post|put|patch|delete|head|request|options)$/

// Whitelist of OBJECT names that own HTTP-shaped methods. Filters out the
// false positive where `regex.exec(...)` or `array.get(...)` happens to
// share a method name with `axios.get`.
const HTTP_CALLER_OBJECTS = new Set([
  "fetch", // bare fetch
  "axios",
  "http",
  "https",
  "got",
  "superagent",
  "needle",
  "request",
  "ky",
  "undici",
])

function isHttpClientCall(call: Node): boolean {
  if (!call.isKind(SyntaxKind.CallExpression)) return false
  const name = getCallCalleeName(call)
  if (!name) return false

  // Bare callable form. Covers `fetch(url)` (global since Node 18, also
  // edge runtime), `got(url)`, `axios(config)`, `ky(url)`, `request(opts)`,
  // and `needle(method, url)`. We cannot disambiguate via binding source
  // here so a function variable named `got` or `request` will FP — the
  // user can suppress via .repoguardignore if it happens.
  if (HTTP_CALLER_OBJECTS.has(name)) return true

  // namespace.method form (axios.get / http.request)
  const parts = name.split(".")
  if (parts.length !== 2) return false
  const [obj, method] = parts
  if (!HTTP_CALLER_OBJECTS.has(obj)) return false
  if (!HTTP_CALL_LAST_SEGMENT.test(method)) return false
  return true
}

function urlArgIsUserControlled(arg: Node): boolean {
  if (isUserInputExpression(arg)) return true
  if (arg.isKind(SyntaxKind.TemplateExpression) && findUserInputInTemplate(arg)) return true
  if (arg.isKind(SyntaxKind.BinaryExpression) && findUserInputInBinaryConcat(arg)) return true

  // `new URL(req.body.url)` wrapping — common pattern that "looks safer"
  // but the constructed URL is still attacker-pointed.
  if (arg.isKind(SyntaxKind.NewExpression)) {
    const ctor = arg.getExpression()
    if (ctor.isKind(SyntaxKind.Identifier) && ctor.getText() === "URL") {
      for (const ctorArg of arg.getArguments()) {
        if (urlArgIsUserControlled(ctorArg)) return true
      }
    }
  }
  return false
}

const SSRF_RULE: AstRule = {
  id: "ast/ssrf-http-user-url",
  name: "SSRF: HTTP client called with user-controlled URL",
  severity: "critical",
  category: "ssrf",
  cwe: "CWE-918",
  description:
    "fetch / axios / http / got / superagent / needle / ky / undici was called with a URL sourced from req.body, req.query, req.params, req.headers, ctx.request, or `userInput`. An attacker can redirect the request to internal-only endpoints (AWS metadata service at 169.254.169.254, internal microservices, Docker socket) and exfiltrate the response. Validate the URL against an allow-list of hosts before issuing the request.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (!isHttpClientCall(call)) continue
      const args = call.getArguments()
      if (args.length === 0) continue
      if (!urlArgIsUserControlled(args[0])) continue

      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(SSRF_RULE)

export { SSRF_RULE }
