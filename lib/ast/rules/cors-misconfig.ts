import { Node, SyntaxKind, type SourceFile } from "ts-morph"
import { getCallCalleeName, lineContentOf, lineOf } from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// Detect cors() configurations that allow ANY origin together with
// credentials. Spec-wise the browser blocks this combination, but
// emitting `Access-Control-Allow-Origin: *` already loosens defences
// against CSRF/XSS data exfil and the dev who wrote `credentials: true`
// will eventually swap '*' for a request-echoing handler.

type CorsConfig = {
  hasWildcardOrigin: boolean
  hasCredentialsTrue: boolean
  originLine: number | null
}

function readCorsObject(opts: Node): CorsConfig {
  const cfg: CorsConfig = {
    hasWildcardOrigin: false,
    hasCredentialsTrue: false,
    originLine: null,
  }
  if (!opts.isKind(SyntaxKind.ObjectLiteralExpression)) return cfg

  for (const prop of opts.getProperties()) {
    if (!prop.isKind(SyntaxKind.PropertyAssignment)) continue
    const name = prop.getName()
    const init = prop.getInitializer()
    if (!init) continue

    if (name === "origin") {
      cfg.originLine = init.getStartLineNumber()
      // origin: '*' OR origin: true (cors lib treats `true` as reflecting
      // the Origin header, which is functionally a wildcard).
      if (init.isKind(SyntaxKind.StringLiteral) && init.getLiteralText() === "*") {
        cfg.hasWildcardOrigin = true
      }
      if (init.getKind() === SyntaxKind.TrueKeyword) {
        cfg.hasWildcardOrigin = true
      }
    }
    if (name === "credentials") {
      if (init.getKind() === SyntaxKind.TrueKeyword) {
        cfg.hasCredentialsTrue = true
      }
    }
  }
  return cfg
}

const CORS_RULE: AstRule = {
  id: "ast/cors-credentials-with-any-origin",
  name: "CORS misconfiguration: credentials enabled with permissive origin",
  severity: "high",
  category: "cors",
  cwe: "CWE-942",
  description:
    "A `cors(...)` config sets origin to '*' or `true` while also enabling `credentials: true`. Even if the browser blocks the exact spec violation, the deployment is one config drift away from echoing the request Origin header back as Access-Control-Allow-Origin — at which point any site can read authenticated responses. Set an explicit origin allow-list (`origin: ['https://app.example.com']`) or a function that validates against one.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const name = getCallCalleeName(call)
      if (!name) continue
      const last = name.split(".").pop() ?? ""
      if (last !== "cors") continue
      const args = call.getArguments()
      if (args.length === 0) continue
      const cfg = readCorsObject(args[0])
      if (!cfg.hasWildcardOrigin || !cfg.hasCredentialsTrue) continue
      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(CORS_RULE)

export { CORS_RULE }
