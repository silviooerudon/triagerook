import { Node, SyntaxKind, type SourceFile } from "ts-morph"
import { getCallCalleeName, lineContentOf, lineOf } from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// Detect the HTTP-level form of CORS misconfiguration: setting the
// Access-Control-Allow-Origin header directly to '*' via res.setHeader,
// res.set, NextResponse headers, etc. Different code path from the
// cors() middleware rule in batch 4 — AI hits this one when "fixing
// CORS errors" without installing the cors package.

const HEADER_SETTER_LAST_SEGMENT = /^(?:setHeader|set|header)$/
const HEADER_SETTER_OBJECTS = new Set(["res", "response", "ctx", "context"])

function isHeaderSetterCall(call: Node): {
  isHeaderSetter: boolean
  isAccessControl: boolean
  valueArg: Node | null
} {
  if (!call.isKind(SyntaxKind.CallExpression)) {
    return { isHeaderSetter: false, isAccessControl: false, valueArg: null }
  }
  const name = getCallCalleeName(call)
  if (!name) return { isHeaderSetter: false, isAccessControl: false, valueArg: null }
  const parts = name.split(".")
  if (parts.length !== 2) return { isHeaderSetter: false, isAccessControl: false, valueArg: null }
  const [obj, method] = parts
  if (!HEADER_SETTER_OBJECTS.has(obj)) {
    return { isHeaderSetter: false, isAccessControl: false, valueArg: null }
  }
  if (!HEADER_SETTER_LAST_SEGMENT.test(method)) {
    return { isHeaderSetter: false, isAccessControl: false, valueArg: null }
  }

  const args = call.getArguments()
  if (args.length < 2) return { isHeaderSetter: true, isAccessControl: false, valueArg: null }

  const headerNameArg = args[0]
  let headerName: string | null = null
  if (
    headerNameArg.isKind(SyntaxKind.StringLiteral) ||
    headerNameArg.isKind(SyntaxKind.NoSubstitutionTemplateLiteral)
  ) {
    headerName = headerNameArg.getLiteralText().toLowerCase()
  }
  if (headerName !== "access-control-allow-origin") {
    return { isHeaderSetter: true, isAccessControl: false, valueArg: null }
  }
  return { isHeaderSetter: true, isAccessControl: true, valueArg: args[1] }
}

const WILDCARD_CORS_HEADER_RULE: AstRule = {
  id: "ast/wildcard-cors-via-set-header",
  name: "CORS misconfiguration: Access-Control-Allow-Origin set to '*' via response header",
  severity: "high",
  category: "cors",
  cwe: "CWE-942",
  description:
    "res.setHeader / res.set / res.header / ctx.set was called to assign Access-Control-Allow-Origin: '*'. Combined with any cookie-bearing endpoint this lets any web origin issue authenticated requests against your API and read the response. AI assistants reach for this when asked to 'fix CORS' without using the cors package. Replace with an explicit allow-list of origins, validated per request.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const meta = isHeaderSetterCall(call)
      if (!meta.isAccessControl || !meta.valueArg) continue
      const value = meta.valueArg
      if (
        (value.isKind(SyntaxKind.StringLiteral) ||
          value.isKind(SyntaxKind.NoSubstitutionTemplateLiteral)) &&
        value.getLiteralText() === "*"
      ) {
        hits.push({
          lineNumber: lineOf(call),
          lineContent: lineContentOf(call, sourceFile),
        })
      }
    }
    return hits
  },
}

registerAstRule(WILDCARD_CORS_HEADER_RULE)

export { WILDCARD_CORS_HEADER_RULE }
