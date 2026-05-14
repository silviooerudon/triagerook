import { SyntaxKind, type Node, type SourceFile } from "ts-morph"
import { getCallCalleeName, lineContentOf, lineOf } from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// XML parsers default to safe in some libraries and unsafe in others.
// We flag the explicit opt-in to external-entity expansion / DTD support
// in the three libraries that are most common in Node code:
//
//   fast-xml-parser:  new XMLParser({ allowBooleanAttributes: true, processEntities: true })
//                     (processEntities defaults true but allowDtd: true is the danger flag)
//   libxmljs / libxmljs2: libxmljs.parseXml(buf, { noent: true })   // expands &foo;
//                          libxmljs.parseXml(buf, { dtdload: true }) // fetches external DTD
//   sax:              sax.parser(strict, { ... })   — there's no safe flag, the danger is the
//                     application reading external entities itself; we don't flag sax.
//
// We restrict to library-call patterns because XXE detection by string
// matching is high-noise.

const DANGER_KEYS = new Set([
  "allowDtd",   // fast-xml-parser
  "dtdload",    // libxmljs
  "noent",      // libxmljs — expand &entity;
  "external",   // libxmljs / xml2js — fetch external DTDs
  "noblanks",   // libxmljs — note: not directly dangerous but often paired
])

// Only flag the actually-dangerous keys, even though some libraries
// accept the others. Tighten the set after curation:
const FLAGGED_KEYS = new Set(["allowDtd", "dtdload", "noent", "external"])

const XML_PARSER_OBJECTS = new Set([
  "libxmljs",
  "libxmljs2",
  "xml2js",
  "XMLParser",
])

// Methods that consume the unsafe options object.
const XML_PARSE_METHODS = new Set(["parseXml", "parseXmlString", "parseString"])

function isXmlParserConstructor(newExpr: Node): boolean {
  if (!newExpr.isKind(SyntaxKind.NewExpression)) return false
  const expr = newExpr.getExpression()
  if (!expr.isKind(SyntaxKind.Identifier)) return false
  return XML_PARSER_OBJECTS.has(expr.getText())
}

function isXmlParseCall(call: Node): boolean {
  if (!call.isKind(SyntaxKind.CallExpression)) return false
  const name = getCallCalleeName(call)
  if (!name) return false
  const parts = name.split(".")
  if (parts.length !== 2) return false
  const [obj, method] = parts
  if (!XML_PARSER_OBJECTS.has(obj)) return false
  return XML_PARSE_METHODS.has(method)
}

// Returns the option-object argument from either a constructor or a
// parse-call. fast-xml-parser uses { ... } at position 0 on the
// constructor; libxmljs uses position 1 on parseXml(buffer, opts).
function getOptionsObject(args: Node[], callShape: "ctor" | "method"): Node | null {
  if (callShape === "ctor") {
    return args.length > 0 ? args[0] : null
  }
  return args.length > 1 ? args[1] : null
}

function optionsObjectFlagsDangerKey(opts: Node): boolean {
  if (!opts.isKind(SyntaxKind.ObjectLiteralExpression)) return false
  for (const prop of opts.getProperties()) {
    if (!prop.isKind(SyntaxKind.PropertyAssignment)) continue
    const name = prop.getName()
    if (!FLAGGED_KEYS.has(name)) continue
    const init = prop.getInitializer()
    if (!init) continue
    // We only flag when the value is literally true. A reference to a
    // variable could be anything; we don't trace.
    if (init.getKind() === SyntaxKind.TrueKeyword) return true
  }
  return false
}

const XXE_RULE: AstRule = {
  id: "ast/xxe-xml-parser-external-entities",
  name: "XML parser configured to expand external entities (XXE)",
  severity: "high",
  category: "xxe",
  cwe: "CWE-611",
  description:
    "An XML parser was constructed (or invoked) with an option that lets the parser fetch external DTDs / expand external entities — `allowDtd: true` (fast-xml-parser), `noent: true` / `dtdload: true` / `external: true` (libxmljs / xml2js). A crafted payload like `<!DOCTYPE x [<!ENTITY a SYSTEM \"file:///etc/passwd\">]>` then reads server files into the response. Default-deny: leave the flag at its safe default, and only enable when consuming XML from a fully trusted source. For libxmljs, prefer `parseXml(buf, { noent: false, nonet: true })`.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []

    for (const newExpr of sourceFile.getDescendantsOfKind(SyntaxKind.NewExpression)) {
      if (!isXmlParserConstructor(newExpr)) continue
      const opts = getOptionsObject(newExpr.getArguments(), "ctor")
      if (!opts) continue
      if (!optionsObjectFlagsDangerKey(opts)) continue
      hits.push({
        lineNumber: lineOf(newExpr),
        lineContent: lineContentOf(newExpr, sourceFile),
      })
    }

    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (!isXmlParseCall(call)) continue
      const opts = getOptionsObject(call.getArguments(), "method")
      if (!opts) continue
      if (!optionsObjectFlagsDangerKey(opts)) continue
      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }

    return hits
  },
}

registerAstRule(XXE_RULE)

export { XXE_RULE, DANGER_KEYS }
