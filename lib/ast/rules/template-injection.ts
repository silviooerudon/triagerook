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

// Server-side template injection. The vulnerable shape is `compile(<user
// input>)` or `render(<user input>)` on Handlebars / Pug / EJS / Mustache /
// Nunjucks — the engine will execute helpers or expressions embedded in
// the user-supplied template body, granting RCE on most engines.

const TEMPLATE_CALLER_LAST = /^(?:compile|render|renderString|renderFile)$/

const TEMPLATE_CALLER_OBJECTS = new Set([
  "Handlebars",
  "handlebars",
  "Pug",
  "pug",
  "ejs",
  "EJS",
  "Mustache",
  "mustache",
  "nunjucks",
  "Nunjucks",
  "Twig",
  "twig",
  "dot",
  "doT",
])

function isTemplateEngineCall(call: Node): boolean {
  if (!call.isKind(SyntaxKind.CallExpression)) return false
  const name = getCallCalleeName(call)
  if (!name) return false
  const parts = name.split(".")
  if (parts.length !== 2) return false
  const [obj, method] = parts
  if (!TEMPLATE_CALLER_OBJECTS.has(obj)) return false
  return TEMPLATE_CALLER_LAST.test(method)
}

function argIsUserControlled(arg: Node): boolean {
  if (isUserInputExpression(arg)) return true
  if (arg.isKind(SyntaxKind.TemplateExpression) && findUserInputInTemplate(arg)) return true
  if (arg.isKind(SyntaxKind.BinaryExpression) && findUserInputInBinaryConcat(arg)) return true
  return false
}

const SSTI_RULE: AstRule = {
  id: "ast/template-injection-user-input",
  name: "Server-side template injection: template engine compiled / rendered with user input",
  severity: "critical",
  category: "command-injection",
  cwe: "CWE-1336",
  description:
    "Handlebars / Pug / EJS / Mustache / Nunjucks compile() or render() was called with a template string sourced from user input. These engines parse `{{...}}` (Handlebars/Mustache), `#{...}` / `!=` (Pug), or `<%-%>` (EJS) and execute helper expressions inside — most engines reach JavaScript eval via the prototype chain or escape filters, giving the attacker remote code execution. Render with FIXED templates, never the user's template body; let the user only fill the data slots.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (!isTemplateEngineCall(call)) continue
      const args = call.getArguments()
      if (args.length === 0) continue
      if (!argIsUserControlled(args[0])) continue
      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(SSTI_RULE)

export { SSTI_RULE }
