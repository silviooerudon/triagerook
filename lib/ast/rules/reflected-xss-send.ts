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

// Reflected XSS via response body. `res.send(req.body.html)` echoes user
// input back as the response body — if Content-Type isn't text/plain
// (Express defaults to text/html when the body is a string), the browser
// parses <script> tags and you have XSS.

const SEND_LAST_SEGMENT = /^(?:send|end|write)$/
const SEND_OBJECTS = new Set(["res", "response"])

function isSendCall(call: Node): boolean {
  if (!call.isKind(SyntaxKind.CallExpression)) return false
  const name = getCallCalleeName(call)
  if (!name) return false
  const parts = name.split(".")
  if (parts.length !== 2) return false
  const [obj, method] = parts
  if (!SEND_OBJECTS.has(obj)) return false
  return SEND_LAST_SEGMENT.test(method)
}

function argIsUserControlled(arg: Node): boolean {
  if (isUserInputExpression(arg)) return true
  if (arg.isKind(SyntaxKind.TemplateExpression) && findUserInputInTemplate(arg)) return true
  if (arg.isKind(SyntaxKind.BinaryExpression) && findUserInputInBinaryConcat(arg)) return true
  return false
}

const REFLECTED_XSS_RULE: AstRule = {
  id: "ast/reflected-xss-via-res-send",
  name: "Reflected XSS: response body sourced from user input",
  severity: "high",
  category: "xss",
  cwe: "CWE-79",
  description:
    "res.send / res.write / res.end was called with a body sourced from req.body, req.query, req.params, req.headers, ctx.request, or `userInput`. Express infers Content-Type: text/html when the body is a string — any <script> in the user input runs in the visitor's browser. Either send via res.json (sets Content-Type: application/json, which the browser will NOT parse as HTML), escape the input through a HTML-encoder before sending, or set Content-Type: text/plain explicitly.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (!isSendCall(call)) continue
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

registerAstRule(REFLECTED_XSS_RULE)

export { REFLECTED_XSS_RULE }
