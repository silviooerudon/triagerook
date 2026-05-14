import { Node, SyntaxKind, type SourceFile } from "ts-morph"
import {
  getCallCalleeName,
  isUserInputExpression,
  lineContentOf,
  lineOf,
} from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// MongoDB-flavoured NoSQL injection. Two distinct shapes:
//   (1) $where operator with user input — string is eval'd by Mongo
//   (2) Query object where a value is the raw req.body.* (object) —
//       lets the attacker send `{ "$ne": null }` and bypass equality
//
// We focus on (1) here because it's deterministic and high-confidence.
// Shape (2) requires knowing the runtime type of req.body fields, which
// without TS typings we'd FP on legitimately string-typed inputs.

// Last segments of collection methods that accept query objects.
const QUERY_METHOD_LAST_SEGMENT =
  /^(?:find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace|update|updateOne|updateMany|delete|deleteOne|deleteMany|count|countDocuments|aggregate)$/

function isQueryCall(call: Node): boolean {
  if (!call.isKind(SyntaxKind.CallExpression)) return false
  const name = getCallCalleeName(call)
  if (!name) return false
  const parts = name.split(".")
  if (parts.length < 2) return false
  const method = parts[parts.length - 1]
  return QUERY_METHOD_LAST_SEGMENT.test(method)
}

// Walk an object literal and return true if any property keyed "$where"
// has a value that comes from user input.
function objectHasUserControlledWhere(obj: Node): boolean {
  if (!obj.isKind(SyntaxKind.ObjectLiteralExpression)) return false
  for (const prop of obj.getProperties()) {
    if (!prop.isKind(SyntaxKind.PropertyAssignment)) continue
    // $where is typically quoted (`"$where"`), occasionally bare.
    const nameNode = prop.getNameNode()
    let nameText: string
    if (nameNode.isKind(SyntaxKind.StringLiteral)) {
      nameText = nameNode.getLiteralText()
    } else {
      nameText = nameNode.getText()
    }
    if (nameText !== "$where") continue
    const value = prop.getInitializer()
    if (!value) continue
    if (isUserInputExpression(value)) return true
    if (value.isKind(SyntaxKind.TemplateExpression)) {
      for (const span of value.getTemplateSpans()) {
        if (isUserInputExpression(span.getExpression())) return true
      }
    }
  }
  return false
}

const NOSQL_INJECTION_RULE: AstRule = {
  id: "ast/nosql-injection-where-user-input",
  name: "NoSQL injection: $where operator with user-controlled value",
  severity: "critical",
  category: "sqli",
  cwe: "CWE-943",
  description:
    "A MongoDB query passes `$where` with a value sourced from req.body, req.query, req.params, req.headers, ctx.request, or `userInput`. The Mongo server evaluates `$where` as JavaScript, so the attacker controls server-side code: `this.password.match(/^a.*/)` style payloads exfiltrate other users' fields one char at a time. Replace `$where` with declarative operators (`$regex`, `$eq`, `$in`) and validate the user input first, or drop `$where` support entirely on this collection.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (!isQueryCall(call)) continue
      const args = call.getArguments()
      for (const arg of args) {
        if (objectHasUserControlledWhere(arg)) {
          hits.push({
            lineNumber: lineOf(call),
            lineContent: lineContentOf(call, sourceFile),
          })
          break
        }
      }
    }
    return hits
  },
}

registerAstRule(NOSQL_INJECTION_RULE)

export { NOSQL_INJECTION_RULE }
