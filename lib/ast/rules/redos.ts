import { Node, SyntaxKind, type SourceFile } from "ts-morph"
import {
  findUserInputInBinaryConcat,
  findUserInputInTemplate,
  isUserInputExpression,
  lineContentOf,
  lineOf,
} from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// new RegExp(<user input>) is a Regular-Expression Denial-of-Service
// vector — the attacker controls the pattern and can craft catastrophic
// backtracking like /(a+)+$/ that pegs the event loop for tens of
// seconds. Node's regex engine doesn't have a built-in timeout, so on a
// serverless function this is a free DoS knob.

function patternArgIsUserControlled(arg: Node): boolean {
  if (isUserInputExpression(arg)) return true
  if (arg.isKind(SyntaxKind.TemplateExpression) && findUserInputInTemplate(arg)) return true
  if (arg.isKind(SyntaxKind.BinaryExpression) && findUserInputInBinaryConcat(arg)) return true
  return false
}

const REDOS_RULE: AstRule = {
  id: "ast/redos-dynamic-regexp-user-input",
  name: "ReDoS: RegExp constructed from user-controlled string",
  severity: "high",
  category: "denial-of-service",
  cwe: "CWE-1333",
  description:
    "`new RegExp(<user input>)` (or `RegExp(<user input>)`) compiles a regex pattern under attacker control. Crafted nested quantifiers like `(a+)+$` cause catastrophic backtracking that hangs the Node event loop, denying service to other requests on the same instance. On serverless this also burns billed CPU. Either accept only an allow-list of patterns, escape the input to treat it as a literal (replace special chars), or wrap the .match/.test call with a timeout (e.g. via worker thread).",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []

    // new RegExp(<user input>, [flags])
    for (const newExpr of sourceFile.getDescendantsOfKind(SyntaxKind.NewExpression)) {
      const ctor = newExpr.getExpression()
      if (!ctor.isKind(SyntaxKind.Identifier)) continue
      if (ctor.getText() !== "RegExp") continue
      const args = newExpr.getArguments()
      if (args.length === 0) continue
      if (!patternArgIsUserControlled(args[0])) continue
      hits.push({
        lineNumber: lineOf(newExpr),
        lineContent: lineContentOf(newExpr, sourceFile),
      })
    }

    // RegExp(<user input>, [flags]) — without `new`
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const expr = call.getExpression()
      if (!expr.isKind(SyntaxKind.Identifier)) continue
      if (expr.getText() !== "RegExp") continue
      const args = call.getArguments()
      if (args.length === 0) continue
      if (!patternArgIsUserControlled(args[0])) continue
      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }

    return hits
  },
}

registerAstRule(REDOS_RULE)

export { REDOS_RULE }
