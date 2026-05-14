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

function argIsUserControlled(arg: Node): boolean {
  if (isUserInputExpression(arg)) return true
  if (arg.isKind(SyntaxKind.TemplateExpression) && findUserInputInTemplate(arg)) return true
  if (arg.isKind(SyntaxKind.BinaryExpression) && findUserInputInBinaryConcat(arg)) return true
  return false
}

// Detect eval(...) and the indirect call form eval?.(...). The regex
// version in lib/code-vulns.ts catches any eval() call site; the AST
// version distinguishes "eval of user input" (critical) from "eval of
// constant config" (still bad but lower severity), and reduces FP on
// `obj.eval(...)` where eval is a method on an unrelated library.
const DYNAMIC_EVAL_RULE: AstRule = {
  id: "ast/eval-user-input",
  name: "Dynamic eval / new Function called with user-controlled string",
  severity: "critical",
  category: "eval",
  cwe: "CWE-95",
  description:
    "eval() or `new Function(...)` was called with an argument that interpolates or concatenates a value sourced from req.body, req.query, req.params, req.headers, ctx.request, or `userInput`. The user controls JavaScript that the server then executes — arbitrary code execution. Refactor to parse the input with a structured schema (JSON.parse with validation, or a real expression parser) and act on it via a dispatch map.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []

    // eval(<user input>)
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const name = getCallCalleeName(call)
      if (!name) continue

      // Bare eval(...) is the call we care about. We do NOT flag
      // `regex.eval(...)` or `someObject.eval(...)` because those are
      // not the language built-in.
      if (name !== "eval") continue

      const args = call.getArguments()
      if (args.length === 0) continue
      if (!argIsUserControlled(args[0])) continue

      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }

    // new Function(<user input>)
    for (const newExpr of sourceFile.getDescendantsOfKind(SyntaxKind.NewExpression)) {
      const ctor = newExpr.getExpression()
      if (!ctor.isKind(SyntaxKind.Identifier)) continue
      if (ctor.getText() !== "Function") continue

      const args = newExpr.getArguments()
      if (args.length === 0) continue

      // new Function takes (...paramNames, body). The body is the LAST
      // argument. Flag if any of the args contains user input — most
      // commonly the body, but param names from user input would also
      // be exploitable.
      let tainted = false
      for (const arg of args) {
        if (argIsUserControlled(arg)) {
          tainted = true
          break
        }
      }
      if (!tainted) continue

      hits.push({
        lineNumber: lineOf(newExpr),
        lineContent: lineContentOf(newExpr, sourceFile),
      })
    }

    return hits
  },
}

registerAstRule(DYNAMIC_EVAL_RULE)

export { DYNAMIC_EVAL_RULE }
