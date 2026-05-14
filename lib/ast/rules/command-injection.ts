import { SyntaxKind } from "ts-morph"
import {
  findUserInputInBinaryConcat,
  findUserInputInTemplate,
  getCallCalleeName,
  lineContentOf,
  lineOf,
} from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// Last-segment matcher for the child_process call surface. Covers
// `exec`, `execSync`, `execFile`, `execFileSync`, `spawn`, `spawnSync`,
// `fork`. We match the LAST segment so all of these compose:
//   exec(...)                         // import { exec } from 'child_process'
//   childProcess.exec(...)            // import * as childProcess
//   require('child_process').exec(...)  -> won't match (not a dotted name)
//                                          but the .exec at the end means
//                                          we still catch `.exec(...)` via
//                                          PropertyAccess on a CallExpression
//                                          if the caller stores require()
//                                          first.
const COMMAND_CALL_LAST_SEGMENT = /^(?:exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)$/

const COMMAND_INJECTION_RULE: AstRule = {
  id: "ast/command-injection-user-input",
  name: "Command injection: child_process exec/spawn called with user input",
  severity: "critical",
  category: "command-injection",
  cwe: "CWE-78",
  description:
    "A call to one of child_process.{exec,execSync,execFile,execFileSync,spawn,spawnSync,fork} receives a first argument that interpolates or concatenates a value sourced from req.body, req.query, req.params, req.headers, ctx.request, or `userInput`. Shell metacharacters in user input become command execution. Detected via AST: requires both the child_process call shape AND the user-input expression in the same call argument, so false positives on lookalike function names are unlikely.",
  languages: ["js", "ts"],
  detect(sourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const name = getCallCalleeName(call)
      if (!name) continue
      const lastSegment = name.split(".").pop() ?? ""
      if (!COMMAND_CALL_LAST_SEGMENT.test(lastSegment)) continue

      const args = call.getArguments()
      if (args.length === 0) continue
      const firstArg = args[0]

      // Template literal: `kill -9 ${req.body.pid}`
      if (firstArg.isKind(SyntaxKind.TemplateExpression)) {
        const userInput = findUserInputInTemplate(firstArg)
        if (!userInput) continue
        hits.push({
          lineNumber: lineOf(call),
          lineContent: lineContentOf(call, sourceFile),
        })
        continue
      }

      // String + concat: "kill -9 " + req.body.pid
      if (firstArg.isKind(SyntaxKind.BinaryExpression)) {
        const userInput = findUserInputInBinaryConcat(firstArg)
        if (!userInput) continue
        hits.push({
          lineNumber: lineOf(call),
          lineContent: lineContentOf(call, sourceFile),
        })
      }
    }
    return hits
  },
}

registerAstRule(COMMAND_INJECTION_RULE)

export { COMMAND_INJECTION_RULE }
