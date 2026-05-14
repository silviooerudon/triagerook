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

// Node's `fs` surface that takes a path as the first arg. We deliberately
// include both sync and async variants; the sync forms (Sync suffix) are
// what AI assistants emit most often in serverless handlers because they
// "look simpler".
const FS_CALL_LAST_SEGMENT =
  /^(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|appendFileSync|createReadStream|createWriteStream|access|accessSync|unlink|unlinkSync|stat|statSync|lstat|lstatSync|readdir|readdirSync|rmdir|rmdirSync|rm|rmSync|copyFile|copyFileSync|open|openSync)$/

// path.join / path.resolve / path.normalize — when one of THEIR arguments
// is user input, the resulting path is attacker-controlled even if the
// surrounding code looks like a base-dir is being prepended.
function isPathBuilderCall(node: Node): boolean {
  if (!node.isKind(SyntaxKind.CallExpression)) return false
  const name = getCallCalleeName(node)
  if (!name) return false
  const last = name.split(".").pop() ?? ""
  if (name !== `path.${last}` && name !== last) return false
  return /^(?:join|resolve|normalize)$/.test(last)
}

function argsContainUserInput(callExpr: Node): boolean {
  if (!callExpr.isKind(SyntaxKind.CallExpression)) return false
  for (const arg of callExpr.getArguments()) {
    if (isUserInputExpression(arg)) return true
    if (arg.isKind(SyntaxKind.TemplateExpression) && findUserInputInTemplate(arg)) return true
    if (arg.isKind(SyntaxKind.BinaryExpression) && findUserInputInBinaryConcat(arg)) return true
  }
  return false
}

function pathArgIsUserControlled(arg: Node): boolean {
  if (isUserInputExpression(arg)) return true
  if (arg.isKind(SyntaxKind.TemplateExpression) && findUserInputInTemplate(arg)) return true
  if (arg.isKind(SyntaxKind.BinaryExpression) && findUserInputInBinaryConcat(arg)) return true
  // path.join(__dirname, req.body.file) — the path-builder call wraps the
  // tainted segment, so the final string passed to fs is still attacker
  // controlled. Detect it one level deep.
  if (isPathBuilderCall(arg) && argsContainUserInput(arg)) return true
  return false
}

const PATH_TRAVERSAL_RULE: AstRule = {
  id: "ast/path-traversal-fs",
  name: "Path traversal: fs API called with user-controlled path",
  severity: "critical",
  category: "path-traversal",
  cwe: "CWE-22",
  description:
    "A Node.js fs.* call receives a path argument that is, or is derived from, a value sourced from req.body, req.query, req.params, req.headers, ctx.request, or `userInput`. Even when wrapped in path.join(__dirname, ...), the user-controlled segment can include `../` and escape the intended directory. Use a strict allow-list of filenames or join with a sanitised basename instead.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const name = getCallCalleeName(call)
      if (!name) continue
      const last = name.split(".").pop() ?? ""
      if (!FS_CALL_LAST_SEGMENT.test(last)) continue

      const args = call.getArguments()
      if (args.length === 0) continue
      if (!pathArgIsUserControlled(args[0])) continue

      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(PATH_TRAVERSAL_RULE)

export { PATH_TRAVERSAL_RULE }
