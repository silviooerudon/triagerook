import { SyntaxKind, type SourceFile } from "ts-morph"
import {
  findUserInputInBinaryConcat,
  findUserInputInTemplate,
  getCallCalleeName,
  lineContentOf,
  lineOf,
} from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// Recognise the call sites where untrusted SQL most often lands. Match
// on the last dotted segment so any of `db.query(...)`, `conn.query(...)`,
// `pool.query(...)`, `client.query(...)`, `knex.raw(...)`, `db.execute(...)`,
// `pgClient.run(...)` etc. all map to the same risk.
const SQL_CALL_LAST_SEGMENT = /^(?:query|execute|exec|run|raw|prepare)$/i

// Reduce false positives: only flag if the literal portion of the
// template actually looks like SQL. A template like `Hello ${req.body.name}`
// is interesting for other reasons (XSS, log injection) but not SQLi.
const SQL_KEYWORD = /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|UNION|INTO|VALUES)\b/i

function templateLooksLikeSql(template: ReturnType<SourceFile["getDescendantsOfKind"]>[number]): boolean {
  if (!template.isKind(SyntaxKind.TemplateExpression)) return false
  const head = template.getHead().getLiteralText()
  if (SQL_KEYWORD.test(head)) return true
  for (const span of template.getTemplateSpans()) {
    if (SQL_KEYWORD.test(span.getLiteral().getLiteralText())) return true
  }
  return false
}

function stringConcatLooksLikeSql(expr: ReturnType<SourceFile["getDescendantsOfKind"]>[number]): boolean {
  // Walk the BinaryExpression `+` tree and collect string literal text.
  const literals: string[] = []
  function walk(n: typeof expr): void {
    if (n.isKind(SyntaxKind.StringLiteral) || n.isKind(SyntaxKind.NoSubstitutionTemplateLiteral)) {
      literals.push(n.getLiteralText())
      return
    }
    if (n.isKind(SyntaxKind.BinaryExpression)) {
      if (n.getOperatorToken().getKind() === SyntaxKind.PlusToken) {
        walk(n.getLeft() as typeof expr)
        walk(n.getRight() as typeof expr)
      }
    }
  }
  walk(expr)
  return literals.some((s) => SQL_KEYWORD.test(s))
}

const SQL_INJECTION_TEMPLATE_RULE: AstRule = {
  id: "ast/sql-injection-template",
  name: "SQL injection via template literal interpolating user input",
  severity: "critical",
  category: "sqli",
  cwe: "CWE-89",
  description:
    "A query/execute/raw/run call receives a tagged template literal that interpolates a value sourced from req.body, req.query, req.params, req.headers, ctx.request, or `userInput`. Interpolating raw user input into SQL is the textbook injection vector — use parameterised queries instead. Detected via AST: false positives are rare because we require both the SQL-call shape AND the user-input expression in the same call site.",
  languages: ["js", "ts"],
  detect(sourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      const name = getCallCalleeName(call)
      if (!name) continue
      const lastSegment = name.split(".").pop() ?? ""
      if (!SQL_CALL_LAST_SEGMENT.test(lastSegment)) continue

      const args = call.getArguments()
      if (args.length === 0) continue
      const firstArg = args[0]

      // Template literal path
      if (firstArg.isKind(SyntaxKind.TemplateExpression)) {
        if (!templateLooksLikeSql(firstArg)) continue
        const userInput = findUserInputInTemplate(firstArg)
        if (!userInput) continue
        hits.push({
          lineNumber: lineOf(call),
          lineContent: lineContentOf(call, sourceFile),
        })
        continue
      }

      // String + concat path
      if (firstArg.isKind(SyntaxKind.BinaryExpression)) {
        if (!stringConcatLooksLikeSql(firstArg)) continue
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

registerAstRule(SQL_INJECTION_TEMPLATE_RULE)

export { SQL_INJECTION_TEMPLATE_RULE }
