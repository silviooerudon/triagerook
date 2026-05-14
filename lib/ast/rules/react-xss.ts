import { Node, SyntaxKind, type SourceFile } from "ts-morph"
import {
  findUserInputInBinaryConcat,
  findUserInputInTemplate,
  isUserInputExpression,
  lineContentOf,
  lineOf,
} from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// Walks a JSX `dangerouslySetInnerHTML={{ __html: <expr> }}` and returns
// the expression assigned to __html. Null when the attribute is malformed
// or the value isn't an object literal.
function unwrapDangerousHtmlValue(initializer: Node | undefined): Node | null {
  if (!initializer) return null
  if (!initializer.isKind(SyntaxKind.JsxExpression)) return null
  const inner = initializer.getExpression()
  if (!inner || !inner.isKind(SyntaxKind.ObjectLiteralExpression)) return null

  for (const prop of inner.getProperties()) {
    if (!prop.isKind(SyntaxKind.PropertyAssignment)) continue
    const name = prop.getName()
    if (name !== "__html") continue
    return prop.getInitializer() ?? null
  }
  return null
}

function htmlExpressionIsUserControlled(expr: Node): boolean {
  if (isUserInputExpression(expr)) return true
  if (expr.isKind(SyntaxKind.TemplateExpression) && findUserInputInTemplate(expr)) return true
  if (expr.isKind(SyntaxKind.BinaryExpression) && findUserInputInBinaryConcat(expr)) return true
  return false
}

const REACT_XSS_RULE: AstRule = {
  id: "ast/react-dangerously-set-inner-html-user-input",
  name: "React XSS: dangerouslySetInnerHTML fed user-controlled HTML",
  severity: "critical",
  category: "xss",
  cwe: "CWE-79",
  description:
    "A React component sets dangerouslySetInnerHTML with __html sourced from req.body, req.query, req.params, req.headers, ctx.request, or `userInput`. React intentionally skips its escaping for this attribute, so any HTML in the input — including <script> — executes in the browser. Either render the content as text (drop dangerouslySetInnerHTML), or pass it through a HTML sanitiser (DOMPurify) before assigning.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    const attributes = sourceFile.getDescendantsOfKind(SyntaxKind.JsxAttribute)
    for (const attr of attributes) {
      const nameNode = attr.getNameNode()
      if (nameNode.getText() !== "dangerouslySetInnerHTML") continue

      const initializer = attr.getInitializer()
      const htmlExpr = unwrapDangerousHtmlValue(initializer)
      if (!htmlExpr) continue

      if (!htmlExpressionIsUserControlled(htmlExpr)) continue

      hits.push({
        lineNumber: lineOf(attr),
        lineContent: lineContentOf(attr, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(REACT_XSS_RULE)

export { REACT_XSS_RULE }
