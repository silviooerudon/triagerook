import { Node, SyntaxKind, type Expression, type SourceFile } from "ts-morph"

// Identifier prefixes that strongly indicate request-controlled data.
// Conservative — anything that requires data-flow tracing across function
// boundaries is intentionally out of scope so we don't false-positive on
// non-server code (libraries, tests, build scripts).
const USER_INPUT_OBJECTS = new Set([
  "req",
  "request",
  "ctx",
  "context",
])

// Properties of `req` that surface untrusted data. We do NOT treat
// `req.session.*` or `req.user.*` as untrusted — those have already been
// authenticated by middleware in typical Express/Fastify stacks.
const USER_INPUT_PROPERTIES = new Set([
  "body",
  "query",
  "params",
  "headers",
  "cookies",
  "url",
  "originalUrl",
])

// Bare identifiers that conventionally hold user-controlled data in the
// scripts AI assistants write ("userInput", "input", "args"). Narrow on
// purpose — extending this set is the easiest way to false-positive
// legitimate variables.
const USER_INPUT_IDENTIFIERS = new Set(["userInput", "userQuery", "userArg"])

// Walks a property/element access chain rooted at an Identifier. Returns
// the root identifier text and the properties in source order (left-most
// to right-most). Null when the leftmost expression is not a simple
// identifier (e.g. `getReq().body` returns null — call expressions are
// out of scope for this conservative analysis).
//
//   req.body.id         -> { root: "req", properties: ["body", "id"] }
//   ctx.request.body    -> { root: "ctx", properties: ["request", "body"] }
//   req["body"].id      -> { root: "req", properties: ["body", "id"] }
//   req[someVar]        -> { root: "req", properties: ["*"] }
type PropertyChain = { root: string; properties: string[] }

function propertyChain(node: Node | undefined): PropertyChain | null {
  if (!node) return null
  if (node.isKind(SyntaxKind.Identifier)) {
    return { root: node.getText(), properties: [] }
  }

  const properties: string[] = []
  let current: Node = node

  while (true) {
    if (current.isKind(SyntaxKind.Identifier)) {
      return { root: current.getText(), properties: properties.reverse() }
    }
    if (current.isKind(SyntaxKind.PropertyAccessExpression)) {
      properties.push(current.getName())
      current = current.getExpression()
      continue
    }
    if (current.isKind(SyntaxKind.ElementAccessExpression)) {
      const argExpr = current.getArgumentExpression()
      if (argExpr && argExpr.isKind(SyntaxKind.StringLiteral)) {
        properties.push(argExpr.getLiteralText())
      } else {
        properties.push("*")
      }
      current = current.getExpression()
      continue
    }
    return null
  }
}

// Returns true when the expression reads from a request-shaped object.
//
// Matches:
//   req.body            req.body.foo            req.body[bar]
//   request.query.id    ctx.request.headers     userInput
//   ctx.request.body.id (Koa: request is an intermediate hop)
//
// Does NOT match:
//   req.session.userId  (already authenticated)
//   user.email          (not request-shaped)
//   req                 (the bare object — only matches sub-property reads)
export function isUserInputExpression(node: Node | undefined): boolean {
  if (!node) return false

  // Bare conventional identifier.
  if (node.isKind(SyntaxKind.Identifier)) {
    return USER_INPUT_IDENTIFIERS.has(node.getText())
  }

  if (
    !node.isKind(SyntaxKind.PropertyAccessExpression) &&
    !node.isKind(SyntaxKind.ElementAccessExpression)
  ) {
    return false
  }

  const chain = propertyChain(node)
  if (!chain) return false
  if (chain.properties.length === 0) return false
  if (!USER_INPUT_OBJECTS.has(chain.root)) return false

  // Koa convention: ctx.request.body / context.request.query — the
  // tainted property comes AFTER a `request` hop, not directly off the
  // root.
  if (
    (chain.root === "ctx" || chain.root === "context") &&
    chain.properties[0] === "request" &&
    chain.properties.length > 1
  ) {
    return USER_INPUT_PROPERTIES.has(chain.properties[1])
  }

  // Express / Fastify / standard: req.body / request.query — first
  // property is the tainted one.
  return USER_INPUT_PROPERTIES.has(chain.properties[0])
}

// Returns the dotted name of the call's callee, or null if not a simple
// identifier / member access.
//
//   db.query(...)          -> "db.query"
//   query(...)             -> "query"
//   child_process.exec(...) -> "child_process.exec"
//   require("cp").exec(...) -> null  (call expression, not a simple name)
export function getCallCalleeName(call: Node): string | null {
  if (!call.isKind(SyntaxKind.CallExpression)) return null
  const expr = call.getExpression()
  return dottedName(expr)
}

function dottedName(node: Node): string | null {
  if (node.isKind(SyntaxKind.Identifier)) {
    return node.getText()
  }
  if (node.isKind(SyntaxKind.PropertyAccessExpression)) {
    const left = dottedName(node.getExpression())
    if (!left) return null
    return `${left}.${node.getName()}`
  }
  return null
}

// Walks every interpolation in a template literal and returns the first
// one (if any) that is a user-input expression. Null when the template
// has no interpolations or none of them are user-input.
//
//   `SELECT * FROM users WHERE id = ${req.body.id}` -> matches
//   `SELECT * FROM users WHERE id = ${id}`          -> no match unless
//                                                     `id` itself is a
//                                                     known user-input
//                                                     identifier
export function findUserInputInTemplate(template: Node): Node | null {
  if (!template.isKind(SyntaxKind.TemplateExpression)) return null
  for (const span of template.getTemplateSpans()) {
    const expr = span.getExpression()
    if (isUserInputExpression(expr)) return expr
  }
  return null
}

// Returns the first user-input subexpression inside a `+` chain, or null.
//
//   "SELECT * FROM x WHERE id = " + req.body.id  -> matches
//   "prefix" + middle + "suffix"                 -> no match unless
//                                                   `middle` is user-input
export function findUserInputInBinaryConcat(expr: Expression): Node | null {
  if (!expr.isKind(SyntaxKind.BinaryExpression)) return null
  const op = expr.getOperatorToken().getKind()
  if (op !== SyntaxKind.PlusToken) return null

  const left = expr.getLeft()
  const right = expr.getRight()

  if (isUserInputExpression(left)) return left
  if (isUserInputExpression(right)) return right

  // Recurse into chained `+`. `a + b + c` parses as `(a + b) + c`.
  return findUserInputInBinaryConcat(left) ?? findUserInputInBinaryConcat(right)
}

export function lineOf(node: Node): number {
  return node.getStartLineNumber()
}

export function lineContentOf(node: Node, sourceFile: SourceFile): string {
  const lineNumber = lineOf(node)
  const lines = sourceFile.getFullText().split("\n")
  return lines[lineNumber - 1] ?? ""
}
