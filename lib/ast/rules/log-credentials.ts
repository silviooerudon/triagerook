import { Node, SyntaxKind, type SourceFile } from "ts-morph"
import { getCallCalleeName, lineContentOf, lineOf } from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// Identifier / property names that are almost certainly credentials when
// they show up in a log call. Conservative on purpose — `name` or `data`
// would FP everywhere.
const CREDENTIAL_NAMES = new Set([
  "password",
  "passwd",
  "pwd",
  "secret",
  "token",
  "apiKey",
  "api_key",
  "accessToken",
  "access_token",
  "refreshToken",
  "refresh_token",
  "sessionToken",
  "session_token",
  "jwt",
  "auth",
  "authorization",
  "credentials",
  "privateKey",
  "private_key",
])

// console.<method> and the common pino/winston logger surfaces. We only
// flag if the FIRST identifier-like expression among the args is a known
// credential — preserves the "log structured metadata" pattern (`log
// .info({ userId }, 'login ok')`) which isn't a credential leak.
const LOG_CALL_LAST_SEGMENT = /^(?:log|info|debug|warn|error|trace|fatal)$/
const LOG_CALLER_OBJECTS = new Set(["console", "logger", "log", "pino", "winston"])

function isCredentialReference(node: Node): boolean {
  if (node.isKind(SyntaxKind.Identifier)) {
    return CREDENTIAL_NAMES.has(node.getText())
  }
  if (node.isKind(SyntaxKind.PropertyAccessExpression)) {
    return CREDENTIAL_NAMES.has(node.getName())
  }
  if (node.isKind(SyntaxKind.TemplateExpression)) {
    for (const span of node.getTemplateSpans()) {
      if (isCredentialReference(span.getExpression())) return true
    }
    return false
  }
  if (node.isKind(SyntaxKind.BinaryExpression)) {
    if (node.getOperatorToken().getKind() === SyntaxKind.PlusToken) {
      return isCredentialReference(node.getLeft()) || isCredentialReference(node.getRight())
    }
  }
  return false
}

function isLogCall(call: Node): boolean {
  if (!call.isKind(SyntaxKind.CallExpression)) return false
  const name = getCallCalleeName(call)
  if (!name) return false
  const parts = name.split(".")
  if (parts.length !== 2) return false
  const [obj, method] = parts
  if (!LOG_CALLER_OBJECTS.has(obj)) return false
  return LOG_CALL_LAST_SEGMENT.test(method)
}

const LOG_CREDENTIALS_RULE: AstRule = {
  id: "ast/log-credential-disclosure",
  name: "Logging: credential-named value passed to console / logger",
  severity: "high",
  category: "logging",
  cwe: "CWE-532",
  description:
    "A console / logger call carries an argument whose identifier or property name is one of: password / token / secret / apiKey / accessToken / refreshToken / jwt / privateKey / authorization / credentials. Vercel / Datadog / CloudWatch logs are often broader-access than the app itself, and committed credentials in log lines are a frequent breach vector. Redact before logging (or just don't log the value — log `{ userId }` instead of `{ password }`).",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
      if (!isLogCall(call)) continue
      const args = call.getArguments()
      const tainted = args.some((a) => isCredentialReference(a))
      if (!tainted) continue
      hits.push({
        lineNumber: lineOf(call),
        lineContent: lineContentOf(call, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(LOG_CREDENTIALS_RULE)

export { LOG_CREDENTIALS_RULE }
