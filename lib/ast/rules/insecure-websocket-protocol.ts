import { SyntaxKind, type Node, type SourceFile } from "ts-morph"
import { lineContentOf, lineOf } from "../helpers"
import { registerAstRule, type AstRule, type AstRuleHit } from "../runner"

// new WebSocket("ws://host/path") opens a cleartext socket — credentials,
// session cookies, and payload all travel un-encrypted. The fix is wss://.
// We flag literal strings only — variable / template URLs are out of
// scope because the protocol scheme would have to be tracked across the
// data flow, and the regex layer already catches "ws://" in source files
// at a higher recall / lower precision setting.

const INSECURE_PROTOCOLS = new Set(["ws://", "ws:"])

function getInsecureProtocolPrefix(text: string): string | null {
  const lower = text.toLowerCase()
  if (lower.startsWith("ws://")) return "ws://"
  return null
}

function isWebSocketConstructor(newExpr: Node): boolean {
  if (!newExpr.isKind(SyntaxKind.NewExpression)) return false
  const expr = newExpr.getExpression()
  if (!expr.isKind(SyntaxKind.Identifier)) return false
  const name = expr.getText()
  return name === "WebSocket" || name === "ReconnectingWebSocket"
}

const INSECURE_WS_RULE: AstRule = {
  id: "ast/insecure-websocket-protocol",
  name: "WebSocket opened over cleartext ws:// instead of wss://",
  severity: "high",
  category: "tls-verification",
  cwe: "CWE-319",
  description:
    "new WebSocket(\"ws://...\") opens an unencrypted connection. Any cookie sent during the handshake, every message body, and any token in the URL travels in cleartext — trivially readable on shared Wi-Fi, hotel networks, or anywhere a network device sees the bytes. Switch to wss:// and terminate TLS at the same gateway as your HTTPS traffic. For local development behind localhost, gate the protocol on process.env.NODE_ENV so production code paths never reach the ws:// branch.",
  languages: ["js", "ts"],
  detect(sourceFile: SourceFile): AstRuleHit[] {
    const hits: AstRuleHit[] = []
    for (const newExpr of sourceFile.getDescendantsOfKind(SyntaxKind.NewExpression)) {
      if (!isWebSocketConstructor(newExpr)) continue
      const args = newExpr.getArguments()
      if (args.length === 0) continue
      const first = args[0]
      let text: string | null = null
      if (
        first.isKind(SyntaxKind.StringLiteral) ||
        first.isKind(SyntaxKind.NoSubstitutionTemplateLiteral)
      ) {
        text = first.getLiteralText()
      }
      if (!text) continue
      const proto = getInsecureProtocolPrefix(text)
      if (!proto) continue
      hits.push({
        lineNumber: lineOf(newExpr),
        lineContent: lineContentOf(newExpr, sourceFile),
      })
    }
    return hits
  },
}

registerAstRule(INSECURE_WS_RULE)

export { INSECURE_WS_RULE, INSECURE_PROTOCOLS }
