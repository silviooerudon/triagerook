import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/insecure-websocket-protocol", () => {
  const rule = "ast/insecure-websocket-protocol"

  it("flags new WebSocket('ws://...')", () => {
    const code = `const sock = new WebSocket("ws://api.example.com/feed")`
    expect(findRule(code, "src/client.ts", rule).length).toBe(1)
  })

  it("flags new WebSocket with template literal (no interpolation) starting ws://", () => {
    const code = `const sock = new WebSocket(\`ws://api.example.com/feed\`)`
    expect(findRule(code, "src/client.ts", rule).length).toBe(1)
  })

  it("flags case-insensitive WS:// prefix", () => {
    const code = `const sock = new WebSocket("WS://example.com")`
    expect(findRule(code, "src/client.ts", rule).length).toBe(1)
  })

  it("flags ReconnectingWebSocket as well", () => {
    const code = `const sock = new ReconnectingWebSocket("ws://api.example.com/feed")`
    expect(findRule(code, "src/client.ts", rule).length).toBe(1)
  })

  it("does NOT flag wss://", () => {
    const code = `const sock = new WebSocket("wss://api.example.com/feed")`
    expect(findRule(code, "src/client.ts", rule).length).toBe(0)
  })

  it("does NOT flag a non-string URL argument (variable / template with interpolation)", () => {
    const code = `const sock = new WebSocket(url)`
    expect(findRule(code, "src/client.ts", rule).length).toBe(0)
  })

  it("does NOT flag new of an unrelated class with a ws:// URL string", () => {
    // We only match WebSocket and ReconnectingWebSocket constructors. A
    // user-defined SocketClient with the same string isn't flagged —
    // the regex code-vulns layer is responsible for picking up bare
    // "ws://" mentions.
    const code = `const sock = new SocketClient("ws://api.example.com/feed")`
    expect(findRule(code, "src/client.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-319 + high + tls-verification category", () => {
    const code = `new WebSocket("ws://x")`
    const [hit] = findRule(code, "src/client.ts", rule)
    expect(hit.cwe).toBe("CWE-319")
    expect(hit.severity).toBe("high")
    expect(hit.category).toBe("tls-verification")
  })
})
