import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/wildcard-cors-via-set-header", () => {
  const rule = "ast/wildcard-cors-via-set-header"

  it("flags res.setHeader('Access-Control-Allow-Origin', '*')", () => {
    const code = `res.setHeader('Access-Control-Allow-Origin', '*')`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags res.set('Access-Control-Allow-Origin', '*')", () => {
    const code = `res.set('Access-Control-Allow-Origin', '*')`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags res.header (Express alias) with wildcard origin", () => {
    const code = `res.header('Access-Control-Allow-Origin', '*')`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("matches case-insensitively on the header name", () => {
    const code = `res.setHeader('access-control-allow-origin', '*')`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  // ─── NO-MATCH ───

  it("does NOT flag a specific origin", () => {
    const code = `res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com')`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag wildcard on an unrelated header", () => {
    const code = `res.setHeader('X-Foo', '*')`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag setHeader on a non-res object", () => {
    const code = `socket.setHeader('Access-Control-Allow-Origin', '*')`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-942 + high + cors", () => {
    const code = `res.setHeader('Access-Control-Allow-Origin', '*')`
    const [hit] = findRule(code, "src/api.ts", rule)
    expect(hit.cwe).toBe("CWE-942")
    expect(hit.severity).toBe("high")
    expect(hit.category).toBe("cors")
  })
})
