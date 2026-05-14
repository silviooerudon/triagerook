import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/redos-dynamic-regexp-user-input", () => {
  const rule = "ast/redos-dynamic-regexp-user-input"

  it("flags new RegExp(req.body.pattern)", () => {
    const code = `const re = new RegExp(req.body.pattern)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags RegExp(req.query.q) without new", () => {
    const code = `const re = RegExp(req.query.q, 'i')`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags new RegExp with template literal interpolating req.body", () => {
    const code = `new RegExp(\`^prefix-\${req.body.suffix}\`)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("does NOT flag new RegExp with literal pattern", () => {
    const code = `new RegExp('^foo$')`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag new RegExp with session-derived input", () => {
    const code = `new RegExp(req.session.pattern)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag a regex literal", () => {
    const code = `const re = /foo/gi`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-1333 + high + denial-of-service", () => {
    const code = `new RegExp(req.body.p)`
    const [hit] = findRule(code, "src/api.ts", rule)
    expect(hit.cwe).toBe("CWE-1333")
    expect(hit.severity).toBe("high")
    expect(hit.category).toBe("denial-of-service")
  })
})
