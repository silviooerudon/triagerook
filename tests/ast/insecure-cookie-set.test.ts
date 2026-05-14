import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/insecure-cookie-set", () => {
  const rule = "ast/insecure-cookie-set"

  it("flags res.cookie(name, value) without options", () => {
    const code = `res.cookie('sessionId', token)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags res.cookie with httpOnly: false", () => {
    const code = `res.cookie('sessionId', token, { httpOnly: false, secure: true })`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags res.cookie with secure: false", () => {
    const code = `res.cookie('sessionId', token, { httpOnly: true, secure: false })`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags res.cookie with only one of httpOnly/secure (the other implicitly false)", () => {
    const code = `res.cookie('sessionId', token, { httpOnly: true })`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("does NOT flag res.cookie with httpOnly: true + secure: true", () => {
    const code = `res.cookie('sessionId', token, { httpOnly: true, secure: true, sameSite: 'lax' })`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag a non-res cookie setter", () => {
    const code = `document.cookie = 'theme=dark'`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag unrelated method named cookie on a different object", () => {
    const code = `lib.cookie('x', 'y')`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-1004 + high + insecure-cookie category", () => {
    const code = `res.cookie('s', tok)`
    const [hit] = findRule(code, "src/api.ts", rule)
    expect(hit.cwe).toBe("CWE-1004")
    expect(hit.severity).toBe("high")
    expect(hit.category).toBe("insecure-cookie")
  })
})
