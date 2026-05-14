import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/math-random-for-security-token", () => {
  const rule = "ast/math-random-for-security-token"

  it("flags const token = Math.random().toString(36)", () => {
    const code = `const token = Math.random().toString(36).slice(2)`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags const sessionId = Math.random().toString(36)", () => {
    const code = `const sessionId = Math.random().toString(36)`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags const csrfToken = String(Math.random())", () => {
    const code = `const csrfToken = String(Math.random())`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags property assignment user.resetToken = Math.random().toString()", () => {
    const code = `user.resetToken = Math.random().toString()`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags function generateOtp() returning Math.random based value", () => {
    const code = `
      function generateOtp() {
        return Math.floor(Math.random() * 1000000)
      }
    `
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags object literal { nonce: Math.random() }", () => {
    const code = `const o = { nonce: Math.random().toString(36) }`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  // ─── NO-MATCH ───

  it("does NOT flag Math.random for shuffles / animations", () => {
    const code = `const i = Math.floor(Math.random() * items.length)`
    expect(findRule(code, "src/game.ts", rule).length).toBe(0)
  })

  it("does NOT flag Math.random assigned to non-security-named variable", () => {
    const code = `const r = Math.random()`
    expect(findRule(code, "src/util.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-338 + critical + weak-crypto category", () => {
    const code = `const token = Math.random().toString(36)`
    const [hit] = findRule(code, "src/auth.ts", rule)
    expect(hit.cwe).toBe("CWE-338")
    expect(hit.severity).toBe("critical")
    expect(hit.category).toBe("weak-crypto")
  })
})
