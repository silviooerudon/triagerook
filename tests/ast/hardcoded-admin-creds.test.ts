import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/hardcoded-admin-credentials", () => {
  const rule = "ast/hardcoded-admin-credentials"

  it("flags username === 'admin'", () => {
    const code = `if (username === 'admin') ok()`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags user === 'root'", () => {
    const code = `if (user === 'root') login()`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags password === 'admin' (placeholder password)", () => {
    const code = `if (password === 'admin') login()`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags pwd === '123456'", () => {
    const code = `if (pwd === '123456') ok()`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags req.body.username === 'administrator' (property access)", () => {
    const code = `if (req.body.username === 'administrator') login()`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags 'admin' === username (literal on left side)", () => {
    const code = `if ('admin' === username) login()`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  // ─── NO-MATCH ───

  it("does NOT flag username === 'alice' (regular user)", () => {
    const code = `if (username === 'alice') showAliceUI()`
    expect(findRule(code, "src/ui.ts", rule).length).toBe(0)
  })

  it("does NOT flag password === randomVariable (no literal)", () => {
    const code = `if (password === storedHash) login()`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(0)
  })

  it("does NOT flag unrelated identifier compared to 'admin'", () => {
    const code = `if (role === 'admin') showAdminUI()`
    expect(findRule(code, "src/ui.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-798 + critical + hardcoded-creds", () => {
    const code = `if (username === 'admin') ok()`
    const [hit] = findRule(code, "src/auth.ts", rule)
    expect(hit.cwe).toBe("CWE-798")
    expect(hit.severity).toBe("critical")
    expect(hit.category).toBe("hardcoded-creds")
  })
})
