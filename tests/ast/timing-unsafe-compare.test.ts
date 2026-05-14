import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/timing-unsafe-credential-compare", () => {
  const rule = "ast/timing-unsafe-credential-compare"

  it("flags password === bareIdentifier compare", () => {
    const code = `if (password === storedPassword) login()`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags user.password === input.password", () => {
    const code = `if (user.password === input.password) login()`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags token === expected", () => {
    const code = `if (token === expected) authorise()`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags hmac == signature", () => {
    const code = `if (hmac == signature) verify()`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags apiKey === process.env.API_KEY", () => {
    const code = `if (req.headers['x-api-key'] === process.env.API_KEY) ok()`
    // Left side is element access, right is property access named API_KEY.
    // Neither side is a bare identifier "apiKey" or a .apiKey property,
    // so this should NOT trip the rule — documents the limit.
    expect(findRule(code, "src/auth.ts", rule).length).toBe(0)
  })

  it("does NOT flag unrelated comparison", () => {
    const code = `if (userId === otherId) doStuff()`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(0)
  })

  it("does NOT flag with crypto.timingSafeEqual idiom (different shape)", () => {
    const code = `crypto.timingSafeEqual(a, b)`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-208 + high + timing-attack category", () => {
    const code = `if (password === stored) ok()`
    const [hit] = findRule(code, "src/auth.ts", rule)
    expect(hit.cwe).toBe("CWE-208")
    expect(hit.severity).toBe("high")
    expect(hit.category).toBe("timing-attack")
  })
})
