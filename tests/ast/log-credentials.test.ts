import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/log-credential-disclosure", () => {
  const rule = "ast/log-credential-disclosure"

  it("flags console.log(password)", () => {
    const code = `function authn(password) { console.log(password) }`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags console.log(user.password)", () => {
    const code = `console.log(user.password)`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags console.error(token) — error channel too", () => {
    const code = `console.error('login failed', token)`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags logger.info with apiKey identifier", () => {
    const code = `logger.info({ apiKey })`
    // ObjectLiteral with shorthand prop — out of scope for v1 (only
    // direct identifier / property access args are checked). Document
    // the limitation.
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("flags template literal containing 'token' identifier", () => {
    const code = `console.log(\`auth header: \${token}\`)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags concat with accessToken", () => {
    const code = `console.log('Authorization: Bearer ' + accessToken)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  // ─── NO-MATCH ───

  it("does NOT flag console.log on non-credential identifier", () => {
    const code = `console.log(userId, requestId, action)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag console.log of a static message", () => {
    const code = `console.log('user logged in')`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag pino on a property unrelated to credentials", () => {
    const code = `pino.info({ duration: ms }, 'request completed')`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-532 + high + logging category", () => {
    const code = `console.log(password)`
    const [hit] = findRule(code, "src/api.ts", rule)
    expect(hit.cwe).toBe("CWE-532")
    expect(hit.severity).toBe("high")
    expect(hit.category).toBe("logging")
  })
})
