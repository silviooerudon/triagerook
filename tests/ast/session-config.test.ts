import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/insecure-session-config", () => {
  const rule = "ast/insecure-session-config"

  it("flags session({ secret: 'literal-secret' })", () => {
    const code = `app.use(session({ secret: 'my-app-secret', resave: false }))`
    expect(findRule(code, "src/server.ts", rule).length).toBe(1)
  })

  it("flags session({ cookie: { httpOnly: false } })", () => {
    const code = `app.use(session({ secret: process.env.S, cookie: { httpOnly: false } }))`
    expect(findRule(code, "src/server.ts", rule).length).toBe(1)
  })

  it("flags session({ cookie: { secure: false } })", () => {
    const code = `session({ secret: process.env.S, cookie: { secure: false } })`
    expect(findRule(code, "src/server.ts", rule).length).toBe(1)
  })

  it("flags cookieSession({ secret: 'literal' })", () => {
    const code = `app.use(cookieSession({ secret: 'literal-secret' }))`
    expect(findRule(code, "src/server.ts", rule).length).toBe(1)
  })

  // ─── NO-MATCH ───

  it("does NOT flag session with process.env secret + secure cookies", () => {
    const code = `
      app.use(session({
        secret: process.env.SESSION_SECRET,
        cookie: { httpOnly: true, secure: true },
        resave: false,
      }))
    `
    expect(findRule(code, "src/server.ts", rule).length).toBe(0)
  })

  it("does NOT flag an unrelated function called session()", () => {
    const code = `db.session({ secret: 'x' })`
    expect(findRule(code, "src/server.ts", rule).length).toBe(0)
  })

  it("does NOT flag session() with no config", () => {
    const code = `app.use(session())`
    expect(findRule(code, "src/server.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-614 + high + weak-session category", () => {
    const code = `session({ secret: 'lit' })`
    const [hit] = findRule(code, "src/server.ts", rule)
    expect(hit.cwe).toBe("CWE-614")
    expect(hit.severity).toBe("high")
    expect(hit.category).toBe("weak-session")
  })
})
