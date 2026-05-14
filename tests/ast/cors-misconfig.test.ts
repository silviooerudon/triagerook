import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/cors-credentials-with-any-origin", () => {
  const rule = "ast/cors-credentials-with-any-origin"

  it("flags cors({ origin: '*', credentials: true })", () => {
    const code = `app.use(cors({ origin: '*', credentials: true }))`
    expect(findRule(code, "src/server.ts", rule).length).toBe(1)
  })

  it("flags cors({ origin: true, credentials: true })", () => {
    const code = `app.use(cors({ origin: true, credentials: true }))`
    expect(findRule(code, "src/server.ts", rule).length).toBe(1)
  })

  it("does NOT flag cors with a specific origin string", () => {
    const code = `app.use(cors({ origin: 'https://app.example.com', credentials: true }))`
    expect(findRule(code, "src/server.ts", rule).length).toBe(0)
  })

  it("does NOT flag cors({ origin: '*' }) without credentials", () => {
    const code = `app.use(cors({ origin: '*' }))`
    expect(findRule(code, "src/server.ts", rule).length).toBe(0)
  })

  it("does NOT flag cors() with no config", () => {
    const code = `app.use(cors())`
    expect(findRule(code, "src/server.ts", rule).length).toBe(0)
  })

  it("does NOT flag origin with allow-list array", () => {
    const code = `cors({ origin: ['https://x', 'https://y'], credentials: true })`
    expect(findRule(code, "src/server.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-942 + high + cors category", () => {
    const code = `cors({ origin: '*', credentials: true })`
    const [hit] = findRule(code, "src/server.ts", rule)
    expect(hit.cwe).toBe("CWE-942")
    expect(hit.severity).toBe("high")
    expect(hit.category).toBe("cors")
  })
})
