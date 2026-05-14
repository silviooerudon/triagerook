import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/open-redirect-user-url", () => {
  const rule = "ast/open-redirect-user-url"

  it("flags res.redirect(req.body.url)", () => {
    const code = `app.get('/r', (req, res) => res.redirect(req.body.url))`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags res.redirect with template literal containing req.query", () => {
    const code = `res.redirect(\`/login?next=\${req.query.next}\`)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags res.redirect(status, url) form with user input as second arg", () => {
    const code = `res.redirect(302, req.body.next)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags NextResponse.redirect with user input", () => {
    const code = `return NextResponse.redirect(req.body.target)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags ctx.redirect with user input (Koa)", () => {
    const code = `ctx.redirect(ctx.request.body.url)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  // ─── NO-MATCH ───

  it("does NOT flag res.redirect to a constant path", () => {
    const code = `res.redirect('/dashboard')`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag res.redirect to session-derived path", () => {
    const code = `res.redirect(req.session.returnTo)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag unrelated method named redirect", () => {
    const code = `router.redirect(req.body.url)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-601 + high + open-redirect category", () => {
    const code = `res.redirect(req.body.url)`
    const [hit] = findRule(code, "src/api.ts", rule)
    expect(hit.cwe).toBe("CWE-601")
    expect(hit.severity).toBe("high")
    expect(hit.category).toBe("open-redirect")
  })
})
