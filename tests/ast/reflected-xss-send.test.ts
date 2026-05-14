import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/reflected-xss-via-res-send", () => {
  const rule = "ast/reflected-xss-via-res-send"

  it("flags res.send(req.body.html)", () => {
    const code = `app.post('/echo', (req, res) => res.send(req.body.html))`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags res.send template literal interpolating req.query", () => {
    const code = `res.send(\`<h1>\${req.query.title}</h1>\`)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags res.send concat with user input", () => {
    const code = `res.send('Hello ' + req.body.name)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags res.end with req.body.payload", () => {
    const code = `res.end(req.body.payload)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags res.write with template containing req.body", () => {
    const code = `res.write(\`payload: \${req.body.x}\`)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  // ─── NO-MATCH ───

  it("does NOT flag res.send of a constant", () => {
    const code = `res.send('OK')`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag res.send of req.session data", () => {
    const code = `res.send(\`Hi \${req.session.username}\`)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag res.json (sets application/json content-type)", () => {
    const code = `res.json({ body: req.body.html })`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-79 + high + xss category", () => {
    const code = `res.send(req.body.html)`
    const [hit] = findRule(code, "src/api.ts", rule)
    expect(hit.cwe).toBe("CWE-79")
    expect(hit.severity).toBe("high")
    expect(hit.category).toBe("xss")
  })
})
