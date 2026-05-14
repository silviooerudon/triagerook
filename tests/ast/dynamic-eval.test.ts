import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/eval-user-input", () => {
  const rule = "ast/eval-user-input"

  it("flags eval(req.body.code)", () => {
    const code = `app.post('/run', (req, res) => res.send(eval(req.body.code)))`
    expect(findRule(code, "src/run.ts", rule).length).toBe(1)
  })

  it("flags eval with template literal interpolating req.query", () => {
    const code = `eval(\`return \${req.query.expr}\`)`
    expect(findRule(code, "src/run.ts", rule).length).toBe(1)
  })

  it("flags new Function(req.body.code)", () => {
    const code = `const f = new Function(req.body.code); f()`
    expect(findRule(code, "src/run.ts", rule).length).toBe(1)
  })

  it("flags new Function with string concat of user input", () => {
    const code = `new Function('arg', 'return ' + req.body.expr)`
    expect(findRule(code, "src/run.ts", rule).length).toBe(1)
  })

  it("flags eval with bare userInput identifier", () => {
    const code = `eval(userInput)`
    expect(findRule(code, "src/run.ts", rule).length).toBe(1)
  })

  // ─── NO-MATCH ───

  it("does NOT flag eval with a constant string", () => {
    const code = `eval('2 + 2')`
    expect(findRule(code, "src/run.ts", rule).length).toBe(0)
  })

  it("does NOT flag obj.eval(req.body.x) (regex/lib method, not the language eval)", () => {
    const code = `regex.eval(req.body.pattern)`
    expect(findRule(code, "src/run.ts", rule).length).toBe(0)
  })

  it("does NOT flag eval with session-derived data", () => {
    const code = `eval(req.session.snippet)`
    expect(findRule(code, "src/run.ts", rule).length).toBe(0)
  })

  it("does NOT flag new Function with constants", () => {
    const code = `new Function('a', 'b', 'return a + b')`
    expect(findRule(code, "src/run.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-95 + critical + eval category", () => {
    const code = `eval(req.body.x)`
    const [hit] = findRule(code, "src/run.ts", rule)
    expect(hit.cwe).toBe("CWE-95")
    expect(hit.severity).toBe("critical")
    expect(hit.category).toBe("eval")
  })
})
