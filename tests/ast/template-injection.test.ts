import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/template-injection-user-input", () => {
  const rule = "ast/template-injection-user-input"

  it("flags Handlebars.compile(req.body.template)", () => {
    const code = `const t = Handlebars.compile(req.body.template); res.send(t({}))`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags handlebars.compile (lowercase namespace) with req.query", () => {
    const code = `const t = handlebars.compile(req.query.tpl)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags pug.compile with template literal interpolating user input", () => {
    const code = `pug.compile(\`h1= \${req.body.title}\`)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags ejs.render(req.body.tpl, data)", () => {
    const code = `ejs.render(req.body.tpl, { user })`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags nunjucks.renderString with req.params.tpl", () => {
    const code = `nunjucks.renderString(req.params.tpl, ctx)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  // ─── NO-MATCH ───

  it("does NOT flag Handlebars.compile of a constant template", () => {
    const code = `const t = Handlebars.compile('<h1>{{title}}</h1>')`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag user input in DATA slot (only template body matters)", () => {
    const code = `
      const t = Handlebars.compile('<h1>{{name}}</h1>')
      res.send(t({ name: req.body.name }))
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag an unrelated method called compile", () => {
    const code = `bundler.compile(req.body.source)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-1336 + critical + command-injection category", () => {
    const code = `Handlebars.compile(req.body.tpl)`
    const [hit] = findRule(code, "src/api.ts", rule)
    expect(hit.cwe).toBe("CWE-1336")
    expect(hit.severity).toBe("critical")
    expect(hit.category).toBe("command-injection")
  })
})
