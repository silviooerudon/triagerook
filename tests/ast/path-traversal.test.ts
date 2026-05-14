import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/path-traversal-fs", () => {
  const rule = "ast/path-traversal-fs"

  it("flags fs.readFile with direct req.body.file", () => {
    const code = `
      const fs = require('fs')
      app.get('/d', (req, res) => fs.readFile(req.body.file, cb))
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags fs.readFileSync with template literal containing req.body", () => {
    const code = `
      const data = fs.readFileSync(\`/uploads/\${req.body.name}\`)
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags fs.readFile wrapped in path.join with user input", () => {
    const code = `
      const path = require('path')
      fs.readFile(path.join(__dirname, req.body.file), cb)
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags fs.writeFileSync with concat user input", () => {
    const code = `
      fs.writeFileSync("/tmp/" + req.body.name, data)
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags fs.unlink with user input (delete-arbitrary)", () => {
    const code = `
      fs.unlink(req.query.target, cb)
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags fs.createReadStream with template + req.params", () => {
    const code = `
      fs.createReadStream(\`/files/\${req.params.id}\`).pipe(res)
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  // ─── NO-MATCH cases ───

  it("does NOT flag fs.readFile with a static path", () => {
    const code = `fs.readFile('./package.json', cb)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag fs.readFile with __dirname + static segment", () => {
    const code = `fs.readFile(path.join(__dirname, 'config.json'), cb)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag fs.readFile with session-derived data", () => {
    const code = `fs.readFile(\`/u/\${req.session.userId}.json\`, cb)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag fs.readFile of an arbitrary path variable", () => {
    // No user-input expression at the call site. Out of scope for v1
    // (would require basic data-flow tracking).
    const code = `
      const filePath = computePath()
      fs.readFile(filePath, cb)
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-22 + critical + path-traversal category", () => {
    const code = `fs.readFile(req.body.file, cb)`
    const [hit] = findRule(code, "src/api.ts", rule)
    expect(hit.cwe).toBe("CWE-22")
    expect(hit.severity).toBe("critical")
    expect(hit.category).toBe("path-traversal")
  })
})
