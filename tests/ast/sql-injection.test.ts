import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/sql-injection-template", () => {
  const rule = "ast/sql-injection-template"

  it("flags template literal SQL with req.body interpolation", () => {
    const code = `
      app.get('/u', (req, res) => {
        db.query(\`SELECT * FROM users WHERE id = \${req.body.id}\`)
      })
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags template literal SQL with req.query interpolation", () => {
    const code = `
      pool.execute(\`SELECT name FROM users WHERE id = \${req.query.id}\`)
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags template literal SQL with ctx.request interpolation (Koa-style)", () => {
    const code = `
      client.query(\`UPDATE posts SET body = \${ctx.request.body.body} WHERE id = 1\`)
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags element access on req.body (req['body'])", () => {
    const code = `
      conn.query(\`DELETE FROM t WHERE id = \${req['body'].id}\`)
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags string + concatenation with user input AND SQL keyword", () => {
    const code = `
      db.query("SELECT * FROM users WHERE id = " + req.body.id)
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags knex.raw with user input interpolation", () => {
    const code = `
      knex.raw(\`SELECT * FROM users WHERE id = \${req.params.id}\`)
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  // ─── NO-MATCH cases that exist precisely to reduce false positives ───

  it("does NOT flag template literal without SQL keywords (e.g. log line)", () => {
    const code = `
      logger.log(\`User clicked: \${req.body.action}\`)
    `
    expect(findRule(code, "src/log.ts", rule).length).toBe(0)
  })

  it("does NOT flag SQL template literal with parameterised placeholders (no user input expr)", () => {
    const code = `
      db.query('SELECT * FROM users WHERE id = ?', [req.body.id])
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag template literal interpolating req.session (already authenticated)", () => {
    const code = `
      db.query(\`SELECT * FROM users WHERE id = \${req.session.userId}\`)
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag template literal interpolating a constant", () => {
    const code = `
      const id = 42
      db.query(\`SELECT * FROM users WHERE id = \${id}\`)
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag a regular function called 'query' on a non-SQL string", () => {
    const code = `
      thing.query(\`Find anything matching \${req.body.term}\`)
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag commented-out vulnerable code", () => {
    const code = `
      // db.query(\`SELECT * FROM users WHERE id = \${req.body.id}\`)
      const x = 1
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("emits a CodeFinding with the expected shape (cwe + severity + category)", () => {
    const code = `db.query(\`SELECT * FROM x WHERE id = \${req.body.id}\`)`
    const [hit] = findRule(code, "src/api.ts", rule)
    expect(hit.cwe).toBe("CWE-89")
    expect(hit.severity).toBe("critical")
    expect(hit.category).toBe("sqli")
    expect(hit.lineNumber).toBe(1)
    expect(hit.filePath).toBe("src/api.ts")
  })
})
