import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/nosql-injection-where-user-input", () => {
  const rule = "ast/nosql-injection-where-user-input"

  it("flags db.users.find({ $where: req.body.query })", () => {
    const code = `db.users.find({ $where: req.body.query })`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags db.users.find({ '$where': req.query.q })", () => {
    const code = `db.users.find({ '$where': req.query.q })`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags collection.findOne with $where containing user template literal", () => {
    const code = `posts.findOne({ $where: \`this.title === \${req.body.title}\` })`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags Model.updateOne({ $where: req.body.filter }, ...)", () => {
    const code = `User.updateOne({ $where: req.body.filter }, { active: true })`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  // ─── NO-MATCH ───

  it("does NOT flag find with constant $where", () => {
    const code = `db.users.find({ $where: 'this.active === true' })`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag find with $eq / $regex (declarative operators)", () => {
    const code = `db.users.find({ name: { $eq: req.body.name } })`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag find with session-derived $where", () => {
    const code = `db.users.find({ $where: req.session.scopeQuery })`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag a non-query method", () => {
    const code = `db.users.bulkWrite([{ insertOne: { $where: req.body.x } }])`
    // bulkWrite isn't in the QUERY_METHOD_LAST_SEGMENT regex. Conservative.
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-943 + critical + sqli category", () => {
    const code = `db.users.find({ $where: req.body.q })`
    const [hit] = findRule(code, "src/api.ts", rule)
    expect(hit.cwe).toBe("CWE-943")
    expect(hit.severity).toBe("critical")
    expect(hit.category).toBe("sqli")
  })
})
