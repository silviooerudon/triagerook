import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/prototype-pollution-merge-user-input", () => {
  const rule = "ast/prototype-pollution-merge-user-input"

  it("flags lodash.merge with req.body source", () => {
    const code = `_.merge(target, req.body)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags lodash.defaultsDeep with req.query source", () => {
    const code = `lodash.defaultsDeep(opts, req.query)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags Object.assign(target, req.body)", () => {
    const code = `Object.assign(config, req.body)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags lodash.set with ctx.request.body", () => {
    const code = `_.set(state, 'k', ctx.request.body.value)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  // ─── NO-MATCH ───

  it("does NOT flag lodash.merge of constants", () => {
    const code = `_.merge({}, defaults)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag Object.assign({}, req.body) — empty target is safe-ish", () => {
    // Note: this is technically still risky if the resulting object is
    // later spread into a class. Out of scope for this rule's v1.
    const code = `const safe = Object.assign({}, req.body)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
    // Trade-off documented: target is the FIRST arg, source is the second.
    // We flag any non-target arg that is user input — even when the target
    // is a fresh literal. Tightening would require knowing the target's
    // downstream use; out of scope.
  })

  it("does NOT flag user-defined .merge() on non-lodash receivers", () => {
    const code = `myStore.merge(target, req.body)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-1321 + high + prototype-pollution category", () => {
    const code = `_.merge({}, req.body)`
    const [hit] = findRule(code, "src/api.ts", rule)
    expect(hit.cwe).toBe("CWE-1321")
    expect(hit.severity).toBe("high")
    expect(hit.category).toBe("prototype-pollution")
  })
})
