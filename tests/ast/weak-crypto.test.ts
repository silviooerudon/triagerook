import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/weak-crypto-hash-for-secrets", () => {
  const rule = "ast/weak-crypto-hash-for-secrets"

  it("flags createHash('md5').update(password)", () => {
    const code = `
      const crypto = require('crypto')
      function hashPwd(password) {
        return crypto.createHash('md5').update(password).digest('hex')
      }
    `
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags createHash('sha1').update(token)", () => {
    const code = `
      crypto.createHash('sha1').update(token).digest('hex')
    `
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags createHash('md5') with .update on a .password property access", () => {
    const code = `
      crypto.createHash('md5').update(user.password).digest('hex')
    `
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags createHash('sha-1') (dash form) used for secret", () => {
    const code = `
      crypto.createHash('sha-1').update(req.body.secret)
    `
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  // ─── NO-MATCH ───

  it("does NOT flag createHash('sha256') (modern algo)", () => {
    const code = `crypto.createHash('sha256').update(password).digest('hex')`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(0)
  })

  it("does NOT flag createHash('md5') for cache key (no security-shaped name)", () => {
    const code = `
      const cacheKey = crypto.createHash('md5').update(filePath).digest('hex')
    `
    expect(findRule(code, "src/cache.ts", rule).length).toBe(0)
  })

  it("does NOT flag createHash with a dynamic algorithm variable", () => {
    // The algo arg is an identifier, not a literal — we can't tell what
    // it resolves to without full data-flow tracking. Out of scope for v1.
    const code = `
      const algo = 'md5'
      crypto.createHash(algo).update(password)
    `
    expect(findRule(code, "src/auth.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-327 + high + weak-crypto category", () => {
    const code = `crypto.createHash('md5').update(password)`
    const [hit] = findRule(code, "src/auth.ts", rule)
    expect(hit.cwe).toBe("CWE-327")
    expect(hit.severity).toBe("high")
    expect(hit.category).toBe("weak-crypto")
  })
})
