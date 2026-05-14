import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/jwt-sign-no-expires-in", () => {
  const rule = "ast/jwt-sign-no-expires-in"

  it("flags jwt.sign(payload, secret) with no options arg", () => {
    const code = `
      const jwt = require('jsonwebtoken')
      const token = jwt.sign({ uid: 1 }, process.env.SECRET)
    `
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags jwt.sign with options object that lacks expiresIn", () => {
    const code = `
      jwt.sign({ uid: 1 }, process.env.SECRET, { algorithm: 'HS256' })
    `
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags jsonwebtoken.sign similarly (namespace import form)", () => {
    const code = `
      jsonwebtoken.sign({ id: 1 }, secret)
    `
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("does NOT flag jwt.sign with { expiresIn: '15m' }", () => {
    const code = `
      jwt.sign({ uid: 1 }, secret, { expiresIn: '15m' })
    `
    expect(findRule(code, "src/auth.ts", rule).length).toBe(0)
  })

  it("does NOT flag jwt.sign with shorthand { expiresIn } property", () => {
    const code = `
      const expiresIn = '15m'
      jwt.sign({ uid: 1 }, secret, { expiresIn })
    `
    expect(findRule(code, "src/auth.ts", rule).length).toBe(0)
  })

  it("does NOT flag jwt.verify (only sign is flagged)", () => {
    const code = `jwt.verify(token, secret)`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(0)
  })

  it("does NOT flag an unrelated method named sign", () => {
    const code = `crypto.sign('sha256', data, key)`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(0)
  })
})

describe("ast/jwt-sign-hardcoded-secret", () => {
  const rule = "ast/jwt-sign-hardcoded-secret"

  it("flags jwt.sign with a string-literal secret", () => {
    const code = `
      jwt.sign({ uid: 1 }, 'super-secret-key', { expiresIn: '1h' })
    `
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags jwt.sign with a no-substitution template-literal secret", () => {
    const code = `jwt.sign({ uid: 1 }, \`literal-secret\`, { expiresIn: '1h' })`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("does NOT flag jwt.sign with process.env secret", () => {
    const code = `jwt.sign({ uid: 1 }, process.env.JWT_SECRET, { expiresIn: '1h' })`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(0)
  })

  it("does NOT flag jwt.sign with an identifier", () => {
    const code = `
      const secret = loadSecretFromVault()
      jwt.sign({ uid: 1 }, secret)
    `
    expect(findRule(code, "src/auth.ts", rule).length).toBe(0)
  })

  it("does NOT flag an empty string (test placeholder)", () => {
    const code = `jwt.sign({}, '')`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-798 + critical + hardcoded-creds category", () => {
    const code = `jwt.sign({}, 'literal-key')`
    const [hit] = findRule(code, "src/auth.ts", rule)
    expect(hit.cwe).toBe("CWE-798")
    expect(hit.severity).toBe("critical")
    expect(hit.category).toBe("hardcoded-creds")
  })
})
