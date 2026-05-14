import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/weak-cipher-mode-or-deprecated-api", () => {
  const rule = "ast/weak-cipher-mode-or-deprecated-api"

  it("flags crypto.createCipher (deprecated, zeroed IV)", () => {
    const code = `const c = crypto.createCipher('aes-256-cbc', password)`
    expect(findRule(code, "src/crypto.ts", rule).length).toBe(1)
  })

  it("flags crypto.createDecipher (deprecated)", () => {
    const code = `const d = crypto.createDecipher('aes-256-cbc', password)`
    expect(findRule(code, "src/crypto.ts", rule).length).toBe(1)
  })

  it("flags createCipheriv with ECB mode", () => {
    const code = `const c = crypto.createCipheriv('aes-256-ecb', key, iv)`
    expect(findRule(code, "src/crypto.ts", rule).length).toBe(1)
  })

  it("flags createCipheriv with aes-128-ecb", () => {
    const code = `crypto.createCipheriv('aes-128-ecb', key, iv)`
    expect(findRule(code, "src/crypto.ts", rule).length).toBe(1)
  })

  it("does NOT flag createCipheriv with GCM mode", () => {
    const code = `crypto.createCipheriv('aes-256-gcm', key, iv)`
    expect(findRule(code, "src/crypto.ts", rule).length).toBe(0)
  })

  it("does NOT flag createCipheriv with CBC mode", () => {
    const code = `crypto.createCipheriv('aes-256-cbc', key, iv)`
    expect(findRule(code, "src/crypto.ts", rule).length).toBe(0)
  })

  it("does NOT flag createCipheriv with a dynamic algorithm", () => {
    const code = `const algo = process.env.CIPHER_ALGO; crypto.createCipheriv(algo, key, iv)`
    expect(findRule(code, "src/crypto.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-327 + high + weak-crypto category", () => {
    const code = `crypto.createCipher('aes-256-cbc', pw)`
    const [hit] = findRule(code, "src/crypto.ts", rule)
    expect(hit.cwe).toBe("CWE-327")
    expect(hit.severity).toBe("high")
    expect(hit.category).toBe("weak-crypto")
  })
})
