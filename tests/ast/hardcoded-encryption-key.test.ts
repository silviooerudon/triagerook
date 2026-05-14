import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/hardcoded-encryption-key", () => {
  const rule = "ast/hardcoded-encryption-key"

  it("flags createCipheriv with string-literal key", () => {
    const code = `crypto.createCipheriv('aes-256-cbc', 'my-secret-32-byte-key-literal-x', iv)`
    expect(findRule(code, "src/crypto.ts", rule).length).toBe(1)
  })

  it("flags createDecipheriv with string-literal key", () => {
    const code = `crypto.createDecipheriv('aes-256-cbc', 'my-secret-key-literal', iv)`
    expect(findRule(code, "src/crypto.ts", rule).length).toBe(1)
  })

  it("flags createCipheriv with no-substitution template-literal key", () => {
    const code = `crypto.createCipheriv('aes-256-cbc', \`literal-key-x\`, iv)`
    expect(findRule(code, "src/crypto.ts", rule).length).toBe(1)
  })

  it("does NOT flag createCipheriv with Buffer.from key", () => {
    const code = `crypto.createCipheriv('aes-256-cbc', Buffer.from(keyHex, 'hex'), iv)`
    expect(findRule(code, "src/crypto.ts", rule).length).toBe(0)
  })

  it("does NOT flag createCipheriv with process.env key", () => {
    const code = `crypto.createCipheriv('aes-256-cbc', process.env.ENCRYPTION_KEY, iv)`
    expect(findRule(code, "src/crypto.ts", rule).length).toBe(0)
  })

  it("does NOT flag createCipheriv with very short literal (< 8 chars)", () => {
    const code = `crypto.createCipheriv('aes-256-cbc', 'short', iv)`
    expect(findRule(code, "src/crypto.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-798 + critical + hardcoded-creds category", () => {
    const code = `crypto.createCipheriv('aes-256-cbc', 'literal-key-here', iv)`
    const [hit] = findRule(code, "src/crypto.ts", rule)
    expect(hit.cwe).toBe("CWE-798")
    expect(hit.severity).toBe("critical")
    expect(hit.category).toBe("hardcoded-creds")
  })
})
