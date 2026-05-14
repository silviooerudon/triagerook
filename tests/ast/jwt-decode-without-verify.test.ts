import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/jwt-decode-without-verify", () => {
  const rule = "ast/jwt-decode-without-verify"

  it("flags jwt.decode(token)", () => {
    const code = `
      const payload = jwt.decode(token)
      req.user = payload.sub
    `
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags jsonwebtoken.decode(token)", () => {
    const code = `
      import jsonwebtoken from "jsonwebtoken"
      const payload = jsonwebtoken.decode(token)
    `
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("flags JWT.decode(token) (the namespace import convention)", () => {
    const code = `const claims = JWT.decode(rawToken)`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(1)
  })

  it("does NOT flag jwt.verify(token, secret)", () => {
    const code = `const payload = jwt.verify(token, process.env.SECRET)`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(0)
  })

  it("does NOT flag an unrelated .decode call on a different object", () => {
    const code = `const v = base64.decode(token)`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(0)
  })

  it("does NOT flag bare jwtDecode() from the browser-only `jwt-decode` library", () => {
    // jwt-decode exposes a default function with no namespace; we
    // deliberately don't flag that because the library only decodes
    // and can't verify (the browser doesn't have the secret).
    const code = `const payload = jwtDecode(token)`
    expect(findRule(code, "src/auth.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-347 + high + jwt category", () => {
    const code = `jwt.decode(t)`
    const [hit] = findRule(code, "src/auth.ts", rule)
    expect(hit.cwe).toBe("CWE-347")
    expect(hit.severity).toBe("high")
    expect(hit.category).toBe("jwt")
  })
})
