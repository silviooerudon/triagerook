import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/ssrf-http-user-url", () => {
  const rule = "ast/ssrf-http-user-url"

  it("flags bare fetch with req.body.url", () => {
    const code = `
      app.get('/proxy', (req, res) => fetch(req.body.url))
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags axios.get with req.query.url", () => {
    const code = `axios.get(req.query.url).then(r => res.send(r.data))`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags http.get with template URL containing req.body.host", () => {
    const code = `http.get(\`https://\${req.body.host}/api\`, cb)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags fetch wrapping req.body.url in new URL()", () => {
    const code = `fetch(new URL(req.body.url))`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags got with ctx.request.body.endpoint", () => {
    const code = `got(ctx.request.body.endpoint)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  it("flags superagent.post with req.params concat", () => {
    const code = `superagent.post("https://api.x/" + req.params.target)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(1)
  })

  // ─── NO-MATCH cases ───

  it("does NOT flag fetch with a static URL", () => {
    const code = `fetch('https://api.github.com/user')`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag axios.get with a constant", () => {
    const code = `
      const url = process.env.UPSTREAM_URL
      axios.get(url)
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag regex.exec / array.get / map.get false-positive callers", () => {
    const code = `
      regex.exec(req.body.x)
      array.get(req.body.x)
      map.get(req.body.x)
    `
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("does NOT flag fetch with session-derived URL", () => {
    const code = `fetch(\`https://api.x/\${req.session.userId}\`)`
    expect(findRule(code, "src/api.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-918 + critical + ssrf category", () => {
    const code = `fetch(req.body.url)`
    const [hit] = findRule(code, "src/api.ts", rule)
    expect(hit.cwe).toBe("CWE-918")
    expect(hit.severity).toBe("critical")
    expect(hit.category).toBe("ssrf")
  })
})
