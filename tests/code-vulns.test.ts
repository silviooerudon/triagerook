import { describe, it, expect } from "vitest"
import { findCodeVulns } from "@/lib/code-vulns"

function findCategories(content: string, path: string): string[] {
  return findCodeVulns(content, path, false).map((f) => f.category)
}

describe("findCodeVulns", () => {
  it("returns empty for files with no detectable language", () => {
    expect(findCodeVulns("anything", "README.md", false)).toEqual([])
  })

  it("flags SSRF: fetch with req.body in JS", () => {
    const code = `app.get('/proxy', (req, res) => { fetch(req.body.url) })`
    expect(findCategories(code, "src/server.ts")).toContain("ssrf")
  })

  it("flags SQL injection via string concatenation in JS", () => {
    const code = `db.query("SELECT * FROM users WHERE id = " + userId)`
    expect(findCategories(code, "src/db.ts")).toContain("sqli")
  })

  it("flags command injection: exec with req.body in JS", () => {
    const code = `const { exec } = require('child_process'); exec(req.body.cmd)`
    const cats = findCategories(code, "src/runner.js")
    expect(cats).toContain("command-injection")
  })

  it("flags eval / new Function in JS", () => {
    expect(findCategories(`eval(userInput)`, "src/app.js")).toContain("eval")
    expect(findCategories(`new Function('return ' + userInput)`, "src/app.js")).toContain("eval")
  })

  it("flags innerHTML XSS", () => {
    const code = `element.innerHTML = userInput`
    expect(findCategories(code, "src/dom.js")).toContain("xss")
  })

  it("flags Python pickle.loads insecure deserialization", () => {
    const code = `data = pickle.loads(payload)`
    expect(findCategories(code, "src/api.py")).toContain("deserialization")
  })

  it("flags Python f-string SQL injection", () => {
    const code = `cursor.execute(f"SELECT * FROM users WHERE id={user_id}")`
    expect(findCategories(code, "src/db.py")).toContain("sqli")
  })

  it("skips trivially-commented lines", () => {
    const commented = `// eval(userInput)\n# eval(userInput)\n* eval(userInput)`
    expect(findCodeVulns(commented, "src/app.js", false)).toEqual([])
  })

  it("clean code has no findings", () => {
    const code = `function add(a, b) { return a + b }\nconst x = 1\nconsole.log(x)`
    expect(findCodeVulns(code, "src/util.ts", false)).toEqual([])
  })

  it("each finding carries cwe + filePath + lineNumber", () => {
    const code = `\n\ndb.query("SELECT * FROM users WHERE id = " + userId)`
    const findings = findCodeVulns(code, "src/db.ts", false)
    expect(findings.length).toBeGreaterThan(0)
    expect(findings[0].cwe).toMatch(/^CWE-/)
    expect(findings[0].filePath).toBe("src/db.ts")
    expect(findings[0].lineNumber).toBeGreaterThan(0)
  })
})

describe("findCodeVulns — AI-typical insecure patterns", () => {
  it("flags JS TLS verification disabled (rejectUnauthorized: false)", () => {
    const code = `const agent = new https.Agent({ rejectUnauthorized: false })`
    expect(findCategories(code, "src/http.ts")).toContain("tls-verification")
  })

  it("flags Python requests with verify=False", () => {
    const code = `r = requests.get(url, verify=False)`
    expect(findCategories(code, "src/client.py")).toContain("tls-verification")
  })

  it("flags httpx with verify=False", () => {
    const code = `r = httpx.post(url, json=data, verify=False)`
    expect(findCategories(code, "src/client.py")).toContain("tls-verification")
  })

  it("flags Cookie httpOnly: false", () => {
    const code = `res.cookie('session', token, { httpOnly: false, maxAge: 3600 })`
    expect(findCategories(code, "src/auth.ts")).toContain("insecure-cookie")
  })

  it("flags session() middleware with secure: false", () => {
    const code = `app.use(session({ secret: s, cookie: { secure: false, maxAge: 60000 } }))`
    expect(findCategories(code, "src/server.ts")).toContain("insecure-cookie")
  })

  it("flags bcrypt cost factor below 10", () => {
    const code = `const hash = await bcrypt.hash(password, 8)`
    expect(findCategories(code, "src/auth.ts")).toContain("weak-crypto")
  })

  it("does NOT flag bcrypt with cost factor >= 10", () => {
    const code = `const hash = await bcrypt.hash(password, 12)`
    const findings = findCodeVulns(code, "src/auth.ts", false)
    expect(findings.find((f) => f.ruleId === "js-bcrypt-low-rounds")).toBeUndefined()
  })

  it("flags process.env fallback to a hardcoded secret-shaped string", () => {
    const sk = "sk" + "-abcdefghijklmnopqrstuvwxyz123456"
    const code = `const apiKey = process.env.OPENAI_API_KEY || "${sk}"`
    expect(findCategories(code, "src/openai.ts")).toContain("hardcoded-creds")
  })

  it("flags process.env nullish fallback (??) to a secret-shaped string", () => {
    const ghp = "ghp" + "_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
    const code = `const token = process.env.GITHUB_TOKEN ?? "${ghp}"`
    expect(findCategories(code, "src/gh.ts")).toContain("hardcoded-creds")
  })

  it("does NOT flag env fallback to a clearly placeholder string", () => {
    const code = `const apiKey = process.env.OPENAI_API_KEY || "your-key-here"`
    const findings = findCodeVulns(code, "src/openai.ts", false)
    expect(findings.find((f) => f.ruleId === "js-env-fallback-secret")).toBeUndefined()
  })

  it("flags NEXT_PUBLIC_*SECRET* env access", () => {
    const code = `const k = process.env.NEXT_PUBLIC_API_SECRET`
    expect(findCategories(code, "app/page.tsx")).toContain("hardcoded-creds")
  })

  it("flags NEXT_PUBLIC_SUPABASE_SERVICE_ROLE access", () => {
    const code = `createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY)`
    expect(findCategories(code, "lib/db.ts")).toContain("hardcoded-creds")
  })

  it("does NOT flag NEXT_PUBLIC_SUPABASE_URL (no secret-like suffix)", () => {
    const code = `const url = process.env.NEXT_PUBLIC_SUPABASE_URL`
    const findings = findCodeVulns(code, "lib/db.ts", false)
    expect(findings.find((f) => f.ruleId === "js-next-public-secret-name")).toBeUndefined()
  })

  it("redacts the literal credential in lineContent for hardcoded-creds findings", () => {
    // Regression: a tool that detects hardcoded secrets must not persist
    // the literal credential it found to the database. The js-env-fallback
    // -secret rule matches `process.env.X || "real-token"` — the quoted
    // literal must be redacted before it ends up in `lineContent`.
    const sk = "sk" + "-abcdefghijklmnopqrstuvwxyz123456"
    const code = `const apiKey = process.env.OPENAI_API_KEY || "${sk}"`
    const findings = findCodeVulns(code, "src/openai.ts", false)
    const match = findings.find((f) => f.ruleId === "js-env-fallback-secret")
    expect(match).toBeDefined()
    expect(match!.lineContent).not.toContain(sk)
    expect(match!.lineContent).toContain("***REDACTED***")
  })

  it("does NOT redact short string literals in non-credential findings", () => {
    // Sanity: only hardcoded-creds rules should redact. Other rules
    // surface the line as-is so users can recognise the pattern.
    const code = `bcrypt.hash(pw, 4)`
    const findings = findCodeVulns(code, "src/auth.ts", false)
    const match = findings.find((f) => f.ruleId === "js-bcrypt-low-rounds")
    expect(match).toBeDefined()
    expect(match!.lineContent).toContain("bcrypt.hash(pw, 4)")
  })
})
