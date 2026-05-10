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
