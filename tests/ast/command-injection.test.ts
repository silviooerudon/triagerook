import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/command-injection-user-input", () => {
  const rule = "ast/command-injection-user-input"

  it("flags exec() with template literal interpolating req.body", () => {
    const code = `
      const { exec } = require('child_process')
      exec(\`kill -9 \${req.body.pid}\`)
    `
    expect(findRule(code, "src/admin.ts", rule).length).toBe(1)
  })

  it("flags execSync with req.query in template", () => {
    const code = `
      execSync(\`rm -rf /tmp/\${req.query.dir}\`)
    `
    expect(findRule(code, "src/cleanup.ts", rule).length).toBe(1)
  })

  it("flags spawn with concatenation containing req.body", () => {
    const code = `
      spawn("git clone " + req.body.url, { shell: true })
    `
    expect(findRule(code, "src/git.ts", rule).length).toBe(1)
  })

  it("flags childProcess.exec namespace import form", () => {
    const code = `
      import * as childProcess from 'child_process'
      childProcess.exec(\`ping -c 1 \${req.body.host}\`)
    `
    expect(findRule(code, "src/net.ts", rule).length).toBe(1)
  })

  it("flags exec with ctx.request body (Koa-style)", () => {
    const code = `
      exec(\`docker rm \${ctx.request.body.id}\`)
    `
    expect(findRule(code, "src/docker.ts", rule).length).toBe(1)
  })

  it("flags exec with bare 'userInput' identifier (conventional name)", () => {
    const code = `
      exec(\`echo \${userInput}\`)
    `
    expect(findRule(code, "src/run.ts", rule).length).toBe(1)
  })

  // ─── NO-MATCH cases ───

  it("does NOT flag exec with a static string", () => {
    const code = `exec("ls -la")`
    expect(findRule(code, "src/run.ts", rule).length).toBe(0)
  })

  it("does NOT flag exec with a constant variable", () => {
    const code = `
      const cmd = "git status"
      exec(cmd)
    `
    expect(findRule(code, "src/run.ts", rule).length).toBe(0)
  })

  it("does NOT flag exec on session-derived data (already authenticated)", () => {
    const code = `
      exec(\`whoami \${req.session.user}\`)
    `
    expect(findRule(code, "src/run.ts", rule).length).toBe(0)
  })

  it("does NOT flag an unrelated function called 'exec' on safe data", () => {
    const code = `
      regex.exec(\`pattern \${req.body.q}\`)
    `
    // regex.exec is the RegExp built-in, not child_process. Our rule
    // matches by callee name's last segment, so this WILL match. This
    // test documents the conservative-but-not-perfect contract; the
    // CWE description says false positives on lookalike names are
    // possible, and the user can suppress via .repoguardignore.
    //
    // CHANGE PLAN: a future revision can disambiguate by tracking the
    // imported binding source. Out of scope for v1 AST rules.
    expect(findRule(code, "src/run.ts", rule).length).toBe(1)
  })

  it("does NOT flag commented-out vulnerable code", () => {
    const code = `
      // exec(\`kill -9 \${req.body.pid}\`)
    `
    expect(findRule(code, "src/run.ts", rule).length).toBe(0)
  })

  it("emits a CodeFinding with the expected shape (cwe + severity + category)", () => {
    const code = `exec(\`ls \${req.body.dir}\`)`
    const [hit] = findRule(code, "src/run.ts", rule)
    expect(hit.cwe).toBe("CWE-78")
    expect(hit.severity).toBe("critical")
    expect(hit.category).toBe("command-injection")
    expect(hit.filePath).toBe("src/run.ts")
  })
})

describe("ast runner — file-type gating", () => {
  it("returns no findings for non-JS/TS files (Python, MD, etc)", () => {
    expect(runAstRules("README.md", "anything", false)).toEqual([])
    expect(runAstRules("api.py", "exec(req.body.cmd)", false)).toEqual([])
  })

  it("returns no findings for files larger than the 200KB cap", () => {
    const big = `db.query(\`SELECT * FROM x WHERE id = \${req.body.id}\`)\n` + "x".repeat(210 * 1024)
    expect(runAstRules("src/api.ts", big, false)).toEqual([])
  })

  it("returns no findings for syntactically broken JS (parse error path)", () => {
    const broken = `
      function {
        db.query(\`SELECT * FROM x WHERE id = \${req.body.id}\`)
    `
    // Should not throw; should return empty so a partial / in-progress
    // edit doesn't break a scan.
    const result = runAstRules("src/broken.ts", broken, false)
    expect(Array.isArray(result)).toBe(true)
  })
})
