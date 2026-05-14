import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/react-dangerously-set-inner-html-user-input", () => {
  const rule = "ast/react-dangerously-set-inner-html-user-input"

  it("flags dangerouslySetInnerHTML with req.body.html", () => {
    const code = `
      function Page({ req }) {
        return <div dangerouslySetInnerHTML={{ __html: req.body.html }} />
      }
    `
    expect(findRule(code, "src/Page.tsx", rule).length).toBe(1)
  })

  it("flags dangerouslySetInnerHTML with req.query interpolated in template", () => {
    const code = `
      function Page({ req }) {
        return <div dangerouslySetInnerHTML={{ __html: \`<h1>\${req.query.title}</h1>\` }} />
      }
    `
    expect(findRule(code, "src/Page.tsx", rule).length).toBe(1)
  })

  it("flags dangerouslySetInnerHTML with ctx.request.body (Koa-style server component)", () => {
    const code = `
      export default function Page({ ctx }) {
        return <div dangerouslySetInnerHTML={{ __html: ctx.request.body.body }} />
      }
    `
    expect(findRule(code, "src/Page.tsx", rule).length).toBe(1)
  })

  it("flags dangerouslySetInnerHTML with bare 'userInput' identifier", () => {
    const code = `
      export default function Page() {
        const userInput = window.location.hash
        return <div dangerouslySetInnerHTML={{ __html: userInput }} />
      }
    `
    expect(findRule(code, "src/Page.tsx", rule).length).toBe(1)
  })

  // ─── NO-MATCH cases ───

  it("does NOT flag dangerouslySetInnerHTML with a constant", () => {
    const code = `
      const html = '<h1>Welcome</h1>'
      export default function Page() {
        return <div dangerouslySetInnerHTML={{ __html: html }} />
      }
    `
    expect(findRule(code, "src/Page.tsx", rule).length).toBe(0)
  })

  it("does NOT flag dangerouslySetInnerHTML with session/user-derived data", () => {
    const code = `
      export default function Page({ req }) {
        return <div dangerouslySetInnerHTML={{ __html: req.session.bio }} />
      }
    `
    expect(findRule(code, "src/Page.tsx", rule).length).toBe(0)
  })

  it("does NOT flag non-dangerouslySetInnerHTML attributes with user input", () => {
    const code = `
      export default function Page({ req }) {
        return <input value={req.body.q} />
      }
    `
    expect(findRule(code, "src/Page.tsx", rule).length).toBe(0)
  })

  it("does NOT flag dangerouslySetInnerHTML when value is post-sanitised", () => {
    // We can only detect direct user input on __html. A user passing the
    // value through DOMPurify produces a CallExpression in that slot,
    // which is out of scope (no taint tracing into call returns).
    const code = `
      export default function Page({ req }) {
        return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(req.body.html) }} />
      }
    `
    expect(findRule(code, "src/Page.tsx", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-79 + critical + xss category", () => {
    const code = `
      export default function P({ req }) {
        return <div dangerouslySetInnerHTML={{ __html: req.body.html }} />
      }
    `
    const [hit] = findRule(code, "src/Page.tsx", rule)
    expect(hit.cwe).toBe("CWE-79")
    expect(hit.severity).toBe("critical")
    expect(hit.category).toBe("xss")
  })
})
