import { describe, it, expect } from "vitest"
import { runAstRules } from "@/lib/ast"

function findRule(content: string, path: string, ruleId: string) {
  return runAstRules(path, content, false).filter((f) => f.ruleId === ruleId)
}

describe("ast/xxe-xml-parser-external-entities", () => {
  const rule = "ast/xxe-xml-parser-external-entities"

  it("flags new XMLParser({ allowDtd: true })", () => {
    const code = `
      import { XMLParser } from "fast-xml-parser"
      const parser = new XMLParser({ allowDtd: true })
    `
    expect(findRule(code, "src/xml.ts", rule).length).toBe(1)
  })

  it("flags libxmljs.parseXml(buf, { noent: true })", () => {
    const code = `
      import libxmljs from "libxmljs"
      const doc = libxmljs.parseXml(buf, { noent: true })
    `
    expect(findRule(code, "src/xml.ts", rule).length).toBe(1)
  })

  it("flags libxmljs.parseXmlString(buf, { dtdload: true })", () => {
    const code = `
      libxmljs.parseXmlString(input, { dtdload: true })
    `
    expect(findRule(code, "src/xml.ts", rule).length).toBe(1)
  })

  it("flags xml2js.parseString(buf, { external: true })", () => {
    const code = `xml2js.parseString(buf, { external: true })`
    expect(findRule(code, "src/xml.ts", rule).length).toBe(1)
  })

  it("does NOT flag XMLParser with no danger options", () => {
    const code = `new XMLParser({ ignoreAttributes: false })`
    expect(findRule(code, "src/xml.ts", rule).length).toBe(0)
  })

  it("does NOT flag XMLParser with no options at all (safe default)", () => {
    const code = `new XMLParser()`
    expect(findRule(code, "src/xml.ts", rule).length).toBe(0)
  })

  it("does NOT flag when allowDtd: false explicitly", () => {
    const code = `new XMLParser({ allowDtd: false })`
    expect(findRule(code, "src/xml.ts", rule).length).toBe(0)
  })

  it("does NOT flag when the value is a variable (not a literal true)", () => {
    // Conservative — we don't trace value origins. Avoid false positives.
    const code = `new XMLParser({ allowDtd: enableDtdInTest })`
    expect(findRule(code, "src/xml.ts", rule).length).toBe(0)
  })

  it("emits CodeFinding with CWE-611 + high + xxe category", () => {
    const code = `new XMLParser({ allowDtd: true })`
    const [hit] = findRule(code, "src/xml.ts", rule)
    expect(hit.cwe).toBe("CWE-611")
    expect(hit.severity).toBe("high")
    expect(hit.category).toBe("xxe")
  })
})
