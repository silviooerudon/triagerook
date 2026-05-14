import { describe, it, expect } from "vitest"
import {
  isInsideRegexLiteral,
  isLikelyDetectorDefinition,
  isLikelyScannerSelfReference,
} from "@/lib/scanner-self-reference"

// Helper: takes a line + the text we expect to find inside it and
// returns the offset, so tests stay readable when the offset is
// irrelevant to the assertion.
function offsetOf(line: string, needle: string): number {
  const idx = line.indexOf(needle)
  if (idx < 0) throw new Error(`needle not found: ${needle}`)
  return idx
}

describe("isInsideRegexLiteral", () => {
  it("detects a match between two unescaped slashes on the same line", () => {
    const line = `    regex: /BEGIN PRIVATE KEY-----/g,`
    expect(isInsideRegexLiteral(line, offsetOf(line, "BEGIN"))).toBe(true)
  })

  it("does not flag a match with no surrounding slashes", () => {
    const line = `const secret = "-----BEGIN PRIVATE KEY-----"`
    expect(isInsideRegexLiteral(line, offsetOf(line, "BEGIN"))).toBe(false)
  })

  it("does not flag when only one slash is present (start of a // comment)", () => {
    const line = `// example: -----BEGIN PRIVATE KEY-----`
    expect(isInsideRegexLiteral(line, offsetOf(line, "BEGIN"))).toBe(false)
  })

  it("does not flag the start of a /* block comment", () => {
    const line = `/* example: BEGIN PRIVATE KEY here */`
    expect(isInsideRegexLiteral(line, offsetOf(line, "BEGIN"))).toBe(false)
  })

  it("treats escaped slashes as not delimiters", () => {
    const line = `const path = "foo\\/bar -----BEGIN PRIVATE KEY-----"`
    expect(isInsideRegexLiteral(line, offsetOf(line, "BEGIN"))).toBe(false)
  })

  it("flags a real regex literal from lib/secret-patterns.ts", () => {
    const line = `    regex: /"type":\\s*"service_account"[\\s\\S]{0,500}?"private_key":\\s*"-----BEGIN PRIVATE KEY-----/g,`
    expect(isInsideRegexLiteral(line, offsetOf(line, "BEGIN"))).toBe(true)
  })
})

describe("isLikelyDetectorDefinition", () => {
  it("flags a `regex:` property assignment", () => {
    const line = `    regex: /BEGIN PRIVATE KEY-----/g,`
    expect(isLikelyDetectorDefinition(line, offsetOf(line, "BEGIN"))).toBe(true)
  })

  it("flags a `pattern:` property assignment", () => {
    const line = `    pattern: "rejectUnauthorized: false",`
    expect(isLikelyDetectorDefinition(line, offsetOf(line, "rejectUnauthorized"))).toBe(true)
  })

  it("flags `Pattern:` case-insensitively", () => {
    const line = `    Pattern: "AKIA[0-9A-Z]{16}",`
    expect(isLikelyDetectorDefinition(line, offsetOf(line, "AKIA"))).toBe(true)
  })

  it("does not flag a regular variable assignment", () => {
    const line = `const apiKey = "AKIA0123456789012345"`
    expect(isLikelyDetectorDefinition(line, offsetOf(line, "AKIA"))).toBe(false)
  })

  it("does not flag when the marker appears AFTER the match", () => {
    const line = `"AKIA0123456789012345" // pattern: example`
    expect(isLikelyDetectorDefinition(line, offsetOf(line, "AKIA"))).toBe(false)
  })
})

describe("isLikelyScannerSelfReference (combined)", () => {
  it("treats real exploit-shaped code as not self-reference", () => {
    // Concrete real-world false positive we must NOT skip
    const line = `https.request(url, { rejectUnauthorized: false })`
    expect(isLikelyScannerSelfReference(line, offsetOf(line, "rejectUnauthorized"))).toBe(false)
  })

  it("skips the secret-patterns.ts gcp-service-account regex literal", () => {
    // Matches the actual line 58 of lib/secret-patterns.ts that caused
    // the original critical false-positive
    const line = `    regex: /"type":\\s*"service_account"[\\s\\S]{0,500}?"private_key":\\s*"-----BEGIN PRIVATE KEY-----/g,`
    expect(isLikelyScannerSelfReference(line, offsetOf(line, "BEGIN"))).toBe(true)
  })

  it("skips a quoted pattern string in a rule definition", () => {
    const line = `  { id: "tls-off", pattern: "rejectUnauthorized: false" },`
    expect(isLikelyScannerSelfReference(line, offsetOf(line, "rejectUnauthorized"))).toBe(true)
  })

  it("does not skip a finding in a regular code path", () => {
    const line = `const agent = new Agent({ rejectUnauthorized: false });`
    expect(isLikelyScannerSelfReference(line, offsetOf(line, "rejectUnauthorized"))).toBe(false)
  })
})
