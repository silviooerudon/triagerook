import { describe, it, expect } from "vitest"
import { findEntropySecrets } from "@/lib/entropy"

describe("findEntropySecrets", () => {
  it("ignores files with unscannable extensions", () => {
    const content = "API_KEY=ZmFrZWtleXdpdGhsb3RzMjUwNzMwNzg5OTI4NzY1"
    const findings = findEntropySecrets(content, "src/app.ts", false)
    expect(findings).toEqual([])
  })

  it("flags a high-entropy value behind a secret-like key in .env", () => {
    const content = `API_KEY=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbA==`
    const findings = findEntropySecrets(content, ".env", false)
    expect(findings).toHaveLength(1)
    expect(findings[0].patternId).toBe("entropy-high-secret")
    expect(findings[0].filePath).toBe(".env")
  })

  it("ignores placeholders even with secret-looking keys", () => {
    const content = [
      "API_KEY=your-api-key-here",
      "SECRET=changeme",
      "PASSWORD=xxxxxxxxxxxxxxxxxxxx",
    ].join("\n")
    const findings = findEntropySecrets(content, ".env", false)
    expect(findings).toEqual([])
  })

  it("ignores low-entropy values (repeated characters)", () => {
    const content = "API_KEY=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    const findings = findEntropySecrets(content, ".env", false)
    expect(findings).toEqual([])
  })

  it("ignores values that are not secret-keys (e.g. PORT, NODE_ENV)", () => {
    const content = [
      "PORT=3000",
      "NODE_ENV=production",
      "DEBUG=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbA==",
    ].join("\n")
    const findings = findEntropySecrets(content, ".env", false)
    expect(findings).toEqual([])
  })

  it("masks the value in lineContent", () => {
    const value = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbA=="
    const content = `API_KEY=${value}`
    const findings = findEntropySecrets(content, ".env", false)
    expect(findings[0].lineContent).not.toContain(value)
    expect(findings[0].lineContent).toContain("•")
  })

  it("propagates likelyTestFixture flag", () => {
    const content = `API_KEY=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbA==`
    const findings = findEntropySecrets(content, ".env", true)
    expect(findings[0].likelyTestFixture).toBe(true)
  })

  it("never leaks the literal secret in lineContent even when the line exceeds the display cap", () => {
    // Regression for mask-after-truncate bug: a >200-char line with the
    // secret near the end would be truncated *before* masking, leaving the
    // truncated tail of the literal value in lineContent.
    const value = "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbA=="
    const padding = "x".repeat(220)
    const content = `API_KEY=${value}  # ${padding}`
    const findings = findEntropySecrets(content, ".env", false)
    expect(findings).toHaveLength(1)
    expect(findings[0].lineContent).not.toContain(value)
    expect(findings[0].lineContent).not.toContain(value.slice(0, 20))
  })
})
