import { describe, it, expect } from "vitest"
import { isSafeRepoFilePath } from "@/lib/path-validation"

// Path-narrow validation is the boundary check for ?path=<x>. The
// helper itself is covered in detail in tests/path-validation.test.ts;
// these tests verify the patterns we expect users to actually type and
// the malicious shapes the API has to reject.
describe("isSafeRepoFilePath — path-narrow scenarios", () => {
  it("accepts a typical monorepo subfolder", () => {
    expect(isSafeRepoFilePath("packages/auth")).toBe(true)
    expect(isSafeRepoFilePath("apps/web")).toBe(true)
    expect(isSafeRepoFilePath("services/billing/src")).toBe(true)
  })

  it("accepts a deeply-nested path", () => {
    expect(isSafeRepoFilePath("a/b/c/d/e/f")).toBe(true)
  })

  it("rejects a leading slash (must be repo-relative)", () => {
    expect(isSafeRepoFilePath("/etc/passwd")).toBe(false)
    expect(isSafeRepoFilePath("/packages/auth")).toBe(false)
  })

  it("rejects parent-traversal segments", () => {
    expect(isSafeRepoFilePath("..")).toBe(false)
    expect(isSafeRepoFilePath("../etc/passwd")).toBe(false)
    expect(isSafeRepoFilePath("packages/../etc/passwd")).toBe(false)
    expect(isSafeRepoFilePath("packages/auth/../../../etc")).toBe(false)
  })

  it("rejects URL schemes (no http://, git://, file://, etc.)", () => {
    expect(isSafeRepoFilePath("https://evil.example.com/x")).toBe(false)
    expect(isSafeRepoFilePath("file:///etc/passwd")).toBe(false)
  })

  it("rejects null bytes", () => {
    expect(isSafeRepoFilePath("packages/auth\0")).toBe(false)
  })

  it("rejects backslashes (POSIX separators only)", () => {
    expect(isSafeRepoFilePath("packages\\auth")).toBe(false)
  })

  it("rejects empty and whitespace-padded", () => {
    expect(isSafeRepoFilePath("")).toBe(false)
    expect(isSafeRepoFilePath(" packages/auth")).toBe(false)
    expect(isSafeRepoFilePath("packages/auth ")).toBe(false)
  })

  it("rejects '.' and './'", () => {
    expect(isSafeRepoFilePath(".")).toBe(false)
    expect(isSafeRepoFilePath("./")).toBe(false)
  })

  it("rejects non-string input (defensive)", () => {
    expect(isSafeRepoFilePath(null)).toBe(false)
    expect(isSafeRepoFilePath(undefined)).toBe(false)
    expect(isSafeRepoFilePath(123)).toBe(false)
    expect(isSafeRepoFilePath({})).toBe(false)
  })
})
