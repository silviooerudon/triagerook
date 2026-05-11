import { describe, it, expect } from "vitest"
import { isSafeRepoFilePath } from "@/lib/path-validation"

describe("isSafeRepoFilePath", () => {
  it("accepts a normal nested path", () => {
    expect(isSafeRepoFilePath("lib/stripe.ts")).toBe(true)
  })

  it("accepts a top-level file", () => {
    expect(isSafeRepoFilePath("package.json")).toBe(true)
  })

  it("accepts paths with dots in the filename", () => {
    expect(isSafeRepoFilePath("scripts/deploy.sh")).toBe(true)
    expect(isSafeRepoFilePath("src/index.spec.ts")).toBe(true)
  })

  it("accepts dotfiles in subdirectories", () => {
    expect(isSafeRepoFilePath(".github/workflows/ci.yml")).toBe(true)
    expect(isSafeRepoFilePath("frontend/.env.example")).toBe(true)
  })

  it("rejects empty string", () => {
    expect(isSafeRepoFilePath("")).toBe(false)
  })

  it("rejects null and undefined", () => {
    // @ts-expect-error testing runtime guards
    expect(isSafeRepoFilePath(null)).toBe(false)
    // @ts-expect-error testing runtime guards
    expect(isSafeRepoFilePath(undefined)).toBe(false)
  })

  it("rejects absolute paths starting with /", () => {
    expect(isSafeRepoFilePath("/etc/passwd")).toBe(false)
    expect(isSafeRepoFilePath("/")).toBe(false)
  })

  it("rejects parent-directory traversal", () => {
    expect(isSafeRepoFilePath("../etc/passwd")).toBe(false)
    expect(isSafeRepoFilePath("lib/../../../etc/passwd")).toBe(false)
    expect(isSafeRepoFilePath("..")).toBe(false)
    expect(isSafeRepoFilePath("./..")).toBe(false)
  })

  it("rejects URLs", () => {
    expect(isSafeRepoFilePath("https://example.com/file")).toBe(false)
    expect(isSafeRepoFilePath("http://example.com")).toBe(false)
    expect(isSafeRepoFilePath("file://etc/passwd")).toBe(false)
  })

  it("rejects null bytes", () => {
    expect(isSafeRepoFilePath("lib/stripe.ts\0evil")).toBe(false)
  })

  it("rejects backslashes (Windows-style separators)", () => {
    expect(isSafeRepoFilePath("lib\\stripe.ts")).toBe(false)
  })

  it("rejects paths with leading or trailing whitespace", () => {
    expect(isSafeRepoFilePath(" lib/stripe.ts")).toBe(false)
    expect(isSafeRepoFilePath("lib/stripe.ts ")).toBe(false)
    expect(isSafeRepoFilePath("\tlib/stripe.ts")).toBe(false)
  })

  it("rejects paths longer than 1024 chars (sanity ceiling)", () => {
    expect(isSafeRepoFilePath("a/" + "b".repeat(1024))).toBe(false)
  })

  it("rejects paths that are only dots", () => {
    expect(isSafeRepoFilePath(".")).toBe(false)
    expect(isSafeRepoFilePath("./")).toBe(false)
  })
})
