import { describe, it, expect } from "vitest"
import { isSafeGitRef, isSafeOwnerRepo, isSafeRepoFilePath } from "@/lib/path-validation"

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

describe("isSafeOwnerRepo", () => {
  it("accepts typical GitHub owner/repo names", () => {
    expect(isSafeOwnerRepo("silviooerudon")).toBe(true)
    expect(isSafeOwnerRepo("triagerook")).toBe(true)
    expect(isSafeOwnerRepo("next.js")).toBe(true)
    expect(isSafeOwnerRepo("vercel")).toBe(true)
    expect(isSafeOwnerRepo("user-name")).toBe(true)
    expect(isSafeOwnerRepo("name_with_underscore")).toBe(true)
  })

  it("rejects empty and over-long names", () => {
    expect(isSafeOwnerRepo("")).toBe(false)
    expect(isSafeOwnerRepo("a".repeat(101))).toBe(false)
  })

  it("rejects non-string inputs", () => {
    expect(isSafeOwnerRepo(null)).toBe(false)
    expect(isSafeOwnerRepo(undefined)).toBe(false)
    expect(isSafeOwnerRepo(123)).toBe(false)
  })

  it("rejects path-traversal and URL-shaping characters", () => {
    // These are the actual exploit shapes that motivated this guard —
    // any of them concatenated into a GitHub API URL would reshape the path.
    expect(isSafeOwnerRepo("evil/path")).toBe(false)
    expect(isSafeOwnerRepo("..")).toBe(false)
    expect(isSafeOwnerRepo("a..b")).toBe(true) // dots in the middle are fine
    expect(isSafeOwnerRepo("a/b")).toBe(false)
    expect(isSafeOwnerRepo("a?b")).toBe(false)
    expect(isSafeOwnerRepo("a#b")).toBe(false)
    expect(isSafeOwnerRepo("a b")).toBe(false)
    expect(isSafeOwnerRepo("a\nb")).toBe(false)
    expect(isSafeOwnerRepo("a%2fb")).toBe(false)
  })
})

describe("isSafeGitRef", () => {
  it("accepts typical branch names", () => {
    expect(isSafeGitRef("main")).toBe(true)
    expect(isSafeGitRef("master")).toBe(true)
    expect(isSafeGitRef("release/2026.05")).toBe(true)
    expect(isSafeGitRef("feature/scan-private")).toBe(true)
    expect(isSafeGitRef("v1.2.3")).toBe(true)
  })

  it("accepts commit SHAs and short SHAs", () => {
    expect(isSafeGitRef("34e114876b0b11c390a56381ad16ebd13914f8d5")).toBe(true)
    expect(isSafeGitRef("abc1234")).toBe(true)
  })

  it("rejects empty and non-string inputs", () => {
    expect(isSafeGitRef("")).toBe(false)
    expect(isSafeGitRef(null)).toBe(false)
    expect(isSafeGitRef(undefined)).toBe(false)
    expect(isSafeGitRef(123)).toBe(false)
  })

  it("rejects URL-reshaping characters", () => {
    // These are the actual exploit shapes — any would let a malicious
    // caller redirect the GitHub tree fetch.
    expect(isSafeGitRef("main?owner=evil")).toBe(false)
    expect(isSafeGitRef("main#frag")).toBe(false)
    expect(isSafeGitRef("main with space")).toBe(false)
    expect(isSafeGitRef("../../etc/passwd")).toBe(false)
    expect(isSafeGitRef("..")).toBe(false)
    expect(isSafeGitRef("main..evil")).toBe(false)
    expect(isSafeGitRef("main%2fevil")).toBe(false)
  })

  it("rejects leading or trailing slash, leading dash, double slash", () => {
    expect(isSafeGitRef("/main")).toBe(false)
    expect(isSafeGitRef("main/")).toBe(false)
    expect(isSafeGitRef("-main")).toBe(false)
    expect(isSafeGitRef("a//b")).toBe(false)
  })

  it("rejects '@' as a whole component (git HEAD shorthand)", () => {
    expect(isSafeGitRef("@")).toBe(false)
    expect(isSafeGitRef("refs/@")).toBe(false)
  })

  it("rejects refs over 255 chars (sanity ceiling)", () => {
    expect(isSafeGitRef("a".repeat(256))).toBe(false)
  })
})
