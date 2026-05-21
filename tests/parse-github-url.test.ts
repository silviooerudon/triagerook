import { describe, it, expect } from "vitest"
import { parseGitHubUrl } from "@/lib/parse-github-url"

describe("parseGitHubUrl", () => {
  it("parses canonical https URLs", () => {
    expect(parseGitHubUrl("https://github.com/silviooerudon/triagerook")).toEqual({
      owner: "silviooerudon",
      repo: "triagerook",
    })
  })

  it("strips .git suffix", () => {
    expect(parseGitHubUrl("https://github.com/foo/bar.git")).toEqual({
      owner: "foo",
      repo: "bar",
    })
  })

  it("accepts URLs without protocol", () => {
    expect(parseGitHubUrl("github.com/foo/bar")).toEqual({
      owner: "foo",
      repo: "bar",
    })
  })

  it("accepts deep paths and ignores the rest", () => {
    expect(parseGitHubUrl("https://github.com/foo/bar/tree/main/lib")).toEqual({
      owner: "foo",
      repo: "bar",
    })
  })

  it("rejects non-github hosts", () => {
    expect(parseGitHubUrl("https://gitlab.com/foo/bar")).toBeNull()
    expect(parseGitHubUrl("https://example.com/foo/bar")).toBeNull()
  })

  it("rejects malformed inputs", () => {
    expect(parseGitHubUrl("")).toBeNull()
    expect(parseGitHubUrl("   ")).toBeNull()
    expect(parseGitHubUrl("not a url")).toBeNull()
    expect(parseGitHubUrl("https://github.com/foo")).toBeNull()
    expect(parseGitHubUrl("https://github.com/")).toBeNull()
  })

  it("rejects owner/repo names with disallowed characters", () => {
    expect(parseGitHubUrl("https://github.com/foo bar/baz")).toBeNull()
    expect(parseGitHubUrl("https://github.com/foo!/baz")).toBeNull()
  })

  it("is case-insensitive on the hostname", () => {
    expect(parseGitHubUrl("https://GitHub.com/foo/bar")).toEqual({
      owner: "foo",
      repo: "bar",
    })
  })
})
