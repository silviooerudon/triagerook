import { describe, it, expect } from "vitest"
import { encodePathSegments } from "@/lib/github-fetch"
import { parseGitHubRateLimit } from "@/lib/scan"

describe("encodePathSegments", () => {
  it("preserves '/' so slashed branch names still resolve (B1)", () => {
    // A plain encodeURIComponent would yield "release%2Fv2", which GitHub's
    // tree/branch/contents path endpoints do not resolve → 404.
    expect(encodePathSegments("release/v2")).toBe("release/v2")
    expect(encodePathSegments(".github/CODEOWNERS")).toBe(".github/CODEOWNERS")
  })

  it("leaves a simple branch untouched", () => {
    expect(encodePathSegments("main")).toBe("main")
  })

  it("still encodes URL-significant characters within a segment", () => {
    expect(encodePathSegments("feature/a b")).toBe("feature/a%20b")
    expect(encodePathSegments("a?b/c#d")).toBe("a%3Fb/c%23d")
  })
})

describe("parseGitHubRateLimit", () => {
  function res(status: number, headers: Record<string, string> = {}): Response {
    return new Response(null, { status, headers })
  }

  it("returns null for a non-rate-limit status", () => {
    expect(parseGitHubRateLimit(res(200))).toBeNull()
    expect(parseGitHubRateLimit(res(404))).toBeNull()
  })

  it("returns null for a 403 permission error with no rate-limit signature", () => {
    expect(parseGitHubRateLimit(res(403))).toBeNull()
  })

  it("parses the primary limit from x-ratelimit-remaining/reset", () => {
    const reset = Math.floor(Date.now() / 1000) + 42
    const out = parseGitHubRateLimit(
      res(403, { "x-ratelimit-remaining": "0", "x-ratelimit-reset": String(reset) }),
    )
    expect(out).not.toBeNull()
    expect(out!).toBeGreaterThan(0)
    expect(out!).toBeLessThanOrEqual(42)
  })

  it("parses the Retry-After header", () => {
    expect(parseGitHubRateLimit(res(429, { "retry-after": "30" }))).toBe(30)
  })

  it("defaults a bare 429 to a 60s backoff (D1)", () => {
    // GitHub's secondary/abuse limit can arrive as a 429 with neither
    // x-ratelimit-remaining nor Retry-After set; treat it as a rate limit.
    expect(parseGitHubRateLimit(res(429))).toBe(60)
  })
})
