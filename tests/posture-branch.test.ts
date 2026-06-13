import { describe, it, expect, afterEach, vi } from "vitest"
import { assessPosture } from "@/lib/posture"

// assessPosture used to check branch protection / rulesets on a hardcoded
// "main". These tests stub global fetch, record every URL, and assert the
// branch-scoped endpoints target the repo's real default branch instead.

afterEach(() => {
  vi.unstubAllGlobals()
})

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  })
}

// Stub fetch: the bare repo object returns `repoObj`; everything else 404s
// (no files, no protection, no rulesets) so the scan soft-fails to a result.
function stubFetch(repoObj: unknown): { urls: string[] } {
  const urls: string[] = []
  const mock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input)
    urls.push(url)
    if (url === "https://api.github.com/repos/o/r") return json(repoObj)
    return new Response("not found", { status: 404 })
  })
  vi.stubGlobal("fetch", mock)
  return { urls }
}

describe("assessPosture branch targeting", () => {
  it("targets the repo's default branch, never a hardcoded main", async () => {
    const { urls } = stubFetch({ default_branch: "develop", owner: { type: "User" } })

    await assessPosture("o", "r", null)

    expect(urls).toContain("https://api.github.com/repos/o/r/branches/develop")
    expect(urls).toContain("https://api.github.com/repos/o/r/rules/branches/develop")
    expect(urls.some((u) => u.includes("/branches/main"))).toBe(false)
  })

  it("falls back to main when the repo object can't be read", async () => {
    // Every request 404s, including the repo object → default_branch is
    // unknown → branch resolution falls back to "main".
    const urls: string[] = []
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        urls.push(String(input))
        return new Response("not found", { status: 404 })
      }),
    )

    await assessPosture("o", "r", null)

    expect(urls.some((u) => u.includes("/branches/main"))).toBe(true)
  })

  it("an explicit branch wins and is path-segment encoded (slash preserved)", async () => {
    const { urls } = stubFetch({ default_branch: "develop", owner: { type: "User" } })

    await assessPosture("o", "r", null, "release/v2")

    // encodePathSegments keeps the slash raw so GitHub resolves the ref.
    expect(urls).toContain("https://api.github.com/repos/o/r/branches/release/v2")
    expect(urls.some((u) => u.includes("/branches/develop"))).toBe(false)
  })
})
