import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import {
  assertPublicRepo,
  GitHubRateLimitError,
  GitHubRepoNotFoundError,
  PrivateRepoRefusedError,
} from "@/lib/scan"

const realFetch = globalThis.fetch

function mockFetch(
  body: unknown,
  init: { status?: number; headers?: Record<string, string> } = {},
) {
  return vi.fn().mockResolvedValue(
    new Response(JSON.stringify(body), {
      status: init.status ?? 200,
      headers: init.headers,
    }),
  )
}

describe("assertPublicRepo", () => {
  beforeEach(() => {
    // Each test installs its own fetch mock; restore after.
  })

  afterEach(() => {
    globalThis.fetch = realFetch
  })

  it("returns the default branch when the repo exists and is public", async () => {
    globalThis.fetch = mockFetch({
      default_branch: "main",
      private: false,
    })
    const { defaultBranch } = await assertPublicRepo(null, "silviooerudon", "repoguard")
    expect(defaultBranch).toBe("main")
  })

  it("throws PrivateRepoRefusedError when the repo is marked private", async () => {
    // This is the security promise on /security: we never scan private
    // repos, even when the user's OAuth token grants access. A user
    // could land here only by hitting the URL directly with a private
    // repo they own — which is exactly the case the guard exists to
    // catch.
    globalThis.fetch = mockFetch({
      default_branch: "main",
      private: true,
    })
    await expect(
      assertPublicRepo("user-token", "silviooerudon", "secret-stash"),
    ).rejects.toBeInstanceOf(PrivateRepoRefusedError)
  })

  it("throws GitHubRepoNotFoundError on 404", async () => {
    globalThis.fetch = mockFetch({}, { status: 404 })
    await expect(
      assertPublicRepo(null, "ghost", "missing"),
    ).rejects.toBeInstanceOf(GitHubRepoNotFoundError)
  })

  it("throws GitHubRateLimitError when GitHub returns 403 with rate-limit headers", async () => {
    const reset = Math.floor(Date.now() / 1000) + 60
    globalThis.fetch = mockFetch(
      {},
      {
        status: 403,
        headers: {
          "x-ratelimit-remaining": "0",
          "x-ratelimit-reset": String(reset),
        },
      },
    )
    await expect(
      assertPublicRepo(null, "x", "y"),
    ).rejects.toBeInstanceOf(GitHubRateLimitError)
  })
})
