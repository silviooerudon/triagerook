import { describe, it, expect, beforeEach } from "vitest"
import {
  GitHubAppFetchError,
  _clearInstallationTokenCacheForTests,
  getInstallationTokenForRepo,
  lookupInstallationId,
  type AppAuthFactory,
  type GitHubAppCredentials,
} from "@/lib/octokit-app"

const CREDS: GitHubAppCredentials = {
  appId: "12345",
  privateKey: "fake-key-for-tests",
}

function fakeAuthFactory(opts: {
  appJwt?: string
  installationToken?: string
  onInstallationToken?: (installationId: string) => void
} = {}): AppAuthFactory {
  return () => ({
    async appJwt() {
      return opts.appJwt ?? "fake-app-jwt"
    },
    async installationToken(installationId) {
      opts.onInstallationToken?.(installationId)
      return opts.installationToken ?? `fake-install-token-${installationId}`
    },
  })
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  })
}

beforeEach(() => {
  _clearInstallationTokenCacheForTests()
})

describe("lookupInstallationId", () => {
  it("returns the installation id when the App is installed on the repo", async () => {
    const fetchImpl: typeof fetch = async (url) => {
      expect(String(url)).toBe(
        "https://api.github.com/repos/silviooerudon/rg-fix-test/installation",
      )
      return jsonResponse({ id: 131387775 })
    }
    const id = await lookupInstallationId("silviooerudon", "rg-fix-test", {
      credentials: CREDS,
      fetchImpl,
      authFactory: fakeAuthFactory(),
    })
    expect(id).toBe(131387775)
  })

  it("returns null when GitHub responds 404 (App not installed)", async () => {
    const fetchImpl: typeof fetch = async () => jsonResponse({ message: "Not Found" }, 404)
    const id = await lookupInstallationId("acme", "private-repo", {
      credentials: CREDS,
      fetchImpl,
      authFactory: fakeAuthFactory(),
    })
    expect(id).toBeNull()
  })

  it("throws GitHubAppFetchError on rate-limit/5xx so callers can decide retry policy", async () => {
    const fetchImpl: typeof fetch = async () =>
      new Response("rate limited", {
        status: 403,
        headers: { "x-ratelimit-remaining": "0" },
      })
    await expect(
      lookupInstallationId("acme", "anything", {
        credentials: CREDS,
        fetchImpl,
        authFactory: fakeAuthFactory(),
      }),
    ).rejects.toBeInstanceOf(GitHubAppFetchError)
  })

  it("authenticates the lookup with the App-level JWT, not an installation token", async () => {
    let observedAuthHeader: string | null = null
    const fetchImpl: typeof fetch = async (_, init) => {
      const headers = new Headers(init?.headers as HeadersInit)
      observedAuthHeader = headers.get("authorization")
      return jsonResponse({ id: 42 })
    }
    await lookupInstallationId("acme", "anything", {
      credentials: CREDS,
      fetchImpl,
      authFactory: fakeAuthFactory({ appJwt: "the-app-jwt" }),
    })
    // GitHub App JWTs go in as `Bearer <jwt>` — never `token <jwt>`.
    expect(observedAuthHeader).toBe("Bearer the-app-jwt")
  })
})

describe("getInstallationTokenForRepo", () => {
  it("discovers the installation per repo and mints a scoped token", async () => {
    const installationsMinted: string[] = []
    const fetchImpl: typeof fetch = async () => jsonResponse({ id: 999 })
    const token = await getInstallationTokenForRepo("acme", "widgets", {
      credentials: CREDS,
      fetchImpl,
      authFactory: fakeAuthFactory({
        onInstallationToken: (id) => installationsMinted.push(id),
      }),
    })
    expect(installationsMinted).toEqual(["999"])
    expect(token).toBe("fake-install-token-999")
  })

  it("throws appNotInstalled() error when the App is missing on the repo", async () => {
    const fetchImpl: typeof fetch = async () => jsonResponse({ message: "Not Found" }, 404)
    const promise = getInstallationTokenForRepo("acme", "no-app-here", {
      credentials: CREDS,
      fetchImpl,
      authFactory: fakeAuthFactory(),
    })
    await expect(promise).rejects.toBeInstanceOf(GitHubAppFetchError)
    try {
      await promise
    } catch (err) {
      expect((err as GitHubAppFetchError).appNotInstalled()).toBe(true)
    }
  })

  it("caches the token per-(owner,repo) — repeated calls do not re-discover", async () => {
    let fetchCalls = 0
    const fetchImpl: typeof fetch = async () => {
      fetchCalls++
      return jsonResponse({ id: 111 })
    }
    let mintCalls = 0
    const factory = fakeAuthFactory({
      onInstallationToken: () => {
        mintCalls++
      },
    })
    const opts = { credentials: CREDS, fetchImpl, authFactory: factory }

    await getInstallationTokenForRepo("acme", "widgets", opts)
    await getInstallationTokenForRepo("acme", "widgets", opts)
    await getInstallationTokenForRepo("acme", "widgets", opts)

    expect(fetchCalls).toBe(1)
    expect(mintCalls).toBe(1)
  })

  it("uses a separate cache slot per (owner,repo) — does not bleed cross-tenant", async () => {
    const idByRepo: Record<string, number> = {
      "acme/widgets": 111,
      "globex/spanner": 222,
    }
    const fetchImpl: typeof fetch = async (url) => {
      const m = String(url).match(/repos\/([^/]+)\/([^/]+)\/installation/)
      if (!m) throw new Error(`unexpected ${url}`)
      const key = `${m[1]}/${m[2]}`
      return jsonResponse({ id: idByRepo[key] })
    }
    const minted: string[] = []
    const factory = fakeAuthFactory({
      onInstallationToken: (id) => minted.push(id),
    })

    await getInstallationTokenForRepo("acme", "widgets", {
      credentials: CREDS,
      fetchImpl,
      authFactory: factory,
    })
    await getInstallationTokenForRepo("globex", "spanner", {
      credentials: CREDS,
      fetchImpl,
      authFactory: factory,
    })

    // Each (owner, repo) gets the GitHub-assigned installation id for
    // THAT tenant, not a shared one. This is the C2 regression test.
    expect(minted).toEqual(["111", "222"])
  })

  it("normalises owner/repo case so cache hits match regardless of input casing", async () => {
    let fetchCalls = 0
    const fetchImpl: typeof fetch = async () => {
      fetchCalls++
      return jsonResponse({ id: 777 })
    }
    const opts = {
      credentials: CREDS,
      fetchImpl,
      authFactory: fakeAuthFactory(),
    }
    await getInstallationTokenForRepo("Acme", "Widgets", opts)
    await getInstallationTokenForRepo("acme", "widgets", opts)
    expect(fetchCalls).toBe(1)
  })
})
