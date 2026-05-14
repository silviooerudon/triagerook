import { createAppAuth } from "@octokit/auth-app"
import { buildGitHubHeaders } from "./github-fetch"

const GH_API = "https://api.github.com"

export type GitHubAppCredentials = {
  appId: string
  privateKey: string
  // Optional: when present, the per-repo installation lookup is skipped
  // and this id is used directly. Today only used in tests; production
  // discovers the installation per-(owner,repo) so a user who installs
  // the App on their own org gets fixes wired up correctly.
  installationId?: string
}

function readEnvCredentials(): GitHubAppCredentials {
  const appId = process.env.AUTH_GITHUB_APP_ID
  const privateKey = process.env.AUTH_GITHUB_APP_PRIVATE_KEY

  if (!appId || !privateKey) {
    throw new Error(
      "GitHub App credentials missing. Required env vars: AUTH_GITHUB_APP_ID, AUTH_GITHUB_APP_PRIVATE_KEY"
    )
  }

  // installationId is read but no longer required. Kept on the object as
  // a legacy fallback for any caller that still wants single-tenant.
  const installationId = process.env.AUTH_GITHUB_APP_INSTALLATION_ID

  return { appId, privateKey, installationId }
}

// Pluggable factory so tests can swap createAppAuth without spinning up
// real JWT signing. Returns the two operations we actually need: an
// app-level JWT (used to look up where the App is installed) and an
// installation-scoped token (used for all per-repo write operations).
export type AppAuthHelpers = {
  appJwt(): Promise<string>
  installationToken(installationId: string): Promise<string>
}

export type AppAuthFactory = (creds: GitHubAppCredentials) => AppAuthHelpers

const defaultAppAuthFactory: AppAuthFactory = (creds) => {
  const auth = createAppAuth({
    appId: creds.appId,
    privateKey: creds.privateKey,
  })
  return {
    async appJwt() {
      const result = await auth({ type: "app" })
      return result.token
    },
    async installationToken(installationId: string) {
      const result = await auth({ type: "installation", installationId })
      return result.token
    },
  }
}

// Per-(owner,repo) installation token cache. GitHub mints these with a
// 1-hour TTL; we cache 50 min to leave headroom for clock skew + the
// round-trip cost of a re-mint on the next request.
type CachedToken = { token: string; expiresAt: number }
const TOKEN_CACHE_TTL_MS = 50 * 60 * 1000
const tokenCache = new Map<string, CachedToken>()

function cacheKey(owner: string, repo: string): string {
  return `${owner.toLowerCase()}/${repo.toLowerCase()}`
}

// Test helper — never call from production. Lets vitest reset the cache
// between cases so token reuse doesn't leak across `it()` blocks.
export function _clearInstallationTokenCacheForTests(): void {
  tokenCache.clear()
}

export type LookupOptions = {
  credentials?: GitHubAppCredentials
  fetchImpl?: typeof fetch
  authFactory?: AppAuthFactory
}

// Resolves the installation id GitHub assigned when the App was installed
// on the target owner. Returns null when the App is not installed there
// (404). Other failures (rate limit, 5xx, network) surface as
// GitHubAppFetchError so the caller can decide between retry and bail.
//
// Uses the App-level JWT (not an installation token) — the App is allowed
// to probe its own installations across the GitHub user base.
export async function lookupInstallationId(
  owner: string,
  repo: string,
  options: LookupOptions = {}
): Promise<number | null> {
  const credentials = options.credentials ?? readEnvCredentials()
  const fetchImpl = options.fetchImpl ?? fetch
  const factory = options.authFactory ?? defaultAppAuthFactory

  const helpers = factory(credentials)
  const appJwt = await helpers.appJwt()

  const path = `/repos/${owner}/${repo}/installation`
  const response = await fetchImpl(`${GH_API}${path}`, {
    headers: buildGitHubHeaders(appJwt),
    cache: "no-store",
  })

  if (response.status === 404) return null
  if (!response.ok) {
    const text = await response.text().catch(() => "")
    throw new GitHubAppFetchError(
      response.status,
      response.statusText,
      path,
      text
    )
  }
  const data = (await response.json()) as { id: number }
  return data.id
}

// Public API used by the auto-fix routes. Discovers (or pulls from cache)
// the installation for (owner, repo) and returns a fresh installation
// token. Throws GitHubAppFetchError with appNotInstalled() === true if the
// App is not installed on the target — the route handler maps that to the
// "install on this repo" UI.
export async function getInstallationTokenForRepo(
  owner: string,
  repo: string,
  options: LookupOptions = {}
): Promise<string> {
  const cached = tokenCache.get(cacheKey(owner, repo))
  if (cached && cached.expiresAt > Date.now()) return cached.token

  const credentials = options.credentials ?? readEnvCredentials()

  // Always discover the installation per-(owner,repo). The previous
  // single-tenant fallback that used AUTH_GITHUB_APP_INSTALLATION_ID was
  // the C2 bug — it caused auto-fix to mint the deployer's token for
  // EVERY user, silently breaking the feature for anyone who installed
  // the App on their own org.
  const installationId = await lookupInstallationId(owner, repo, {
    credentials,
    fetchImpl: options.fetchImpl,
    authFactory: options.authFactory,
  })
  if (installationId === null) {
    throw new GitHubAppFetchError(
      404,
      "Not Found",
      `/repos/${owner}/${repo}/installation`,
      `RepoGuard Security GitHub App is not installed on ${owner}/${repo}.`
    )
  }

  const factory = options.authFactory ?? defaultAppAuthFactory
  const helpers = factory(credentials)
  const token = await helpers.installationToken(String(installationId))

  tokenCache.set(cacheKey(owner, repo), {
    token,
    expiresAt: Date.now() + TOKEN_CACHE_TTL_MS,
  })
  return token
}

type FetchOptions = {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
  body?: unknown
}

// Thrown by ghFetch on any non-2xx response. Callers (specifically
// prepareFixContext) want to distinguish "App not installed in this repo"
// (404 / 403 + 'Not Accessible by Integration' body) from generic failures
// to give the UI a chance to offer the install link.
export class GitHubAppFetchError extends Error {
  readonly status: number
  readonly path: string
  readonly responseBody: string

  constructor(status: number, statusText: string, path: string, body: string) {
    super(`GitHub API ${path} failed: ${status} ${statusText} ${body}`)
    this.name = "GitHubAppFetchError"
    this.status = status
    this.path = path
    this.responseBody = body
  }

  // True for the failure modes that look like "App is missing on the repo":
  // 404 typically (repo not visible to the installation), 403 with the
  // "Not Accessible by Integration" body for installations that have the
  // App but on a different repo set.
  appNotInstalled(): boolean {
    if (this.status === 404) return true
    if (this.status === 403 && /not\s+accessible\s+by\s+integration/i.test(this.responseBody))
      return true
    return false
  }
}

export async function ghFetch<T>(
  token: string,
  path: string,
  options: FetchOptions = {}
): Promise<T> {
  const url = path.startsWith("http") ? path : `${GH_API}${path}`
  const response = await fetch(url, {
    method: options.method ?? "GET",
    headers: {
      ...buildGitHubHeaders(token),
      ...(options.body ? { "Content-Type": "application/json" } : {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
    cache: "no-store",
  })

  if (!response.ok) {
    const text = await response.text().catch(() => "")
    throw new GitHubAppFetchError(response.status, response.statusText, path, text)
  }

  return (await response.json()) as T
}

export type FilePatch = {
  path: string
  content: string
}

export type CreatePullRequestParams = {
  owner: string
  repo: string
  baseBranch: string
  newBranch: string
  commitMessage: string
  prTitle: string
  prBody: string
  patches: FilePatch[]
}

type RepoInfo = { default_branch: string }
type RefObject = { object: { sha: string } }
type CreatedPr = { html_url: string; number: number }
type FileBlob = { sha: string; content?: string }

export async function createPullRequestFromPatches(
  token: string,
  params: CreatePullRequestParams
): Promise<{ url: string; number: number }> {
  const { owner, repo, baseBranch, newBranch, commitMessage, prTitle, prBody, patches } = params

  const baseRef = await ghFetch<RefObject>(
    token,
    `/repos/${owner}/${repo}/git/refs/heads/${baseBranch}`
  )
  const baseSha = baseRef.object.sha

  await ghFetch(token, `/repos/${owner}/${repo}/git/refs`, {
    method: "POST",
    body: { ref: `refs/heads/${newBranch}`, sha: baseSha },
  })

  for (const patch of patches) {
    let existingSha: string | undefined
    try {
      const existing = await ghFetch<FileBlob>(
        token,
        `/repos/${owner}/${repo}/contents/${encodeURIComponent(patch.path)}?ref=${newBranch}`
      )
      existingSha = existing.sha
    } catch {
      existingSha = undefined
    }

    await ghFetch(token, `/repos/${owner}/${repo}/contents/${encodeURIComponent(patch.path)}`, {
      method: "PUT",
      body: {
        message: commitMessage,
        content: Buffer.from(patch.content, "utf8").toString("base64"),
        branch: newBranch,
        ...(existingSha ? { sha: existingSha } : {}),
      },
    })
  }

  const pr = await ghFetch<CreatedPr>(token, `/repos/${owner}/${repo}/pulls`, {
    method: "POST",
    body: {
      title: prTitle,
      body: prBody,
      head: newBranch,
      base: baseBranch,
    },
  })

  return { url: pr.html_url, number: pr.number }
}

export async function getRepoDefaultBranch(
  token: string,
  owner: string,
  repo: string
): Promise<string> {
  const info = await ghFetch<RepoInfo>(token, `/repos/${owner}/${repo}`)
  return info.default_branch
}

export async function getFileContent(
  token: string,
  owner: string,
  repo: string,
  path: string,
  ref?: string
): Promise<string> {
  const refQs = ref ? `?ref=${encodeURIComponent(ref)}` : ""
  const blob = await ghFetch<FileBlob>(
    token,
    `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}${refQs}`
  )
  if (!blob.content) {
    throw new Error(`File ${path} has no content (likely a symlink or directory)`)
  }
  return Buffer.from(blob.content, "base64").toString("utf8")
}

// Deprecated alias kept for backwards compatibility with the previous
// single-tenant API. New callers should use getInstallationTokenForRepo.
// Will be removed once we ship Sentry + know nothing still hits this.
export async function getInstallationToken(
  credentials: GitHubAppCredentials = readEnvCredentials()
): Promise<string> {
  if (!credentials.installationId) {
    throw new Error(
      "getInstallationToken() requires installationId in credentials. " +
        "Use getInstallationTokenForRepo(owner, repo) instead for per-repo discovery."
    )
  }
  const helpers = defaultAppAuthFactory(credentials)
  return helpers.installationToken(credentials.installationId)
}
