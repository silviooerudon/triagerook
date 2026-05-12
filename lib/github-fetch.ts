// Centralised GitHub API HTTP helpers. Before this file existed, every
// detector (and the github.ts / octokit-app.ts wrappers) had its own
// near-identical `buildHeaders` / `buildGithubHeaders` / `buildGitHubHeaders`
// implementation. That ran a real risk: a change to the Accept header or
// the X-GitHub-Api-Version pin had to be applied in 6+ places and was
// silently inconsistent at any given moment.
//
// One pinned API version, one Accept default, one optional override for
// rulesets-and-similar endpoints that need a different media type.

export const GITHUB_API_BASE = "https://api.github.com"
export const GITHUB_API_VERSION = "2022-11-28"
export const DEFAULT_GITHUB_ACCEPT = "application/vnd.github+json"

// The single source of truth for GitHub API request headers. `token` is
// the user (or installation) access token; null means "fire unauthenticated"
// and yields the lower 60-req/hr quota. `accept` overrides the default
// media type for endpoints that need a different one (e.g. ".raw" for
// blob contents, or the rulesets API).
export function buildGitHubHeaders(
  token: string | null,
  accept: string = DEFAULT_GITHUB_ACCEPT,
): Record<string, string> {
  const headers: Record<string, string> = {
    Accept: accept,
    "X-GitHub-Api-Version": GITHUB_API_VERSION,
  }
  if (token) {
    headers.Authorization = `Bearer ${token}`
  }
  return headers
}

// Optional convenience wrapper for the simple `fetch GitHub API URL with
// no-store cache` shape. Caller still owns error handling because some
// detectors translate 404/403/429 differently (rate limit specifically
// needs Retry-After parsing). Kept narrow on purpose.
export type GitHubFetchOptions = {
  token?: string | null
  accept?: string
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
  body?: unknown
  signal?: AbortSignal
}

export async function githubFetch(
  url: string,
  options: GitHubFetchOptions = {},
): Promise<Response> {
  const headers = buildGitHubHeaders(options.token ?? null, options.accept)
  const init: RequestInit = {
    method: options.method ?? "GET",
    headers: options.body
      ? { ...headers, "Content-Type": "application/json" }
      : headers,
    cache: "no-store",
    signal: options.signal,
  }
  if (options.body !== undefined) {
    init.body = JSON.stringify(options.body)
  }
  return fetch(url, init)
}
