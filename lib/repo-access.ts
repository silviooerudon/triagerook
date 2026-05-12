import { buildGitHubHeaders } from "./github-fetch"

// Verifies that the GitHub user behind `userAccessToken` has at least
// push access to a given repo. Used as a gate inside the auto-fix
// endpoints so a logged-in RepoGuard user cannot trigger a PR (under
// the GitHub App identity) on a repo they themselves do not have write
// access to.
//
// GitHub's GET /repos/{owner}/{repo} response includes a `permissions`
// object only when called with a user-scoped token; we treat
// permissions.push or permissions.admin as authorisation to act.

const SAFE_OWNER_REPO = /^[A-Za-z0-9._-]+$/

type FetchImpl = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>

export type AccessCheckOptions = {
  fetchImpl?: FetchImpl
}

type RepoPermissionsResponse = {
  permissions?: {
    push?: boolean
    admin?: boolean
    maintain?: boolean
  }
}

export async function userHasPushAccess(
  userAccessToken: string,
  owner: string,
  repo: string,
  options: AccessCheckOptions = {},
): Promise<boolean> {
  if (!userAccessToken) return false
  if (!SAFE_OWNER_REPO.test(owner)) return false
  if (!SAFE_OWNER_REPO.test(repo)) return false

  const fetchImpl = options.fetchImpl ?? fetch

  let response: Response
  try {
    response = await fetchImpl(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: buildGitHubHeaders(userAccessToken),
      cache: "no-store",
    })
  } catch (err) {
    console.warn("[repo-access] fetch failed:", err instanceof Error ? err.message : String(err))
    return false
  }

  if (!response.ok) return false

  let body: RepoPermissionsResponse
  try {
    body = (await response.json()) as RepoPermissionsResponse
  } catch {
    return false
  }

  return body.permissions?.push === true || body.permissions?.admin === true
}
