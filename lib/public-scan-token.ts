// Server-side fallback GitHub token used by /api/scan-public when no
// user is signed in.
//
// Without this, anonymous public scans inherit GitHub's unauthenticated
// quota: 60 requests/hour shared across ALL anonymous visitors of the
// deployment. A single concurrent HN spike exhausts that in seconds and
// every subsequent anonymous scan returns the GitHubRateLimitError
// surface. Setting PUBLIC_SCAN_GITHUB_TOKEN to a personal access token
// (or fine-grained token) with `public_repo` read scope raises the
// effective ceiling to 5000 requests/hour for the whole deployment,
// which survives Show HN.
//
// Safety properties:
//   - The token must have `public_repo` (or fine-grained "public
//     repositories: read-only") scope ONLY. Private-repo read would
//     widen the blast radius if the token leaks; the README and AGENTS
//     guide require public-only.
//   - If unset, behaviour is unchanged from the previous anonymous flow
//     so we degrade rather than break.
//   - We never thread this token into the authenticated route — that
//     path uses the signed-in user's OAuth token, which is bound to
//     their identity for posture/IAM queries that need
//     repo-collaborator info.
export function getPublicScanFallbackToken(): string | null {
  const token = process.env.PUBLIC_SCAN_GITHUB_TOKEN
  if (!token || token.length === 0) return null
  return token
}
