// GitHub owner/repo path segment validator. Owner and repo segments are
// concatenated into 15+ GitHub API URLs across the scan pipeline (tree,
// contents, ref, pulls, issues), so anything that escapes the [A-Za-z0-9._-]
// class can reshape the URL path and address unintended endpoints. Mirror
// the constraint GitHub itself enforces on these names.
const SAFE_OWNER_REPO_REGEX = /^[A-Za-z0-9._-]+$/

export function isSafeOwnerRepo(value: unknown): value is string {
  if (typeof value !== "string") return false
  if (value.length === 0 || value.length > 100) return false
  // Reject all-dots ("." / ".." / "...") — passes the character class but
  // shapes the URL path as a directory traversal segment.
  if (/^\.+$/.test(value)) return false
  return SAFE_OWNER_REPO_REGEX.test(value)
}

// Validates that a string is safe to forward to GitHub's Contents API
// as a repo file path. Used by the auto-fix endpoints, which take the
// full finding object from the request body — without this guard, a
// caller could craft a finding with filePath=".env" or filePath="../"
// to exfiltrate arbitrary files from any repo where the GitHub App is
// installed.
//
// Rules (deliberately conservative):
//   - non-empty string, ≤ 1024 chars
//   - no leading slash (must be a repo-relative path)
//   - no '..' segments (no parent traversal)
//   - no URL schemes
//   - no null bytes
//   - no backslashes (POSIX separators only — GitHub does not use \)
//   - no surrounding whitespace
//   - not literally '.' or './'
export function isSafeRepoFilePath(value: unknown): value is string {
  if (typeof value !== "string") return false
  if (value.length === 0 || value.length > 1024) return false
  if (value !== value.trim()) return false
  if (value.startsWith("/")) return false
  if (value.includes("\\")) return false
  if (value.includes("\0")) return false
  if (value.includes("://")) return false
  if (value === "." || value === "./") return false

  const segments = value.split("/")
  for (const seg of segments) {
    if (seg === "..") return false
  }
  return true
}

// Validates that a string is safe to concatenate into a GitHub git tree
// API URL as a ref (branch, tag, or commit SHA). The scan pipeline
// drops the ref straight into `/repos/{owner}/{repo}/git/trees/{ref}`,
// so any character that GitHub treats as a path separator or query
// terminator can reshape the URL.
//
// Mirrors the subset of `git check-ref-format` that GitHub actually
// accepts on its tree endpoint, plus a length cap:
//   - non-empty string, ≤ 255 chars
//   - allowed chars: [A-Za-z0-9._/-]
//   - no leading/trailing slash, no '..', no '//'
//   - no leading '-'
//   - no path component that equals '@' (git reserves '@' as HEAD)
//
// Note: callers should still URL-encode the ref before concatenation.
// This is a structural check, not a substitute for escaping.
export function isSafeGitRef(value: unknown): value is string {
  if (typeof value !== "string") return false
  if (value.length === 0 || value.length > 255) return false
  if (!/^[A-Za-z0-9._/-]+$/.test(value)) return false
  if (value.startsWith("/") || value.endsWith("/")) return false
  if (value.startsWith("-")) return false
  if (value.includes("//")) return false
  if (value.includes("..")) return false
  if (value === "@" || value.split("/").some((seg) => seg === "@")) return false
  return true
}
