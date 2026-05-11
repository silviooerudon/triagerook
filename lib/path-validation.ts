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
