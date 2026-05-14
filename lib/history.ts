import { SECRET_PATTERNS } from "./secret-patterns"
import { GitHubRateLimitError, parseGitHubRateLimit } from "./scan"
import type { SecretFinding } from "./types"
import { buildGitHubHeaders } from "./github-fetch"
import { isLikelyScannerSelfReference } from "./scanner-self-reference"

type CommitListItem = {
  sha: string
  commit: {
    author: { name: string; email: string; date: string } | null
    committer: { name: string; email: string; date: string } | null
    message: string
  }
}

type CommitDetail = {
  sha: string
  commit: {
    author: { name: string; email: string; date: string } | null
    committer: { name: string; email: string; date: string } | null
    message: string
  }
  files?: Array<{
    filename: string
    status: string
    patch?: string
  }>
}

const HISTORY_COMMIT_LIMIT = 30
const HISTORY_PARALLEL = 5
const MAX_PATCH_SIZE = 200_000 // 200KB per patch — bail on huge diffs
const HISTORY_BUDGET_MS = 20_000


async function listCommits(
  token: string | null,
  owner: string,
  repo: string,
  branch: string,
): Promise<CommitListItem[]> {
  const url = `https://api.github.com/repos/${owner}/${repo}/commits?sha=${encodeURIComponent(
    branch,
  )}&per_page=${HISTORY_COMMIT_LIMIT}`
  const res = await fetch(url, { headers: buildGitHubHeaders(token), cache: "no-store" })
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    return []
  }
  return res.json()
}

async function fetchCommit(
  token: string | null,
  owner: string,
  repo: string,
  sha: string,
): Promise<CommitDetail | null> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/commits/${sha}`,
    { headers: buildGitHubHeaders(token), cache: "no-store" },
  )
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    return null
  }
  return res.json()
}

function extractAddedLines(patch: string): Array<{ text: string; hunkLine: number }> {
  const out: Array<{ text: string; hunkLine: number }> = []
  const lines = patch.split("\n")
  let currentLine = 0
  for (const line of lines) {
    const hunkHeader = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/)
    if (hunkHeader) {
      currentLine = Number.parseInt(hunkHeader[1], 10)
      continue
    }
    if (line.startsWith("+++") || line.startsWith("---")) continue
    if (line.startsWith("+")) {
      out.push({ text: line.slice(1), hunkLine: currentLine })
      currentLine++
    } else if (line.startsWith("-")) {
      // deletion — don't bump the new-file line counter
    } else {
      currentLine++
    }
  }
  return out
}

function maskLine(line: string, matchedText: string): string {
  const masked =
    matchedText.length <= 8
      ? "•".repeat(matchedText.length)
      : matchedText.slice(0, 4) + "•".repeat(matchedText.length - 8) + matchedText.slice(-4)
  const replaced = line.replace(matchedText, masked)
  return replaced.length > 200 ? replaced.slice(0, 197) + "..." : replaced.trim()
}

function scanAddedLinesForSecrets(
  addedLines: Array<{ text: string; hunkLine: number }>,
  filePath: string,
  commit: CommitListItem | CommitDetail,
): SecretFinding[] {
  const findings: SecretFinding[] = []
  const commitDate = commit.commit.author?.date ?? commit.commit.committer?.date ?? ""
  const commitAuthor = commit.commit.author?.name ?? commit.commit.committer?.name ?? "unknown"

  for (const { text, hunkLine } of addedLines) {
    for (const pattern of SECRET_PATTERNS) {
      pattern.regex.lastIndex = 0
      let match: RegExpExecArray | null
      while ((match = pattern.regex.exec(text)) !== null) {
        // Skip matches that are the detector's own regex literal in
        // an added line — e.g. a commit adding a new SECRET_PATTERNS
        // entry. The patch line IS the search pattern, not exploit
        // material. See lib/scanner-self-reference.ts.
        if (isLikelyScannerSelfReference(text, match.index)) {
          if (match.index === pattern.regex.lastIndex) pattern.regex.lastIndex++
          continue
        }
        findings.push({
          patternId: pattern.id,
          patternName: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          filePath,
          lineNumber: hunkLine,
          lineContent: maskLine(text, match[0]),
          likelyTestFixture: false,
          source: "history",
          commitSha: commit.sha,
          commitDate,
          commitAuthor,
        })
        if (match.index === pattern.regex.lastIndex) pattern.regex.lastIndex++
      }
    }
  }

  return findings
}

function dedupeAgainstTree(
  history: SecretFinding[],
  tree: SecretFinding[],
): SecretFinding[] {
  // A finding that also appears in the current tree is redundant — we already
  // surface it at the top. History matters for *removed* or *changed* values.
  const treeKeys = new Set(
    tree.map((f) => `${f.filePath}|${f.patternId}|${f.lineContent}`),
  )
  return history.filter(
    (f) => !treeKeys.has(`${f.filePath}|${f.patternId}|${f.lineContent}`),
  )
}

/**
 * Scan up to `HISTORY_COMMIT_LIMIT` recent commits for secrets that were added
 * and potentially later removed. Even a secret that was rotated still lives
 * in git history and should be treated as compromised.
 */
export async function scanHistory(
  token: string | null,
  owner: string,
  repo: string,
  branch: string,
  treeFindings: SecretFinding[],
): Promise<SecretFinding[]> {
  const startedAt = Date.now()
  const commits = await listCommits(token, owner, repo, branch)
  if (commits.length === 0) return []

  const results: SecretFinding[] = []

  for (let i = 0; i < commits.length; i += HISTORY_PARALLEL) {
    if (Date.now() - startedAt > HISTORY_BUDGET_MS) break
    const batch = commits.slice(i, i + HISTORY_PARALLEL)
    const details = await Promise.all(
      batch.map((c) => fetchCommit(token, owner, repo, c.sha).catch(() => null)),
    )
    for (const detail of details) {
      if (!detail?.files) continue
      for (const file of detail.files) {
        if (!file.patch) continue
        if (file.patch.length > MAX_PATCH_SIZE) continue
        const added = extractAddedLines(file.patch)
        const fileFindings = scanAddedLinesForSecrets(added, file.filename, detail)
        results.push(...fileFindings)
      }
    }
  }

  return dedupeAgainstTree(results, treeFindings)
}
