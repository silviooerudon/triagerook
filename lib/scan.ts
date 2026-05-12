import { SECRET_PATTERNS } from "./secret-patterns"
import { findSensitiveFiles } from "./sensitive-files"
import { findEntropySecrets } from "./entropy"
import { findCodeVulns } from "./code-vulns"
import { scanHistory } from "./history"
import {
  isActionsWorkflowPath,
  isDockerfilePath,
  scanDockerfile,
  scanGithubActions,
} from "./iac"
import type {
  SecretFinding,
  SensitiveFileFinding,
  CodeFinding,
  IaCFinding,
  DependencyFinding,
} from "./types"

export class GitHubRateLimitError extends Error {
  readonly retryAfterSeconds: number
  constructor(retryAfterSeconds: number) {
    super(`GitHub API rate limit exceeded. Retry in ${retryAfterSeconds}s.`)
    this.name = "GitHubRateLimitError"
    this.retryAfterSeconds = retryAfterSeconds
  }
}

export class GitHubRepoNotFoundError extends Error {
  readonly owner: string
  readonly repo: string
  constructor(owner: string, repo: string) {
    super(`Repository ${owner}/${repo} not found or inaccessible.`)
    this.name = "GitHubRepoNotFoundError"
    this.owner = owner
    this.repo = repo
  }
}

/**
 * Returns retry-after seconds if the response indicates GitHub rate limiting,
 * otherwise null. Handles primary rate limit (403 + x-ratelimit-remaining: 0)
 * and secondary/abuse rate limit (429 with Retry-After header).
 */
export function parseGitHubRateLimit(response: Response): number | null {
  if (response.status !== 403 && response.status !== 429) return null

  const remaining = response.headers.get("x-ratelimit-remaining")
  const reset = response.headers.get("x-ratelimit-reset")
  const retryAfter = response.headers.get("retry-after")

  if (remaining === "0" && reset) {
    const resetEpoch = Number.parseInt(reset, 10)
    if (Number.isFinite(resetEpoch)) {
      return Math.max(1, resetEpoch - Math.floor(Date.now() / 1000))
    }
  }

  if (retryAfter) {
    const seconds = Number.parseInt(retryAfter, 10)
    if (Number.isFinite(seconds)) return Math.max(1, seconds)
  }

  // 403 without the rate-limit signature is a permission error, not a rate limit
  return null
}

export type { SecretFinding } from "./types"

export type ScanResult = {
  repoFullName: string
  scannedAt: string
  filesScanned: number
  filesSkipped: number
  findings: SecretFinding[]
  durationMs: number
  truncated: boolean // true if we hit file count or time limits
  // Optional extended findings. Absent on legacy/persisted scans — UI treats
  // undefined as an empty list.
  sensitiveFiles?: SensitiveFileFinding[]
  historyFindings?: SecretFinding[]
  codeFindings?: CodeFinding[]
  iacFindings?: IaCFinding[]
  dependencies?: DependencyFinding[]
  pythonDependencies?: DependencyFinding[]
}

// File extensions we want to scan (text-based, likely to contain secrets)
const SCANNABLE_EXTENSIONS = new Set([
  "js", "jsx", "ts", "tsx", "mjs", "cjs",
  "py", "rb", "go", "java", "kt", "scala", "rs", "php",
  "c", "cpp", "h", "hpp", "cs",
  "sh", "bash", "zsh", "fish",
  "yml", "yaml", "json", "xml", "toml", "ini", "conf", "config",
  "env", "envrc",
  "md", "txt",
  "sql",
  "dockerfile", "makefile",
  "properties", "plist",
  "tf", "tfvars", // Terraform
  "bicep", // Azure
])

// Heuristics for test/fixture files — findings here are almost always dummy values
const TEST_PATH_PATTERNS: RegExp[] = [
  /(^|\/)(tests?|__tests?__|specs?|fixtures?|mocks?|examples?|samples?|testdata|stubs?|cypress|e2e|demos?)\//i,
  /\.(test|spec)\.[a-z0-9]+$/i, // foo.test.ts, foo.spec.js
  /_test\.[a-z0-9]+$/i, // Go: foo_test.go
  /_spec\.[a-z0-9]+$/i, // Ruby-ish: foo_spec.rb
]

function isTestLikePath(path: string): boolean {
  return TEST_PATH_PATTERNS.some((pattern) => pattern.test(path))
}

// Paths to always skip (vendored code, build output, etc.)
const SKIP_PATH_PATTERNS = [
  /(^|\/)node_modules\//,
  /(^|\/)\.next\//,
  /(^|\/)dist\//,
  /(^|\/)build\//,
  /(^|\/)target\//, // Java/Rust
  /(^|\/)vendor\//,
  /(^|\/)\.git\//,
  /(^|\/)coverage\//,
  /(^|\/)out\//,
  /\.min\.(js|css)$/,
  /\.lock$/,
  /package-lock\.json$/,
  /yarn\.lock$/,
  /pnpm-lock\.yaml$/,
  /\.map$/, // sourcemaps
]

const MAX_FILE_SIZE = 1_000_000 // 1MB
const MAX_FILES_TO_SCAN = 300 // safety limit to avoid huge repos hanging
const MAX_SCAN_TIME_MS = 45_000 // 45s hard cap

type GitHubTreeItem = {
  path: string
  mode: string
  type: "blob" | "tree" | "commit"
  sha: string
  size?: number
  url: string
}

type GitHubTreeResponse = {
  sha: string
  url: string
  tree: GitHubTreeItem[]
  truncated: boolean
}

/**
 * Main scan entry point.
 */
export async function scanRepo(
  accessToken: string | null,
  owner: string,
  repo: string,
  defaultBranch?: string
): Promise<ScanResult> {
  const startedAt = Date.now()
  const repoFullName = `${owner}/${repo}`

  // 1. Resolve branch (use explicit if given, else query repo metadata)
  const branch =
    defaultBranch ?? (await fetchRepoMetadata(accessToken, owner, repo)).default_branch

  // 2. Get the full file tree
  const tree = await fetchRepoTree(accessToken, owner, repo, branch)

  // 3. Filter to scannable files
  const allBlobs = tree.tree.filter((item) => item.type === "blob")
  const scannable = allBlobs.filter((item) => isScannable(item))

  const filesToScan = scannable.slice(0, MAX_FILES_TO_SCAN)
  const filesSkipped = allBlobs.length - filesToScan.length

  // 4. Flag sensitive files by name (no blob fetch needed)
  const sensitiveFiles = findSensitiveFiles(allBlobs.map((b) => b.path))

  // 5. Scan files in parallel batches
  const findings: SecretFinding[] = []
  const codeFindings: CodeFinding[] = []
  const iacFindings: IaCFinding[] = []
  let filesScanned = 0
  let timeLimitHit = false

  const BATCH_SIZE = 10
  for (let i = 0; i < filesToScan.length; i += BATCH_SIZE) {
    if (Date.now() - startedAt > MAX_SCAN_TIME_MS) {
      timeLimitHit = true
      break
    }

    const batch = filesToScan.slice(i, i + BATCH_SIZE)
    const batchResults = await Promise.all(
      batch.map((file) => scanFile(accessToken, owner, repo, file))
    )

    for (const { secrets, code, iac } of batchResults) {
      findings.push(...secrets)
      codeFindings.push(...code)
      iacFindings.push(...iac)
    }
    filesScanned += batch.length
  }

  // 6. Scan recent commit history (best-effort; soft-fails on errors)
  let historyFindings: SecretFinding[] = []
  try {
    historyFindings = await scanHistory(accessToken, owner, repo, branch, findings)
  } catch (err) {
    if (err instanceof GitHubRateLimitError) {
      // Don't fail the whole scan just because history hit the rate limit.
      historyFindings = []
    } else {
      // Unknown failure (network, parse error, GitHub 5xx). The rest of the
      // scan still has value, so we soft-fail history specifically — but we
      // log because silent failure here violates AGENTS.md ("never silently
      // swallow GitHub/Supabase errors").
      console.warn(
        "[scan] history scan failed, continuing without it:",
        err instanceof Error ? err.message : String(err),
      )
      historyFindings = []
    }
  }

  return {
    repoFullName,
    scannedAt: new Date().toISOString(),
    filesScanned,
    filesSkipped,
    findings,
    sensitiveFiles,
    historyFindings,
    codeFindings,
    iacFindings,
    durationMs: Date.now() - startedAt,
    truncated: tree.truncated || timeLimitHit || scannable.length > MAX_FILES_TO_SCAN,
  }
}

async function fetchRepoMetadata(
  accessToken: string | null,
  owner: string,
  repo: string
): Promise<{ default_branch: string }> {
  const url = `https://api.github.com/repos/${owner}/${repo}`
  const response = await fetch(url, {
    headers: buildGitHubHeaders(accessToken),
    cache: "no-store",
  })

  if (response.status === 404) {
    throw new GitHubRepoNotFoundError(owner, repo)
  }
  if (!response.ok) {
    const retryAfter = parseGitHubRateLimit(response)
    if (retryAfter !== null) throw new GitHubRateLimitError(retryAfter)
    throw new Error(`Failed to fetch repo metadata: ${response.status} ${response.statusText}`)
  }

  return response.json()
}

async function fetchRepoTree(
  accessToken: string | null,
  owner: string,
  repo: string,
  branch: string
): Promise<GitHubTreeResponse> {
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`

  const response = await fetch(url, {
    headers: buildGitHubHeaders(accessToken),
    cache: "no-store",
  })

  if (!response.ok) {
    const retryAfter = parseGitHubRateLimit(response)
    if (retryAfter !== null) {
      throw new GitHubRateLimitError(retryAfter)
    }
    throw new Error(
      `Failed to fetch repo tree: ${response.status} ${response.statusText}`
    )
  }

  return response.json()
}

/**
 * Best-effort fetch of `.repoguardignore` from the repo root via the GitHub
 * Contents API. Soft-fails on any error (404, rate limit, decode error) by
 * returning null — the scan should never fail because the suppressions file
 * is missing or unreadable. Does NOT count against the MAX_FILES_TO_SCAN limit.
 */
export async function fetchSuppressionsFile(
  accessToken: string | null,
  owner: string,
  repo: string,
  ref?: string,
): Promise<string | null> {
  const url = `https://api.github.com/repos/${owner}/${repo}/contents/.repoguardignore${
    ref ? `?ref=${encodeURIComponent(ref)}` : ""
  }`
  try {
    const response = await fetch(url, {
      headers: buildGitHubHeaders(accessToken),
      cache: "no-store",
    })
    if (response.status === 404) return null
    if (!response.ok) {
      console.warn(
        `[suppressions] Unexpected status fetching .repoguardignore: ${response.status} ${response.statusText}`,
      )
      return null
    }
    const data = (await response.json()) as { content?: string; encoding?: string }
    if (data.encoding !== "base64" || !data.content) return null
    return Buffer.from(data.content, "base64").toString("utf-8")
  } catch (err) {
    console.warn(
      "[suppressions] Failed to fetch .repoguardignore:",
      err instanceof Error ? err.message : String(err),
    )
    return null
  }
}

function isScannable(item: GitHubTreeItem): boolean {
  const path = item.path

  // Skip based on path patterns
  if (SKIP_PATH_PATTERNS.some((pattern) => pattern.test(path))) {
    return false
  }

  // Skip files that are too large
  if (item.size !== undefined && item.size > MAX_FILE_SIZE) {
    return false
  }

  // Check extension
  const lowerPath = path.toLowerCase()
  const lastDot = lowerPath.lastIndexOf(".")
  const fileName = lowerPath.split("/").pop() ?? ""

  // Files with no extension: only scan known names
  if (lastDot === -1 || lastDot < lowerPath.lastIndexOf("/")) {
    return (
      fileName === "dockerfile" ||
      fileName === "makefile" ||
      fileName.startsWith(".env")
    )
  }

  const ext = lowerPath.slice(lastDot + 1)
  return SCANNABLE_EXTENSIONS.has(ext) || fileName.startsWith(".env")
}

type FileScanResult = {
  secrets: SecretFinding[]
  code: CodeFinding[]
  iac: IaCFinding[]
}

async function scanFile(
  accessToken: string | null,
  owner: string,
  repo: string,
  file: GitHubTreeItem
): Promise<FileScanResult> {
  try {
    const url = `https://api.github.com/repos/${owner}/${repo}/git/blobs/${file.sha}`
    const response = await fetch(url, {
      headers: buildGitHubHeaders(accessToken),
      cache: "no-store",
    })

    if (!response.ok) return { secrets: [], code: [], iac: [] }

    const data = (await response.json()) as { content: string; encoding: string }
    if (data.encoding !== "base64") return { secrets: [], code: [], iac: [] }

    const content = Buffer.from(data.content, "base64").toString("utf-8")

    // Skip files that look binary (lots of non-printable chars)
    if (looksBinary(content)) return { secrets: [], code: [], iac: [] }

    const likelyTestFixture = isTestLikePath(file.path)
    const regexFindings = matchPatterns(content, file.path, likelyTestFixture)
    const entropyFindings = findEntropySecrets(content, file.path, likelyTestFixture)
    const codeFindings = findCodeVulns(content, file.path, likelyTestFixture)

    const iac: IaCFinding[] = []
    if (isDockerfilePath(file.path)) {
      iac.push(...scanDockerfile(content, file.path))
    } else if (isActionsWorkflowPath(file.path)) {
      iac.push(...scanGithubActions(content, file.path))
    }

    return {
      secrets: [...regexFindings, ...entropyFindings],
      code: codeFindings,
      iac,
    }
  } catch {
    return { secrets: [], code: [], iac: [] }
  }
}

function looksBinary(content: string): boolean {
  // Sample first 1000 chars; if >10% are non-printable, treat as binary
  const sample = content.slice(0, 1000)
  let nonPrintable = 0
  for (let i = 0; i < sample.length; i++) {
    const code = sample.charCodeAt(i)
    if (code === 0 || (code < 32 && code !== 9 && code !== 10 && code !== 13)) {
      nonPrintable++
    }
  }
  return nonPrintable / sample.length > 0.1
}

function matchPatterns(
  content: string,
  filePath: string,
  likelyTestFixture: boolean,
): SecretFinding[] {
  const findings: SecretFinding[] = []
  const lines = content.split("\n")

  for (const pattern of SECRET_PATTERNS) {
    // Reset regex state for global regexes
    pattern.regex.lastIndex = 0

    let match: RegExpExecArray | null
    while ((match = pattern.regex.exec(content)) !== null) {
      const matchIndex = match.index
      const before = content.slice(0, matchIndex)
      const lineNumber = before.split("\n").length
      const lineContent = lines[lineNumber - 1] ?? ""

      findings.push({
        patternId: pattern.id,
        patternName: pattern.name,
        severity: pattern.severity,
        description: pattern.description,
        filePath,
        lineNumber,
        lineContent: maskLine(lineContent, match[0]),
        likelyTestFixture,
      })

      // Prevent infinite loops on zero-width matches
      if (match.index === pattern.regex.lastIndex) {
        pattern.regex.lastIndex++
      }
    }
  }

  return findings
}

function maskLine(line: string, matchedText: string): string {
  // Replace the matched secret with ••• for safe display
  const masked = matchedText.length <= 8
    ? "•".repeat(matchedText.length)
    : matchedText.slice(0, 4) + "•".repeat(matchedText.length - 8) + matchedText.slice(-4)

  // Truncate line if too long
  const replaced = line.replace(matchedText, masked)
  return replaced.length > 200 ? replaced.slice(0, 197) + "..." : replaced.trim()
}

function buildGitHubHeaders(accessToken: string | null): HeadersInit {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  }
  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`
  }
  return headers
}