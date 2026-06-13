import { SECRET_PATTERNS } from "./secret-patterns"
import { buildGitHubHeaders, encodePathSegments } from "./github-fetch"
import { findSensitiveFiles } from "./sensitive-files"
import { findEntropySecrets } from "./entropy"
import { findCodeVulns } from "./code-vulns"
import { runAstRules } from "./ast"
import { scanHistory } from "./history"
import { prioritizeFilesForScan } from "./scan-priority"
import { getMaxFilesToScan, getMaxScanTimeMs } from "./scan-budget"
import { isLikelyScannerSelfReference } from "./scanner-self-reference"
import {
  validateSecrets,
  type SecretWithValue,
} from "./secret-validation"
import {
  isActionsWorkflowPath,
  isDockerfilePath,
  scanDockerfile,
  scanGithubActions,
} from "./iac"
import { scanKubernetes } from "./iac-k8s"
import { isTerraformPath, scanTerraform } from "./iac-terraform"
import { scanCloudFormation } from "./iac-cloudformation"
import { isHelmValuesPath, scanHelmValues } from "./iac-helm"
import { scanIamPolicy } from "./iam-policy"
import {
  detectFrameworks,
  MANIFEST_FILES,
  type Framework,
  type Manifests,
} from "./framework-detect"
import { scanFrameworkRules } from "./framework-rules"
import { scanBusinessLogic } from "./biz-logic"
import { scanAiInsecure } from "./ai-insecure"
import type {
  SecretFinding,
  SensitiveFileFinding,
  CodeFinding,
  IaCFinding,
  DependencyFinding,
  LicenseFinding,
  DetectorHealth,
} from "./types"
import type { AttackGraph } from "./attack-graph"

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

// Raised when the authenticated route is asked to scan a repo the
// user has access to but that is marked private on GitHub. The
// /security page promises "we do not read private repositories";
// enforcing it at the API boundary is what makes that promise true.
export class PrivateRepoRefusedError extends Error {
  readonly owner: string
  readonly repo: string
  constructor(owner: string, repo: string) {
    super(`Repository ${owner}/${repo} is private. TriageRook only scans public repositories.`)
    this.name = "PrivateRepoRefusedError"
    this.owner = owner
    this.repo = repo
  }
}

/**
 * Returns retry-after seconds if the response indicates GitHub rate limiting,
 * otherwise null. Handles the primary rate limit (403/429 + x-ratelimit-
 * remaining: 0) and the secondary/abuse rate limit (Retry-After header).
 * GitHub's docs note a secondary limit may arrive as a bare 429 with neither
 * header set, in which case the client should back off at least 60s.
 */
const SECONDARY_RATE_LIMIT_FALLBACK_SECONDS = 60

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

  // A 429 with no rate-limit signature is still a rate limit: GitHub's
  // secondary (abuse) limits may omit both x-ratelimit-remaining and
  // Retry-After. Default to the documented 60s backoff rather than
  // misclassifying it as a generic failure.
  if (response.status === 429) return SECONDARY_RATE_LIMIT_FALLBACK_SECONDS

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
  // Go (go.mod) and Ruby (Gemfile.lock) ecosystems are optional on the
  // type so persisted scans pre-2026-05-15 still parse. New scans
  // always emit them (possibly empty arrays).
  goDependencies?: DependencyFinding[]
  rubyDependencies?: DependencyFinding[]
  // Open-source license / compliance findings (copyleft, missing license).
  // Optional so persisted scans pre-2026-05-28 still parse as empty.
  licenseFindings?: LicenseFinding[]
  // When set, the scan was narrowed to a subfolder of the repo. UI
  // shows this in the header so a user looking at "0 findings" for a
  // narrow scan doesn't conclude the whole repo is clean. Persisted
  // scans pre-2026-05-14 don't have this field.
  pathPrefix?: string
  // Detectors that soft-failed during this scan. UI surfaces these as
  // a warning banner so "0 findings" isn't mistaken for "actually clean".
  degraded?: DetectorHealth[]
  // Blast-radius / attack-path correlation over the findings (lib/attack-
  // graph.ts). Attached by the scan pipeline. Optional so persisted scans
  // pre-2026-05-28 still parse.
  attackGraph?: AttackGraph
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
// File count and time budget are now configurable via SCAN_MAX_FILES
// and SCAN_MAX_TIME_MS env vars (see lib/scan-budget.ts). Defaults
// (1000 files, 55s) are tuned for Vercel Hobby's 60s function timeout.
// Raise both env vars together when migrating to Vercel Pro (300s) —
// the file cap is the constraint that lets users actually feel the
// extra time budget.

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
  defaultBranch?: string,
  // Optional path prefix to narrow the scan to a subfolder of the repo
  // (e.g. "packages/auth" inside a monorepo). Trailing slash is
  // normalised; the value MUST have been validated by
  // isSafeRepoFilePath() at the API boundary — callers that don't
  // pre-validate risk feeding GitHub's tree filter a directory
  // traversal segment.
  pathPrefix?: string,
  // Optional scan-level options. `validateSecrets` is the per-call permission
  // gate for secret liveness validation — it ANDs with the deployment-level
  // ENABLE_SECRET_VALIDATION flag (see lib/secret-validation.ts). The
  // anonymous public-scan path leaves this false so it never fires
  // third-party API calls with credentials found in arbitrary repos.
  opts?: { validateSecrets?: boolean },
): Promise<ScanResult> {
  const startedAt = Date.now()
  const repoFullName = `${owner}/${repo}`
  const maxFilesToScan = getMaxFilesToScan()
  const maxScanTimeMs = getMaxScanTimeMs()

  // 1. Resolve branch (use explicit if given, else query repo metadata)
  const branch =
    defaultBranch ?? (await fetchRepoMetadata(accessToken, owner, repo)).default_branch

  // 2. Get the full file tree
  const tree = await fetchRepoTree(accessToken, owner, repo, branch)

  // 3. Filter to scannable files, then prioritize source paths over
  //    tests/fixtures/docs so the file-cap budget is spent on the slice
  //    most likely to contain real findings. See lib/scan-priority.ts
  //    for the tier table. If a pathPrefix was supplied, restrict the
  //    tree to that subfolder first — useful for huge monorepos where
  //    the user wants to focus on `packages/auth` without burning the
  //    file-cap budget on unrelated packages.
  const normalizedPrefix = pathPrefix ? pathPrefix.replace(/\/+$/, "") : undefined
  const allBlobs = tree.tree.filter((item) => item.type === "blob")
  const blobsInScope = normalizedPrefix
    ? allBlobs.filter(
        (item) =>
          item.path === normalizedPrefix ||
          item.path.startsWith(`${normalizedPrefix}/`),
      )
    : allBlobs
  const scannable = blobsInScope.filter((item) => isScannable(item))
  const prioritized = prioritizeFilesForScan(scannable)

  const filesToScan = prioritized.slice(0, maxFilesToScan)
  // Skipped count is computed against the IN-SCOPE blob count when a
  // prefix narrows the scan — otherwise a narrow scan would always
  // appear "truncated" because thousands of files outside the prefix
  // count as skipped, which is wrong (they were intentionally excluded).
  const filesSkipped = blobsInScope.length - filesToScan.length

  // 4. Flag sensitive files by name (no blob fetch needed). Honor the
  //    same prefix scope so a narrow scan doesn't surface findings in
  //    sibling subfolders.
  const sensitiveFiles = findSensitiveFiles(blobsInScope.map((b) => b.path))

  // 4b. Detect frameworks from manifests so the framework-aware SAST layer
  //     can gate its rules. Best-effort: detection failure just means those
  //     rules don't fire. Uses the in-scope blob list so a narrowed scan
  //     detects the right subproject's stack.
  let frameworks: Set<Framework> = new Set()
  try {
    frameworks = await detectRepoFrameworks(accessToken, owner, repo, blobsInScope)
  } catch {
    frameworks = new Set()
  }

  // 5. Scan files in parallel batches
  const findings: SecretFinding[] = []
  const codeFindings: CodeFinding[] = []
  const iacFindings: IaCFinding[] = []
  // Transient raw-value channel for optional secret validation. Never returned.
  const secretValues: SecretWithValue[] = []
  let filesScanned = 0
  let timeLimitHit = false

  const BATCH_SIZE = 10
  for (let i = 0; i < filesToScan.length; i += BATCH_SIZE) {
    if (Date.now() - startedAt > maxScanTimeMs) {
      timeLimitHit = true
      break
    }

    const batch = filesToScan.slice(i, i + BATCH_SIZE)
    const batchResults = await Promise.all(
      batch.map((file) => scanFile(accessToken, owner, repo, file, frameworks))
    )

    for (const { secrets, code, iac, secretValues: sv } of batchResults) {
      findings.push(...secrets)
      codeFindings.push(...code)
      iacFindings.push(...iac)
      secretValues.push(...sv)
    }
    filesScanned += batch.length
  }

  // Optional secret liveness validation. Mutates finding.validation in place
  // (the finding objects in `secretValues` are the same references already
  // pushed to `findings`). Raw values stay local to this function and are
  // never returned. No-ops unless the deployment flag + per-call flag are set.
  await validateSecrets(secretValues, {
    enabled: opts?.validateSecrets ?? false,
  })

  // 6. Scan recent commit history (best-effort; soft-fails on errors)
  let historyFindings: SecretFinding[] = []
  const degraded: DetectorHealth[] = []
  try {
    historyFindings = await scanHistory(accessToken, owner, repo, branch, findings)
  } catch (err) {
    if (err instanceof GitHubRateLimitError) {
      // Don't fail the whole scan just because history hit the rate limit —
      // but tell the user we skipped it instead of letting them assume
      // history is clean.
      historyFindings = []
      degraded.push({
        detector: "history",
        reason: "GitHub API rate limit hit — recent-commit history scan skipped.",
      })
    } else {
      // Unknown failure (network, parse error, GitHub 5xx). The rest of the
      // scan still has value, so we soft-fail history specifically — but we
      // log because silent failure here violates AGENTS.md ("never silently
      // swallow GitHub/Supabase errors").
      const msg = err instanceof Error ? err.message : String(err)
      console.warn("[scan] history scan failed, continuing without it:", msg)
      historyFindings = []
      degraded.push({
        detector: "history",
        reason: `History scan failed (${msg.slice(0, 80)}). Recent commits not checked.`,
      })
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
    truncated: tree.truncated || timeLimitHit || scannable.length > maxFilesToScan,
    // Echoes back what subfolder (if any) was scanned. UI uses this to
    // make it clear "this is a narrow scan of packages/auth, not the
    // whole repo" — same shape consideration as the truncation banner.
    pathPrefix: normalizedPrefix ?? undefined,
    degraded: degraded.length > 0 ? degraded : undefined,
  }
}

async function fetchRepoMetadata(
  accessToken: string | null,
  owner: string,
  repo: string
): Promise<{ default_branch: string; private: boolean }> {
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

// Public visibility check used at the API boundary to enforce the
// "public repos only" promise on the /security page. Throws
// GitHubRepoNotFoundError / GitHubRateLimitError on the usual GitHub
// failure modes; throws PrivateRepoRefusedError if the repo exists and
// the caller can see it but it's marked private. Returns the default
// branch so callers can avoid a second metadata round-trip inside
// scanRepo().
export async function assertPublicRepo(
  accessToken: string | null,
  owner: string,
  repo: string,
): Promise<{ defaultBranch: string }> {
  const meta = await fetchRepoMetadata(accessToken, owner, repo)
  if (meta.private) {
    throw new PrivateRepoRefusedError(owner, repo)
  }
  return { defaultBranch: meta.default_branch }
}

async function fetchRepoTree(
  accessToken: string | null,
  owner: string,
  repo: string,
  branch: string
): Promise<GitHubTreeResponse> {
  // encodePathSegments is defense-in-depth — the API boundary already runs
  // isSafeGitRef(), but a future caller that skips validation would
  // otherwise rebuild a malformed URL here. It preserves '/' so a slashed
  // default branch (e.g. `release/v2`) still resolves; a plain
  // encodeURIComponent() would turn '/' into %2F and 404 the tree.
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodePathSegments(branch)}?recursive=1`

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
 * is missing or unreadable. Does NOT count against the per-run file cap.
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
  // Transient: regex-pattern secrets paired with their raw values, for
  // optional liveness validation. Entropy secrets are omitted (no known
  // provider to validate against). Never persisted.
  secretValues: SecretWithValue[]
}

// Fetch a single blob's UTF-8 text by sha, or null on any failure. Shared by
// scanFile and the framework-manifest pre-pass.
async function fetchBlobText(
  accessToken: string | null,
  owner: string,
  repo: string,
  sha: string,
): Promise<string | null> {
  try {
    const res = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/git/blobs/${sha}`,
      { headers: buildGitHubHeaders(accessToken), cache: "no-store" },
    )
    if (!res.ok) return null
    const data = (await res.json()) as { content: string; encoding: string }
    if (data.encoding !== "base64") return null
    return Buffer.from(data.content, "base64").toString("utf-8")
  } catch {
    return null
  }
}

// Detect web frameworks from the repo's root manifests. Fetches only the
// shallowest copy of each known manifest (so a vendored package.json deep in
// the tree doesn't drive detection) — a handful of small blob fetches.
async function detectRepoFrameworks(
  accessToken: string | null,
  owner: string,
  repo: string,
  blobs: GitHubTreeItem[],
): Promise<Set<Framework>> {
  const shallowest = new Map<keyof Manifests, GitHubTreeItem>()
  for (const blob of blobs) {
    const base = blob.path.split("/").pop() ?? ""
    const key = MANIFEST_FILES[base]
    if (!key) continue
    const existing = shallowest.get(key)
    if (!existing || blob.path.split("/").length < existing.path.split("/").length) {
      shallowest.set(key, blob)
    }
  }
  if (shallowest.size === 0) return new Set()

  const entries = await Promise.all(
    Array.from(shallowest.entries()).map(async ([key, blob]) => {
      const text = await fetchBlobText(accessToken, owner, repo, blob.sha)
      return [key, text] as const
    }),
  )
  const manifests: Manifests = {}
  for (const [key, text] of entries) manifests[key] = text
  return detectFrameworks(manifests)
}

async function scanFile(
  accessToken: string | null,
  owner: string,
  repo: string,
  file: GitHubTreeItem,
  frameworks: Set<Framework>,
): Promise<FileScanResult> {
  try {
    const content = await fetchBlobText(accessToken, owner, repo, file.sha)
    if (content === null) return { secrets: [], code: [], iac: [], secretValues: [] }

    // Skip files that look binary (lots of non-printable chars)
    if (looksBinary(content)) return { secrets: [], code: [], iac: [], secretValues: [] }

    const likelyTestFixture = isTestLikePath(file.path)
    const regexMatches = matchPatterns(content, file.path, likelyTestFixture)
    const regexFindings = regexMatches.map((m) => m.finding)
    const entropyFindings = findEntropySecrets(content, file.path, likelyTestFixture)
    const codeFindings = findCodeVulns(content, file.path, likelyTestFixture)
    // Framework-aware rules — gated on the repo's detected frameworks and the
    // file's language (see lib/framework-rules.ts). Empty when no framework
    // matched, so it's free for non-framework repos.
    const frameworkFindings = scanFrameworkRules(
      content,
      file.path,
      frameworks,
      likelyTestFixture,
    )
    // AST-based SAST runs alongside the regex code-vulns layer (not
    // instead of it). Regex rules catch patterns AST can't cheaply
    // express (e.g. comments, string-content checks like bcrypt rounds);
    // AST rules catch patterns regex can't express precisely (e.g. user
    // input flowing into a SQL/exec call across a few hops). Both emit
    // CodeFinding[] so downstream consumers don't care about the source.
    const astFindings = runAstRules(file.path, content, likelyTestFixture)
    // Business-logic / broken-access-control layer (IDOR, mass assignment,
    // privilege escalation, payment tampering). Language-gated, comment-skipped.
    const bizLogicFindings = scanBusinessLogic(content, file.path, likelyTestFixture)
    // AI-generated insecure-code tells (placeholder creds, deferred-security
    // TODOs, "not for production" disclaimers, swallowed exceptions). Reads
    // comment lines too; low/medium severity so it doesn't drown real vulns.
    const aiInsecureFindings = scanAiInsecure(content, file.path, likelyTestFixture)

    const iac: IaCFinding[] = []
    if (isDockerfilePath(file.path)) {
      iac.push(...scanDockerfile(content, file.path))
    } else if (isActionsWorkflowPath(file.path)) {
      iac.push(...scanGithubActions(content, file.path))
    } else if (isTerraformPath(file.path)) {
      iac.push(...scanTerraform(content, file.path))
    } else if (/\.ya?ml$/i.test(file.path)) {
      // Kubernetes manifests and CloudFormation templates aren't path-
      // identifiable, so both self-guard on content (apiVersion:+kind: /
      // AWSTemplateFormatVersion or Resources+AWS::) and return [] otherwise.
      iac.push(...scanKubernetes(content, file.path))
      iac.push(...scanCloudFormation(content, file.path))
      // Helm chart values aren't K8s manifests (no apiVersion+kind), so the
      // K8s scanner skips them; the dedicated Helm scanner catches insecure
      // chart defaults. Path-gated to values*.yaml.
      if (isHelmValuesPath(file.path)) {
        iac.push(...scanHelmValues(content, file.path))
      }
    } else if (/\.json$/i.test(file.path)) {
      // CloudFormation templates are also authored in JSON; self-guards.
      iac.push(...scanCloudFormation(content, file.path))
    }
    // IAM-in-code runs additively (not in the else-if chain): an AWS policy
    // JSON or a file mentioning a GCP primitive role is usually neither a
    // Dockerfile nor a workflow. Self-guards and skips .tf internally.
    iac.push(...scanIamPolicy(content, file.path))

    // Stamp the test-fixture flag so risk scoring de-prioritises IaC findings
    // in test/fixture/example paths, consistent with secret/code findings.
    if (likelyTestFixture) {
      for (const f of iac) f.likelyTestFixture = true
    }

    return {
      secrets: [...regexFindings, ...entropyFindings],
      code: [
        ...codeFindings,
        ...astFindings,
        ...frameworkFindings,
        ...bizLogicFindings,
        ...aiInsecureFindings,
      ],
      iac,
      secretValues: regexMatches,
    }
  } catch {
    return { secrets: [], code: [], iac: [], secretValues: [] }
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
): SecretWithValue[] {
  const findings: SecretWithValue[] = []
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

      // Skip matches that look like the detector's own definition
      // (inside a JS regex literal or after a `pattern:`/`regex:`
      // property marker). See lib/scanner-self-reference.ts.
      const lineStart = before.lastIndexOf("\n") + 1
      const matchOffsetInLine = matchIndex - lineStart
      if (isLikelyScannerSelfReference(lineContent, matchOffsetInLine)) {
        if (match.index === pattern.regex.lastIndex) pattern.regex.lastIndex++
        continue
      }

      findings.push({
        finding: {
          patternId: pattern.id,
          patternName: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          filePath,
          lineNumber,
          lineContent: maskLine(lineContent, match[0]),
          likelyTestFixture,
        },
        // Raw matched value — kept transiently for optional liveness
        // validation. NEVER persisted; consumed in scanRepo and dropped.
        rawValue: match[0],
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

