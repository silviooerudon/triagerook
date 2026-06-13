import { GitHubRateLimitError, parseGitHubRateLimit } from "./scan"
import {
  assessRulesetSignals,
  type RulesetSignals,
} from "./posture-rulesets"
import { buildGitHubHeaders, encodePathSegments } from "./github-fetch"
import type { RulesetBypassFinding } from "./types"

export type PostureGrade = "A" | "B" | "C" | "D" | "F"

export type PostureCategoryId = "branch" | "docs" | "deps" | "governance"

export type PostureSignal = {
  id: string
  category: PostureCategoryId
  label: string
  pointsEarned: number
  pointsMax: number
  satisfied: boolean
  // True when the signal could not be evaluated (admin scope missing, org-only
  // metadata unavailable, network failure). Score treats it as 0 earned but
  // the UI flags it differently from a deliberately-unsatisfied signal.
  unknown?: boolean
}

export type PostureCategoryBreakdown = {
  id: PostureCategoryId
  label: string
  pointsEarned: number
  pointsMax: number
  signals: PostureSignal[]
}

export type QuickWin = {
  signalId: string
  label: string
  pointsAvailable: number
}

export type PostureResult = {
  score: number
  grade: PostureGrade
  breakdown: PostureCategoryBreakdown[]
  quickWins: QuickWin[]
  degraded: boolean
  bypassFindings: RulesetBypassFinding[]
}

// --- Re-balanced weights (total = 100) ----------------------------------------
// Original (8 signals, 100 pts):
//   branch 35 / docs 35 / deps 30
// Expanded (14 signals, 100 pts):
//   branch 30 / docs 30 / deps 25 / governance 15
// Old DB rows persisted with the v1 calibration; new scans use this v2.
// JSONB schema is flexible so no migration is required.

const W = {
  branchProtection: 15,
  branchPrRequired: 5,
  branchStatusChecks: 5,
  branchEnforceAdmins: 5,

  securityMd: 10,
  license: 8,
  codeowners: 5,
  readmeSubstantial: 4,
  readmeMentionsSecurity: 3,

  autoUpdates: 12,
  lockfile: 8,
  gitignoreBasics: 5,

  signedCommits: 10,
  mfaOrg: 5,
  secretScanning: 6,
  workflowPermissions: 5,
  releaseProvenance: 4,
} as const

type BranchProtectionDetails = {
  prRequired: boolean
  statusChecksRequired: boolean
  enforceAdmins: boolean
}

type MfaState = "enforced" | "not-enforced" | "na-user-repo" | "unknown"
type SecretScanningState = "enabled" | "disabled" | "unknown"
type WorkflowPermState = "read" | "write" | "unknown"
type ReleaseProvenanceState = "present" | "absent" | "unknown"

type RawSignals = {
  branchProtected: boolean
  branchProtectionDetails: BranchProtectionDetails | null // null = unknown (no admin / 403 / 404)
  hasSecurityMd: boolean
  hasLicense: boolean
  hasCodeowners: boolean
  readmeContent: string | null
  hasDependabotOrRenovate: boolean
  hasLockfile: boolean
  gitignoreContent: string | null
  signedCommitsRatio: number | null // 0..1 or null if undeterminable
  mfaState: MfaState
  secretScanning: SecretScanningState
  workflowPerms: WorkflowPermState
  releaseProvenance: ReleaseProvenanceState
  rulesetSignals: RulesetSignals | null
  degraded: boolean
}

const QUICK_WIN_COPY: Record<string, string> = {
  "branch-protection": "Enable branch protection on main",
  "branch-pr-required": "Require pull request reviews on main",
  "branch-status-checks": "Require status checks before merge",
  "branch-enforce-admins": "Apply branch protection to admins too",
  "security-md": "Add SECURITY.md",
  "license": "Add a LICENSE file",
  "codeowners": "Add a CODEOWNERS file",
  "readme-substantial": "Expand README (at least 500 chars)",
  "readme-mentions-security": "Mention security/SECURITY.md in README",
  "auto-updates": "Enable Dependabot or Renovate",
  "lockfile": "Commit a lockfile (package-lock.json, yarn.lock, etc.)",
  "gitignore-basics": "Add node_modules and .env to .gitignore",
  "signed-commits": "Sign commits (verified by GitHub)",
  "mfa-org": "Enable two-factor enforcement on the organization",
  "secret-scanning": "Enable GitHub secret scanning + push protection",
  "workflow-permissions": "Set default GITHUB_TOKEN permissions to read-only",
  "release-provenance": "Sign releases / publish build provenance (SLSA, cosign, npm --provenance)",
}

async function fetchRepoFile(
  owner: string,
  repo: string,
  path: string,
  token: string | null,
): Promise<string | null> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${encodePathSegments(path)}`,
    {
      headers: buildGitHubHeaders(token, "application/vnd.github.v3.raw"),
      cache: "no-store",
    },
  )
  if (res.status === 404) return null
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    throw new Error(`GitHub fetch ${path} failed: ${res.status}`)
  }
  return res.text()
}

async function repoPathExists(
  owner: string,
  repo: string,
  path: string,
  token: string | null,
): Promise<boolean> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${encodePathSegments(path)}`,
    {
      headers: buildGitHubHeaders(token, "application/vnd.github.v3.json"),
      cache: "no-store",
    },
  )
  if (res.status === 404) return false
  if (res.ok) return true
  const retry = parseGitHubRateLimit(res)
  if (retry !== null) throw new GitHubRateLimitError(retry)
  throw new Error(`GitHub exists-check ${path} failed: ${res.status}`)
}

async function fetchBranch(
  owner: string,
  repo: string,
  branch: string,
  token: string | null,
): Promise<{ protected: boolean } | null> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/branches/${encodePathSegments(branch)}`,
    {
      headers: buildGitHubHeaders(token, "application/vnd.github+json"),
      cache: "no-store",
    },
  )
  if (res.status === 404) return null
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    throw new Error(`GitHub branch fetch failed: ${res.status}`)
  }
  const json = (await res.json()) as { protected?: boolean }
  return { protected: Boolean(json.protected) }
}

// Branch protection details endpoint requires admin/maintain access on the
// repo. For non-admins this returns 403 / 404. We resolve to null (= unknown)
// without throwing - callers mark sub-signals as unknown and degrade the
// overall posture result.
async function fetchBranchProtection(
  owner: string,
  repo: string,
  branch: string,
  token: string | null,
): Promise<BranchProtectionDetails | null> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/branches/${encodePathSegments(branch)}/protection`,
    {
      headers: buildGitHubHeaders(token, "application/vnd.github+json"),
      cache: "no-store",
    },
  )
  if (res.status === 404 || res.status === 403) return null
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    throw new Error(`GitHub branch protection fetch failed: ${res.status}`)
  }
  const json = (await res.json()) as {
    required_pull_request_reviews?: unknown
    required_status_checks?: { contexts?: unknown[] }
    enforce_admins?: { enabled?: boolean }
  }
  const prRequired = Boolean(json.required_pull_request_reviews)
  const statusChecksRequired =
    Array.isArray(json.required_status_checks?.contexts) &&
    (json.required_status_checks?.contexts?.length ?? 0) > 0
  const enforceAdmins = Boolean(json.enforce_admins?.enabled)
  return { prRequired, statusChecksRequired, enforceAdmins }
}

// Sample the last 30 commits and compute the verified ratio. Null if no
// commits returned or the request failed.
async function fetchSignedCommitsRatio(
  owner: string,
  repo: string,
  token: string | null,
): Promise<number | null> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/commits?per_page=30`,
    {
      headers: buildGitHubHeaders(token, "application/vnd.github+json"),
      cache: "no-store",
    },
  )
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    return null
  }
  const json = (await res.json()) as Array<{
    commit?: { verification?: { verified?: boolean } }
  }>
  if (!Array.isArray(json) || json.length === 0) return null
  const verified = json.filter(
    (c) => c.commit?.verification?.verified === true,
  ).length
  return verified / json.length
}

// The fields of GET /repos/{owner}/{repo} that the posture signals read. The
// MFA and secret-scanning signals both derive from this single object, so we
// fetch it once (see assessPosture) and share the promise rather than issuing
// two identical /repos calls against the rate limit.
type RepoObject = {
  owner?: { type?: string; login?: string }
  security_and_analysis?: {
    secret_scanning?: { status?: string }
    secret_scanning_push_protection?: { status?: string }
  }
}

// Single fetch of the repo object. Throws GitHubRateLimitError on a rate limit
// (so the caller's softFail can surface it) and returns null on any other
// non-OK response, which the derivers below treat as "unknown".
async function fetchRepoObject(
  owner: string,
  repo: string,
  token: string | null,
): Promise<RepoObject | null> {
  const res = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
    headers: buildGitHubHeaders(token, "application/vnd.github+json"),
    cache: "no-store",
  })
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    return null
  }
  return (await res.json()) as RepoObject
}

// MFA state assessment. User-owned repos => not applicable (signal omitted
// from quickWins). Org repos => requires `read:org` scope to read
// two_factor_requirement_enabled. Non-members of the org or missing scope =>
// "unknown" (signal flagged but not penalized as a quick win).
async function deriveMfaState(
  repoObjP: Promise<RepoObject | null>,
  token: string | null,
): Promise<MfaState> {
  const repoObj = await repoObjP
  if (!repoObj) return "unknown"
  const ownerType = repoObj.owner?.type
  const ownerLogin = repoObj.owner?.login
  if (ownerType === "User") return "na-user-repo"
  if (ownerType !== "Organization" || !ownerLogin) return "unknown"

  const orgRes = await fetch(`https://api.github.com/orgs/${ownerLogin}`, {
    headers: buildGitHubHeaders(token, "application/vnd.github+json"),
    cache: "no-store",
  })
  if (!orgRes.ok) {
    // Likely 403 (scope missing) or 404 (not a member of private org).
    return "unknown"
  }
  const orgJson = (await orgRes.json()) as {
    two_factor_requirement_enabled?: boolean
  }
  if (orgJson.two_factor_requirement_enabled === true) return "enforced"
  if (orgJson.two_factor_requirement_enabled === false) return "not-enforced"
  return "unknown"
}

// GitHub secret scanning + push-protection status lives on the repo object's
// security_and_analysis block, which is only returned to principals with admin
// (or for some public repos). Absent block → "unknown" (we genuinely can't see
// it), not "disabled".
async function deriveSecretScanning(
  repoObjP: Promise<RepoObject | null>,
): Promise<SecretScanningState> {
  const repoObj = await repoObjP
  if (!repoObj) return "unknown"
  const sa = repoObj.security_and_analysis
  if (!sa) return "unknown"
  const on =
    sa.secret_scanning?.status === "enabled" ||
    sa.secret_scanning_push_protection?.status === "enabled"
  return on ? "enabled" : "disabled"
}

// Default GITHUB_TOKEN permission for workflows. "read" is least-privilege;
// "write" means every workflow starts with write access to the repo. Needs
// admin on the repo's Actions settings → "unknown" otherwise.
async function fetchWorkflowPermissions(
  owner: string,
  repo: string,
  token: string | null,
): Promise<WorkflowPermState> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/actions/permissions/workflow`,
    {
      headers: buildGitHubHeaders(token, "application/vnd.github+json"),
      cache: "no-store",
    },
  )
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    return "unknown"
  }
  const j = (await res.json()) as { default_workflow_permissions?: string }
  if (j.default_workflow_permissions === "read") return "read"
  if (j.default_workflow_permissions === "write") return "write"
  return "unknown"
}

// Markers that a workflow signs releases / emits build provenance.
const PROVENANCE_MARKERS =
  /attest-build-provenance|provenance:\s*true|--provenance|cosign\s+sign|sigstore|slsa-github-generator|attestations:\s*write/i

// Release integrity: does any workflow publish provenance / sign releases?
// No workflows directory → "unknown" (nothing to assess). Workflows exist but
// none sign → "absent" (an actionable gap). Bounded to 8 workflow fetches.
async function fetchReleaseProvenance(
  owner: string,
  repo: string,
  token: string | null,
): Promise<ReleaseProvenanceState> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/.github/workflows`,
    {
      headers: buildGitHubHeaders(token, "application/vnd.github+json"),
      cache: "no-store",
    },
  )
  if (res.status === 404) return "unknown"
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    return "unknown"
  }
  const list = (await res.json()) as Array<{ name: string; path: string; type: string }>
  if (!Array.isArray(list)) return "unknown"
  const ymls = list
    .filter((f) => f.type === "file" && /\.ya?ml$/i.test(f.name))
    .slice(0, 8)
  if (ymls.length === 0) return "unknown"
  const contents = await Promise.all(
    ymls.map((f) => fetchRepoFile(owner, repo, f.path, token)),
  )
  for (const c of contents) {
    if (c && PROVENANCE_MARKERS.test(c)) return "present"
  }
  return "absent"
}

async function softFail<T>(
  p: Promise<T>,
  fallback: T,
  degradedFlag: { value: boolean },
): Promise<T> {
  try {
    return await p
  } catch (err) {
    if (err instanceof GitHubRateLimitError) throw err
    degradedFlag.value = true
    return fallback
  }
}

function gradeFromScore(score: number): PostureGrade {
  if (score >= 90) return "A"
  if (score >= 75) return "B"
  if (score >= 60) return "C"
  if (score >= 40) return "D"
  return "F"
}

function readmeMentionsSecurity(readme: string): boolean {
  if (/security/i.test(readme)) return true
  if (/SECURITY\.md/i.test(readme)) return true
  return false
}

function gitignoreCoversBasics(content: string): boolean {
  const lines = content.split(/\r?\n/).map((l) => l.trim())
  const hasNodeModules = lines.some(
    (l) => /^\/?node_modules\/?$/.test(l) || /^\/?node_modules\b/.test(l),
  )
  const hasEnv = lines.some(
    (l) => /^\/?\.env(\..*)?$/.test(l) || /^\/?\.env\b/.test(l),
  )
  return hasNodeModules && hasEnv
}

export function computeScore(raw: RawSignals): PostureResult {
  const readme = raw.readmeContent ?? ""
  const readmeSubstantial = readme.length >= 500
  const readmeSecurity = readme.length > 0 && readmeMentionsSecurity(readme)
  const gitignoreOk =
    raw.gitignoreContent !== null && gitignoreCoversBasics(raw.gitignoreContent)

  // Branch sub-signals: only meaningful when branchProtected=true. When
  // protected but details are unknown (no admin), mark as `unknown`. When
  // not protected, signals are simply unsatisfied (0 earned, not unknown).
  // Union per signal: classic OR ruleset (briefing decision 1).
  // Ruleset signals are readable without admin scope, so they often resolve
  // sub-signals that the classic /protection endpoint refuses to disclose.
  const rs = raw.rulesetSignals
  const classicPrRequired = raw.branchProtectionDetails?.prRequired ?? false
  const classicStatusChecksRequired =
    raw.branchProtectionDetails?.statusChecksRequired ?? false
  const classicEnforceAdmins =
    raw.branchProtectionDetails?.enforceAdmins ?? false

  const prRequired = classicPrRequired || (rs?.prRequired ?? false)
  const statusChecksRequired =
    classicStatusChecksRequired || (rs?.statusChecksRequired ?? false)
  // Admin enforcement: classic has explicit enforce_admins; ruleset proxy is
  // "no bypass actors at all". Decision 2 (bypass-as-finding) targets OTHER
  // signals - this one IS the meta-signal about bypass, so empty-bypass is
  // the natural mapping. Visibility unknown => ruleset cannot satisfy this
  // signal alone (falls back to classic).
  const rulesetEnforceAdmins = rs?.noBypassActors === true
  const enforceAdmins = classicEnforceAdmins || rulesetEnforceAdmins

  // Sub-signals are unknown only when BOTH classic details and ruleset signals
  // are unavailable - if either source resolved them, we have an answer
  // (negative results from a readable source still count as "known").
  const detailsUnknown =
    raw.branchProtected &&
    raw.branchProtectionDetails === null &&
    rs === null

  // Branch protection is satisfied if either source flagged it. GitHub's
  // /branches endpoint usually sets protected=true for ruleset-covered branches,
  // but if rules/branches returned active rules we are authoritative regardless.
  const branchProtected = raw.branchProtected || rs !== null

  const branchSignals: PostureSignal[] = [
    {
      id: "branch-protection",
      category: "branch",
      label: "Branch protection enabled on main",
      pointsEarned: branchProtected ? W.branchProtection : 0,
      pointsMax: W.branchProtection,
      satisfied: branchProtected,
    },
    {
      id: "branch-pr-required",
      category: "branch",
      label: "Pull request review required",
      pointsEarned: prRequired ? W.branchPrRequired : 0,
      pointsMax: W.branchPrRequired,
      satisfied: prRequired,
      unknown: detailsUnknown,
    },
    {
      id: "branch-status-checks",
      category: "branch",
      label: "Status checks required before merge",
      pointsEarned: statusChecksRequired ? W.branchStatusChecks : 0,
      pointsMax: W.branchStatusChecks,
      satisfied: statusChecksRequired,
      unknown: detailsUnknown,
    },
    {
      id: "branch-enforce-admins",
      category: "branch",
      label: "Branch protection applied to admins",
      pointsEarned: enforceAdmins ? W.branchEnforceAdmins : 0,
      pointsMax: W.branchEnforceAdmins,
      satisfied: enforceAdmins,
      unknown: detailsUnknown,
    },
  ]

  const docSignals: PostureSignal[] = [
    {
      id: "security-md",
      category: "docs",
      label: "SECURITY.md present",
      pointsEarned: raw.hasSecurityMd ? W.securityMd : 0,
      pointsMax: W.securityMd,
      satisfied: raw.hasSecurityMd,
    },
    {
      id: "license",
      category: "docs",
      label: "LICENSE file present",
      pointsEarned: raw.hasLicense ? W.license : 0,
      pointsMax: W.license,
      satisfied: raw.hasLicense,
    },
    {
      id: "codeowners",
      category: "docs",
      label: "CODEOWNERS file present",
      pointsEarned: raw.hasCodeowners ? W.codeowners : 0,
      pointsMax: W.codeowners,
      satisfied: raw.hasCodeowners,
    },
    {
      id: "readme-substantial",
      category: "docs",
      label: "README is substantial (>= 500 chars)",
      pointsEarned: readmeSubstantial ? W.readmeSubstantial : 0,
      pointsMax: W.readmeSubstantial,
      satisfied: readmeSubstantial,
    },
    {
      id: "readme-mentions-security",
      category: "docs",
      label: "README mentions security or SECURITY.md",
      pointsEarned: readmeSecurity ? W.readmeMentionsSecurity : 0,
      pointsMax: W.readmeMentionsSecurity,
      satisfied: readmeSecurity,
    },
  ]

  const depSignals: PostureSignal[] = [
    {
      id: "auto-updates",
      category: "deps",
      label: "Dependabot or Renovate configured",
      pointsEarned: raw.hasDependabotOrRenovate ? W.autoUpdates : 0,
      pointsMax: W.autoUpdates,
      satisfied: raw.hasDependabotOrRenovate,
    },
    {
      id: "lockfile",
      category: "deps",
      label: "Lockfile committed",
      pointsEarned: raw.hasLockfile ? W.lockfile : 0,
      pointsMax: W.lockfile,
      satisfied: raw.hasLockfile,
    },
    {
      id: "gitignore-basics",
      category: "deps",
      label: ".gitignore covers node_modules and .env",
      pointsEarned: gitignoreOk ? W.gitignoreBasics : 0,
      pointsMax: W.gitignoreBasics,
      satisfied: gitignoreOk,
    },
  ]

  // Signed commits: full points if >= 80% verified, half if >= 50%, else 0.
  // null ratio (could not assess) => unknown signal, 0 earned, not a quick win.
  let signedEarned = 0
  let signedSatisfied = false
  let signedUnknown = false
  // Decision 1 (union): ruleset enforcement is a config-level path to this
  // signal - the rule guarantees future commits are signed regardless of the
  // historical ratio. The behaviour-based path (signedCommitsRatio) remains
  // the fallback when no ruleset enforces required_signatures.
  const rulesetEnforcesSigned = rs?.signedCommitsRequired === true
  if (rulesetEnforcesSigned) {
    signedEarned = W.signedCommits
    signedSatisfied = true
  } else if (raw.signedCommitsRatio === null) {
    signedUnknown = true
  } else if (raw.signedCommitsRatio >= 0.8) {
    signedEarned = W.signedCommits
    signedSatisfied = true
  } else if (raw.signedCommitsRatio >= 0.5) {
    signedEarned = Math.round(W.signedCommits / 2)
  }

  // MFA org: enforced => full points. user-owned repo => N/A (omit from
  // quickWins via unknown=true so it doesn't penalize personal projects).
  // not-enforced => 0 earned, satisfied=false (counts as quick win).
  // unknown => 0 earned, unknown=true (doesn't count as quick win).
  let mfaEarned = 0
  let mfaSatisfied = false
  let mfaUnknown = false
  let mfaLabel = "Two-factor enforcement on the organization"
  if (raw.mfaState === "enforced") {
    mfaEarned = W.mfaOrg
    mfaSatisfied = true
  } else if (raw.mfaState === "na-user-repo") {
    mfaUnknown = true
    mfaLabel = "Two-factor enforcement (N/A - user-owned repo)"
  } else if (raw.mfaState === "unknown") {
    mfaUnknown = true
  }

  const govSignals: PostureSignal[] = [
    {
      id: "signed-commits",
      category: "governance",
      label: "Recent commits are signed (verified)",
      pointsEarned: signedEarned,
      pointsMax: W.signedCommits,
      satisfied: signedSatisfied,
      unknown: signedUnknown,
    },
    {
      id: "mfa-org",
      category: "governance",
      label: mfaLabel,
      pointsEarned: mfaEarned,
      pointsMax: W.mfaOrg,
      satisfied: mfaSatisfied,
      unknown: mfaUnknown,
    },
    {
      id: "secret-scanning",
      category: "governance",
      label: "Secret scanning + push protection enabled",
      pointsEarned: raw.secretScanning === "enabled" ? W.secretScanning : 0,
      pointsMax: W.secretScanning,
      satisfied: raw.secretScanning === "enabled",
      unknown: raw.secretScanning === "unknown",
    },
    {
      id: "workflow-permissions",
      category: "governance",
      label: "Default GITHUB_TOKEN permissions are read-only",
      pointsEarned: raw.workflowPerms === "read" ? W.workflowPermissions : 0,
      pointsMax: W.workflowPermissions,
      satisfied: raw.workflowPerms === "read",
      unknown: raw.workflowPerms === "unknown",
    },
    {
      id: "release-provenance",
      category: "governance",
      label: "Releases are signed / publish build provenance",
      pointsEarned: raw.releaseProvenance === "present" ? W.releaseProvenance : 0,
      pointsMax: W.releaseProvenance,
      satisfied: raw.releaseProvenance === "present",
      unknown: raw.releaseProvenance === "unknown",
    },
  ]

  const sumPoints = (signals: PostureSignal[]) =>
    signals.reduce((acc, s) => acc + s.pointsEarned, 0)
  const sumMax = (signals: PostureSignal[]) =>
    signals.reduce((acc, s) => acc + s.pointsMax, 0)

  const breakdown: PostureCategoryBreakdown[] = [
    {
      id: "branch",
      label: "Branch protection",
      pointsEarned: sumPoints(branchSignals),
      pointsMax: sumMax(branchSignals),
      signals: branchSignals,
    },
    {
      id: "docs",
      label: "Documentation",
      pointsEarned: sumPoints(docSignals),
      pointsMax: sumMax(docSignals),
      signals: docSignals,
    },
    {
      id: "deps",
      label: "Dependency hygiene",
      pointsEarned: sumPoints(depSignals),
      pointsMax: sumMax(depSignals),
      signals: depSignals,
    },
    {
      id: "governance",
      label: "Governance",
      pointsEarned: sumPoints(govSignals),
      pointsMax: sumMax(govSignals),
      signals: govSignals,
    },
  ]

  // Score = percent of *assessable* points earned. Signals we couldn't
  // determine (unknown=true — e.g. admin-only secret-scanning status on a
  // public scan, or N/A signals like MFA on a user repo) are excluded from
  // both numerator and denominator, so they neither penalize nor inflate.
  // This also keeps adding new (often-admin-only) signals from capping every
  // repo below an A. Pre-normalization weights summed to 100, so for a repo
  // with every signal assessable the score is unchanged.
  const allForScore = [...branchSignals, ...docSignals, ...depSignals, ...govSignals]
  const earnedPoints = allForScore.reduce((acc, s) => acc + s.pointsEarned, 0)
  const assessableMax = allForScore
    .filter((s) => !s.unknown)
    .reduce((acc, s) => acc + s.pointsMax, 0)
  const score = assessableMax > 0 ? Math.round((earnedPoints / assessableMax) * 100) : 100
  const grade = gradeFromScore(score)

  // Quick wins: only signals that are unsatisfied AND assessable. Unknown
  // signals are excluded - we can't recommend "fix this" if we don't know
  // whether it's already fixed. Branch protection sub-signals are also
  // suppressed when the parent (branch-protection) is itself unsatisfied:
  // enabling protection is the prerequisite, sub-signals follow naturally.
  const allSignals = [
    ...branchSignals,
    ...docSignals,
    ...depSignals,
    ...govSignals,
  ]
  const branchProtectionUnsatisfied = !branchProtected
  const branchSubSignalIds = new Set([
    "branch-pr-required",
    "branch-status-checks",
    "branch-enforce-admins",
  ])
  const quickWins: QuickWin[] = allSignals
    .filter((s) => !s.satisfied && !s.unknown)
    .filter(
      (s) => !(branchProtectionUnsatisfied && branchSubSignalIds.has(s.id)),
    )
    .sort((a, b) => b.pointsMax - a.pointsMax)
    .slice(0, 5)
    .map((s) => {
      const copy = QUICK_WIN_COPY[s.id] ?? s.label
      return {
        signalId: s.id,
        label: `${copy} (+${s.pointsMax} points)`,
        pointsAvailable: s.pointsMax,
      }
    })

  return {
    score,
    grade,
    breakdown,
    quickWins,
    degraded: raw.degraded,
    bypassFindings: raw.rulesetSignals?.bypassFindings ?? [],
  }
}

export async function assessPosture(
  owner: string,
  repo: string,
  accessToken: string | null,
): Promise<PostureResult> {
  const degradedFlag = { value: false }

  // Both the MFA and secret-scanning signals read off the same repo object.
  // Fetch it once and share the promise so the two signals don't fire two
  // identical GET /repos/{owner}/{repo} calls — meaningful on the
  // unauthenticated 60-req/hr path. Both awaits are handled by softFail, so a
  // rejection here surfaces as a rate-limit error or degrades, never unhandled.
  const repoObjP = fetchRepoObject(owner, repo, accessToken)

  const [
    branch,
    branchProtection,
    securityMd,
    licenseBare,
    licenseMd,
    licenseTxt,
    codeownersRoot,
    codeownersGithub,
    codeownersDocs,
    readme,
    dependabot,
    renovate,
    npmLock,
    yarnLock,
    pnpmLock,
    poetryLock,
    gitignore,
    signedRatio,
    mfaState,
    secretScanning,
    workflowPerms,
    releaseProvenance,
    rulesetSignals,
  ] = await Promise.all([
    softFail(fetchBranch(owner, repo, "main", accessToken), null, degradedFlag),
    softFail(
      fetchBranchProtection(owner, repo, "main", accessToken),
      null,
      degradedFlag,
    ),
    softFail(repoPathExists(owner, repo, "SECURITY.md", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "LICENSE", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "LICENSE.md", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "LICENSE.txt", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "CODEOWNERS", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, ".github/CODEOWNERS", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "docs/CODEOWNERS", accessToken), false, degradedFlag),
    softFail(fetchRepoFile(owner, repo, "README.md", accessToken), null, degradedFlag),
    softFail(repoPathExists(owner, repo, ".github/dependabot.yml", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "renovate.json", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "package-lock.json", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "yarn.lock", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "pnpm-lock.yaml", accessToken), false, degradedFlag),
    softFail(repoPathExists(owner, repo, "poetry.lock", accessToken), false, degradedFlag),
    softFail(fetchRepoFile(owner, repo, ".gitignore", accessToken), null, degradedFlag),
    softFail(fetchSignedCommitsRatio(owner, repo, accessToken), null, degradedFlag),
    softFail(deriveMfaState(repoObjP, accessToken), "unknown" as MfaState, degradedFlag),
    softFail(
      deriveSecretScanning(repoObjP),
      "unknown" as SecretScanningState,
      degradedFlag,
    ),
    softFail(
      fetchWorkflowPermissions(owner, repo, accessToken),
      "unknown" as WorkflowPermState,
      degradedFlag,
    ),
    softFail(
      fetchReleaseProvenance(owner, repo, accessToken),
      "unknown" as ReleaseProvenanceState,
      degradedFlag,
    ),
    softFail(assessRulesetSignals(owner, repo, "main", accessToken), null, degradedFlag),
  ])

  const raw: RawSignals = {
    branchProtected: branch?.protected ?? false,
    branchProtectionDetails: branchProtection,
    hasSecurityMd: securityMd,
    hasLicense: licenseBare || licenseMd || licenseTxt,
    hasCodeowners: codeownersRoot || codeownersGithub || codeownersDocs,
    readmeContent: readme,
    hasDependabotOrRenovate: dependabot || renovate,
    hasLockfile: npmLock || yarnLock || pnpmLock || poetryLock,
    gitignoreContent: gitignore,
    signedCommitsRatio: signedRatio,
    mfaState: mfaState,
    secretScanning,
    workflowPerms,
    releaseProvenance,
    rulesetSignals: rulesetSignals,
    degraded: degradedFlag.value,
  }

  return computeScore(raw)
}
