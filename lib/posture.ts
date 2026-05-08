import { GitHubRateLimitError, parseGitHubRateLimit } from "./scan"

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
} as const

type BranchProtectionDetails = {
  prRequired: boolean
  statusChecksRequired: boolean
  enforceAdmins: boolean
}

type MfaState = "enforced" | "not-enforced" | "na-user-repo" | "unknown"

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
}

function buildGithubHeaders(token: string | null, accept: string): HeadersInit {
  const h: Record<string, string> = { Accept: accept }
  if (token) h.Authorization = `Bearer ${token}`
  return h
}

async function fetchRepoFile(
  owner: string,
  repo: string,
  path: string,
  token: string | null,
): Promise<string | null> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${path}`,
    {
      headers: buildGithubHeaders(token, "application/vnd.github.v3.raw"),
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
    `https://api.github.com/repos/${owner}/${repo}/contents/${path}`,
    {
      headers: buildGithubHeaders(token, "application/vnd.github.v3.json"),
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
    `https://api.github.com/repos/${owner}/${repo}/branches/${branch}`,
    {
      headers: buildGithubHeaders(token, "application/vnd.github+json"),
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
    `https://api.github.com/repos/${owner}/${repo}/branches/${branch}/protection`,
    {
      headers: buildGithubHeaders(token, "application/vnd.github+json"),
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
      headers: buildGithubHeaders(token, "application/vnd.github+json"),
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

// MFA state assessment. User-owned repos => not applicable (signal omitted
// from quickWins). Org repos => requires `read:org` scope to read
// two_factor_requirement_enabled. Non-members of the org or missing scope =>
// "unknown" (signal flagged but not penalized as a quick win).
async function fetchMfaState(
  owner: string,
  repo: string,
  token: string | null,
): Promise<MfaState> {
  const repoRes = await fetch(
    `https://api.github.com/repos/${owner}/${repo}`,
    {
      headers: buildGithubHeaders(token, "application/vnd.github+json"),
      cache: "no-store",
    },
  )
  if (!repoRes.ok) {
    const retry = parseGitHubRateLimit(repoRes)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    return "unknown"
  }
  const repoJson = (await repoRes.json()) as {
    owner?: { type?: string; login?: string }
  }
  const ownerType = repoJson.owner?.type
  const ownerLogin = repoJson.owner?.login
  if (ownerType === "User") return "na-user-repo"
  if (ownerType !== "Organization" || !ownerLogin) return "unknown"

  const orgRes = await fetch(`https://api.github.com/orgs/${ownerLogin}`, {
    headers: buildGithubHeaders(token, "application/vnd.github+json"),
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
  const detailsUnknown =
    raw.branchProtected && raw.branchProtectionDetails === null
  const prRequired = raw.branchProtectionDetails?.prRequired ?? false
  const statusChecksRequired =
    raw.branchProtectionDetails?.statusChecksRequired ?? false
  const enforceAdmins = raw.branchProtectionDetails?.enforceAdmins ?? false

  const branchSignals: PostureSignal[] = [
    {
      id: "branch-protection",
      category: "branch",
      label: "Branch protection enabled on main",
      pointsEarned: raw.branchProtected ? W.branchProtection : 0,
      pointsMax: W.branchProtection,
      satisfied: raw.branchProtected,
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
  if (raw.signedCommitsRatio === null) {
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

  const score = breakdown.reduce((acc, c) => acc + c.pointsEarned, 0)
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
  const branchProtectionUnsatisfied = !raw.branchProtected
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
  }
}

export async function assessPosture(
  owner: string,
  repo: string,
  accessToken: string | null,
): Promise<PostureResult> {
  const degradedFlag = { value: false }

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
    softFail(fetchMfaState(owner, repo, accessToken), "unknown" as MfaState, degradedFlag),
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
    degraded: degradedFlag.value,
  }

  return computeScore(raw)
}
