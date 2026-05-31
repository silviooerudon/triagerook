import type {
  SecretFinding,
  CodeFinding,
  IaCFinding,
  SensitiveFileFinding,
  DependencyFinding,
  LicenseFinding,
} from "./types"

export type AnyFinding =
  | { kind: "secret"; data: SecretFinding }
  | { kind: "code"; data: CodeFinding }
  | { kind: "iac"; data: IaCFinding }
  | { kind: "sensitive-file"; data: SensitiveFileFinding }
  | { kind: "dependency"; data: DependencyFinding }
  | { kind: "license"; data: LicenseFinding }

export type PrioritizedFinding = AnyFinding & {
  score: number
}

export type RiskBreakdown = {
  critical: number
  high: number
  medium: number
  low: number
  fixture: number
}

export type RiskAssessment = {
  score: number
  breakdown: RiskBreakdown
  prioritized: PrioritizedFinding[]
}

export const SEVERITY_BASE_POINTS = {
  critical: 40,
  high: 15,
  medium: 5,
  moderate: 5,
  low: 1,
} as const

export const TEST_FIXTURE_MULTIPLIER = 0.1
export const TRANSITIVE_DEP_MULTIPLIER = 0.5
// A dev/test/build-only dependency isn't shipped to runtime, so a vuln in it
// is lower priority than the same vuln in a production dependency.
export const DEV_DEP_MULTIPLIER = 0.4
// A finding in an HTTP-exposed file (route/controller/handler/api) is directly
// reachable by an attacker, so it's higher priority than the same issue in
// internal/util code. A modest boost — reachability raises urgency without
// dwarfing the severity base.
export const PUBLIC_ROUTE_MULTIPLIER = 1.3
export const HISTORY_SECRET_MULTIPLIER = 0.5
// A provider-confirmed live secret is the highest-urgency finding; a rejected
// (revoked/rotated) one barely matters. Applied only when validation ran.
export const ACTIVE_SECRET_MULTIPLIER = 1.5
export const INACTIVE_SECRET_MULTIPLIER = 0.15
export const REPO_SCORE_CAP = 100

// Score (== penalty) is compressed through log10 so large repos don't
// all saturate at the same "100/100 CRITICAL" reading. Without this,
// every repo with > 2 criticals or > 7 highs landed at the cap and the
// dashboard couldn't tell vercel/next.js (1360 critical points) apart
// from a hobby project with 4 criticals (160 points) — both displayed
// as 0/100 health.
//
// Formula:   penalty = clamp(0, 100, round(SCORE_LOG_MULTIPLIER * log10(1 + raw)))
//
// SCORE_LOG_MULTIPLIER = 25 was chosen by sampling the dogfood pass on
// 2026-05-14:
//   raw=0     → penalty 0      (clean repo, health 100, EXCELLENT)
//   raw=25    → penalty 35     (small repo, 1 high + 2 medium, health 65)
//   raw=100   → penalty 50     (mid-sized repo, several issues, health 50)
//   raw=500   → penalty 67     (large repo with active issues, health 33)
//   raw=1000  → penalty 75     (huge mono-repo, health 25)
//   raw≥10000 → penalty 100    (only the very worst cases saturate)
//
// The breakdown chart still shows raw points (`critical: 1360`) so the
// information isn't lost — only the score gauge is compressed.
export const SCORE_LOG_MULTIPLIER = 25

export function compressScore(rawTotal: number): number {
  if (rawTotal <= 0) return 0
  const compressed = Math.round(
    SCORE_LOG_MULTIPLIER * Math.log10(1 + rawTotal),
  )
  return Math.min(REPO_SCORE_CAP, compressed)
}

// Heuristic: is this file an HTTP-exposed entrypoint (route/controller/handler/
// endpoint/api), where a vulnerability is directly reachable by a remote
// attacker? Matches common framework conventions across ecosystems:
//   - Next.js app router: app/**/route.ts, pages/api/**
//   - Express/Nest/Rails/Laravel: routes/, controllers/, handlers/, endpoints/
//   - filename markers: *.controller.*, *.route(s).*, *.handler.*, *.resolver.*
export function isPublicRouteFile(filePath: string): boolean {
  const p = filePath.toLowerCase()
  if (/(^|\/)(routes?|controllers?|handlers?|endpoints?|resolvers?)\//.test(p)) return true
  if (/(^|\/)pages\/api\//.test(p) || /(^|\/)app\/.*\/route\.[tj]sx?$/.test(p)) return true
  if (/\.(controller|route|routes|handler|resolver|endpoint)\.[a-z]+$/.test(p)) return true
  return false
}

export function scoreFinding(finding: AnyFinding): number {
  const sev = finding.data.severity as keyof typeof SEVERITY_BASE_POINTS
  let points = SEVERITY_BASE_POINTS[sev] ?? 0

  if ("likelyTestFixture" in finding.data && finding.data.likelyTestFixture) {
    points *= TEST_FIXTURE_MULTIPLIER
  }

  if (finding.kind === "secret" && finding.data.source === "history") {
    points *= HISTORY_SECRET_MULTIPLIER
  }

  // Secret validation (when it ran) sharply changes priority: a confirmed-live
  // credential is the most urgent thing in any scan, while one the provider
  // rejected is almost certainly already revoked/rotated.
  if (finding.kind === "secret") {
    if (finding.data.validation === "active") points *= ACTIVE_SECRET_MULTIPLIER
    else if (finding.data.validation === "inactive") points *= INACTIVE_SECRET_MULTIPLIER
  }

  if (finding.kind === "dependency" && finding.data.isTransitive) {
    points *= TRANSITIVE_DEP_MULTIPLIER
  }

  // Dev-only dependency: not shipped to runtime, lower priority.
  if (finding.kind === "dependency" && finding.data.isDev) {
    points *= DEV_DEP_MULTIPLIER
  }

  // Reachability: a code finding in an HTTP-exposed file is more urgent than
  // the same issue buried in internal code.
  if (finding.kind === "code" && isPublicRouteFile(finding.data.filePath)) {
    points *= PUBLIC_ROUTE_MULTIPLIER
  }

  // A copyleft obligation flows through transitive deps too, but a transitive
  // license risk is a lower priority to act on than a direct one — mirror the
  // dependency discount so the prioritized list sorts direct deps first.
  if (finding.kind === "license" && finding.data.isTransitive) {
    points *= TRANSITIVE_DEP_MULTIPLIER
  }

  return points
}

export function prioritize(findings: AnyFinding[]): PrioritizedFinding[] {
  return findings
    .map((f) => ({ ...f, score: scoreFinding(f) }))
    .sort((a, b) => b.score - a.score)
}

export function scoreRepo(findings: AnyFinding[]): RiskAssessment {
  const prioritized = prioritize(findings)

  const breakdown: RiskBreakdown = {
    critical: 0, high: 0, medium: 0, low: 0, fixture: 0,
  }

  for (const f of prioritized) {
    const isFixture =
      "likelyTestFixture" in f.data && f.data.likelyTestFixture
    if (isFixture) {
      breakdown.fixture += f.score
      continue
    }
    const sev = f.data.severity
    if (sev === "critical") breakdown.critical += f.score
    else if (sev === "high") breakdown.high += f.score
    else if (sev === "medium" || sev === "moderate") breakdown.medium += f.score
    else if (sev === "low") breakdown.low += f.score
  }

  // Fixtures are reported in `breakdown.fixture` for transparency (so
  // the user can see e.g. "182 fixture findings detected") but DO NOT
  // contribute to the score. Including them produced visibly wrong
  // gauges: a repo with only test-fixture findings would land in
  // "CRITICAL 40+" purely from the fixture bucket — directly
  // contradicting the "Test fixture" tag that promises "this doesn't
  // count." Per-finding multiplier of 0.1 is kept (lib/risk.ts:42) so
  // prioritization still sorts fixtures last within the visible list.
  const total =
    breakdown.critical + breakdown.high + breakdown.medium + breakdown.low

  return {
    score: compressScore(total),
    breakdown,
    prioritized,
  }
}

type ScanLikeShape = {
  findings?: SecretFinding[]
  historyFindings?: SecretFinding[]
  codeFindings?: CodeFinding[]
  iacFindings?: IaCFinding[]
  sensitiveFiles?: SensitiveFileFinding[]
  dependencies?: DependencyFinding[]
  pythonDependencies?: DependencyFinding[]
  goDependencies?: DependencyFinding[]
  rubyDependencies?: DependencyFinding[]
  jvmDependencies?: DependencyFinding[]
  phpDependencies?: DependencyFinding[]
  licenseFindings?: LicenseFinding[]
}

export function flattenScan(scan: ScanLikeShape): AnyFinding[] {
  const out: AnyFinding[] = []
  for (const s of scan.findings ?? []) out.push({ kind: "secret", data: s })
  for (const s of scan.historyFindings ?? []) out.push({ kind: "secret", data: s })
  for (const c of scan.codeFindings ?? []) out.push({ kind: "code", data: c })
  for (const i of scan.iacFindings ?? []) out.push({ kind: "iac", data: i })
  for (const f of scan.sensitiveFiles ?? []) out.push({ kind: "sensitive-file", data: f })
  for (const d of scan.dependencies ?? []) out.push({ kind: "dependency", data: d })
  for (const d of scan.pythonDependencies ?? []) out.push({ kind: "dependency", data: d })
  for (const d of scan.goDependencies ?? []) out.push({ kind: "dependency", data: d })
  for (const d of scan.rubyDependencies ?? []) out.push({ kind: "dependency", data: d })
  for (const d of scan.jvmDependencies ?? []) out.push({ kind: "dependency", data: d })
  for (const d of scan.phpDependencies ?? []) out.push({ kind: "dependency", data: d })
  for (const l of scan.licenseFindings ?? []) out.push({ kind: "license", data: l })
  return out
}
