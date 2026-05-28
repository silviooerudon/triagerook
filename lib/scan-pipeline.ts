import {
  scanRepo,
  fetchSuppressionsFile,
  type ScanResult,
} from "./scan"
import { scanDependencies } from "./deps"
import { scanPythonDependencies } from "./python-deps"
import { scanGoDependencies } from "./go-deps"
import { scanRubyDependencies } from "./ruby-deps"
import { assessPosture, type PostureResult } from "./posture"
import { assessIAM, type IAMResult } from "./iam"
import { assessSupplyChain, type SupplyChainResult } from "./supply-chain"
import { flattenScan, scoreRepo, type RiskAssessment } from "./risk"
import { buildAttackGraph } from "./attack-graph"
import {
  parseSuppressions,
  applySuppressions,
  type Suppression,
  type SuppressionResult,
} from "./suppressions"
import type { DependencyFinding, DetectorHealth } from "./types"
import { listSuppressions, toRuntimeSuppression } from "./db-suppressions"

// Output shape that's intentionally a superset: callers pick what they need.
// Authenticated route persists most of it to DB; public route returns it
// directly to the client without persistence.
export type FullScanResult = {
  fullResult: ScanResult & {
    dependencies: DependencyFinding[]
    pythonDependencies: DependencyFinding[]
    // New ecosystems live on the same shape so the rest of the
    // pipeline (flattenScan, suppressions, risk) sees a uniform
    // DependencyFinding[] regardless of source. Persisted scans
    // pre-2026-05-15 don't carry these fields — readers must treat
    // them as optional + empty.
    goDependencies: DependencyFinding[]
    rubyDependencies: DependencyFinding[]
  }
  assessment: RiskAssessment
  suppressionResult: SuppressionResult
  postureResult: PostureResult
  iamResult: IAMResult
  supplyChainResult: SupplyChainResult
  npmVulnsCount: number
  pythonVulnsCount: number
  goVulnsCount: number
  rubyVulnsCount: number
  // Aggregated soft-failure markers from every detector that returned an
  // empty result for a known reason (rate limit, registry outage). The
  // UI renders a yellow banner so "0 findings" doesn't look like
  // "actually clean" when half the detectors couldn't run.
  degraded?: DetectorHealth[]
}

// The shared scan orchestration. Used by both:
//   - app/api/scan/[owner]/[repo]/route.ts (authenticated, persists to DB)
//   - app/api/scan-public/[owner]/[repo]/route.ts (anonymous, no persist)
//
// Pre-refactor these two routes were 90% byte-identical and diverged
// silently — scan-public was missing all the migration-006 persistence
// fields and never caught up. Centralizing the orchestration here means
// new detector outputs reach both routes without touching either.
//
// Throws GitHubRateLimitError and GitHubRepoNotFoundError up to the
// caller so the caller can choose error copy (authenticated vs anonymous
// rate-limit messaging differs).
export type RunFullScanOptions = {
  // When provided, dashboard-created (DB) suppressions for this user
  // are loaded and unioned with the in-repo .repoguardignore. The public
  // scan path passes null and only consumes the file source.
  userIdForDbSuppressions?: string | null
}

export async function runFullScan(
  accessToken: string | null,
  owner: string,
  repo: string,
  explicitBranch?: string,
  options: RunFullScanOptions = {},
  // Optional subfolder narrowing. Validated at the API boundary; the
  // pipeline passes through. Posture/IAM/supply-chain are repo-scoped
  // signals so they ignore the prefix — only the file scan obeys it.
  pathPrefix?: string,
): Promise<FullScanResult> {
  const [
    secretsResult,
    npmResult,
    pythonResult,
    goResult,
    rubyResult,
    postureResult,
    iamResult,
    supplyChainResult,
  ] = await Promise.all([
    scanRepo(accessToken, owner, repo, explicitBranch, pathPrefix),
    scanDependencies(owner, repo, accessToken),
    scanPythonDependencies(owner, repo, accessToken),
    scanGoDependencies(owner, repo, accessToken),
    scanRubyDependencies(owner, repo, accessToken),
    assessPosture(owner, repo, accessToken),
    assessIAM(owner, repo, accessToken),
    assessSupplyChain(owner, repo, accessToken, explicitBranch),
  ])

  const fullResult = {
    ...secretsResult,
    dependencies: npmResult.vulns,
    pythonDependencies: pythonResult.findings,
    goDependencies: goResult.findings,
    rubyDependencies: rubyResult.findings,
    iacFindings: [
      ...(secretsResult.iacFindings ?? []),
      ...npmResult.lifecycleIssues,
    ],
  }

  // Roll up soft-failure markers from every detector layer so the UI
  // can render a single banner instead of N silent gaps. Order matches
  // how the UI lists detectors in the prioritized view.
  const aggregateDegraded: DetectorHealth[] = [
    ...(secretsResult.degraded ?? []),
    ...(npmResult.degraded ?? []),
    ...(pythonResult.degraded ? [pythonResult.degraded] : []),
    ...(goResult.degraded ? [goResult.degraded] : []),
    ...(rubyResult.degraded ? [rubyResult.degraded] : []),
  ]

  const flatFindings = flattenScan(fullResult)

  // Best-effort: if explicitBranch is undefined, GitHub Contents API
  // resolves to default branch independently of scanRepo's resolution.
  // Tiny race window is acceptable for MVP - worst case is suppressions
  // from a slightly different commit, which only affects which findings
  // get filtered (no security risk). Backlog: thread commit SHA through
  // ScanResult to eliminate the race.
  const [suppressionsContent, dbSuppressions] = await Promise.all([
    fetchSuppressionsFile(accessToken, owner, repo, explicitBranch),
    options.userIdForDbSuppressions
      ? listSuppressions(options.userIdForDbSuppressions, owner, repo).catch((err) => {
          console.warn(
            "[scan-pipeline] listSuppressions failed; proceeding without DB suppressions:",
            err instanceof Error ? err.message : String(err),
          )
          return []
        })
      : Promise.resolve([]),
  ])
  const fileSuppressions = suppressionsContent
    ? parseSuppressions(suppressionsContent)
    : []
  const runtimeDbSuppressions: Suppression[] = dbSuppressions.map((row, i) =>
    toRuntimeSuppression(row, i),
  )
  const parsedSuppressions = [...fileSuppressions, ...runtimeDbSuppressions]
  const suppressionResult = applySuppressions(flatFindings, parsedSuppressions)

  const assessment = scoreRepo(suppressionResult.kept)

  // Blast-radius / attack-path correlation over the kept (non-suppressed)
  // findings. Pure, no I/O. Attached to fullResult so it persists + returns
  // alongside everything else.
  fullResult.attackGraph = buildAttackGraph(suppressionResult.kept)

  return {
    fullResult,
    assessment,
    suppressionResult,
    postureResult,
    iamResult,
    supplyChainResult,
    npmVulnsCount: npmResult.vulns.length,
    pythonVulnsCount: pythonResult.findings.length,
    goVulnsCount: goResult.findings.length,
    rubyVulnsCount: rubyResult.findings.length,
    degraded: aggregateDegraded.length > 0 ? aggregateDegraded : undefined,
  }
}
