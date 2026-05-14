import {
  scanRepo,
  fetchSuppressionsFile,
  type ScanResult,
} from "./scan"
import { scanDependencies } from "./deps"
import { scanPythonDependencies } from "./python-deps"
import { assessPosture, type PostureResult } from "./posture"
import { assessIAM, type IAMResult } from "./iam"
import { assessSupplyChain, type SupplyChainResult } from "./supply-chain"
import { flattenScan, scoreRepo, type RiskAssessment } from "./risk"
import {
  parseSuppressions,
  applySuppressions,
  type Suppression,
  type SuppressionResult,
} from "./suppressions"
import type { DependencyFinding } from "./types"
import { listSuppressions, toRuntimeSuppression } from "./db-suppressions"

// Output shape that's intentionally a superset: callers pick what they need.
// Authenticated route persists most of it to DB; public route returns it
// directly to the client without persistence.
export type FullScanResult = {
  fullResult: ScanResult & {
    dependencies: DependencyFinding[]
    pythonDependencies: DependencyFinding[]
  }
  assessment: RiskAssessment
  suppressionResult: SuppressionResult
  postureResult: PostureResult
  iamResult: IAMResult
  supplyChainResult: SupplyChainResult
  npmVulnsCount: number
  pythonVulnsCount: number
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
    pythonDeps,
    postureResult,
    iamResult,
    supplyChainResult,
  ] = await Promise.all([
    scanRepo(accessToken, owner, repo, explicitBranch, pathPrefix),
    scanDependencies(owner, repo, accessToken),
    scanPythonDependencies(owner, repo, accessToken),
    assessPosture(owner, repo, accessToken),
    assessIAM(owner, repo, accessToken),
    assessSupplyChain(owner, repo, accessToken, explicitBranch),
  ])

  const fullResult = {
    ...secretsResult,
    dependencies: npmResult.vulns,
    pythonDependencies: pythonDeps,
    iacFindings: [
      ...(secretsResult.iacFindings ?? []),
      ...npmResult.lifecycleIssues,
    ],
  }

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

  return {
    fullResult,
    assessment,
    suppressionResult,
    postureResult,
    iamResult,
    supplyChainResult,
    npmVulnsCount: npmResult.vulns.length,
    pythonVulnsCount: pythonDeps.length,
  }
}
