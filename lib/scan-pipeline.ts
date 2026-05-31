import {
  scanRepo,
  fetchSuppressionsFile,
  type ScanResult,
} from "./scan"
import { scanDependencies } from "./deps"
import { scanPythonDependencies } from "./python-deps"
import { scanGoDependencies } from "./go-deps"
import { scanRubyDependencies } from "./ruby-deps"
import { scanJvmDependencies } from "./jvm-deps"
import { scanPhpDependencies } from "./php-deps"
import { scanContainerVulns } from "./trivy-sarif"
import { scanRegistryLicenses, type DepRef } from "./licenses-registry"
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
import type { DependencyFinding, LicenseFinding, DetectorHealth } from "./types"
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
    // JVM = Maven (pom.xml) + Gradle (build.gradle*); PHP = Composer.
    jvmDependencies: DependencyFinding[]
    phpDependencies: DependencyFinding[]
    // OS-package CVEs ingested from a committed Trivy SARIF report.
    containerDependencies: DependencyFinding[]
    licenseFindings: LicenseFinding[]
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
  jvmVulnsCount: number
  phpVulnsCount: number
  containerVulnsCount: number
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
  // When true, this scan path permits secret liveness validation (it still
  // ANDs with the deployment-level ENABLE_SECRET_VALIDATION flag). The
  // authenticated route opts in; the anonymous public route leaves it false so
  // validation never fires third-party calls with arbitrary repos' secrets.
  allowSecretValidation?: boolean
}

// Map a dependency scanner's parsed deps into the license scanner's DepRef
// shape, tagging the ecosystem. The per-ecosystem `source` literals
// (requirements.txt / go.mod / Gemfile.lock / …) are all members of
// DependencyFinding["source"], so they widen cleanly into DepRef["source"].
function toRegistryDeps(
  deps: { name: string; version: string; source: NonNullable<DependencyFinding["source"]> }[],
  ecosystem: DepRef["ecosystem"],
): DepRef[] {
  return deps.map((d) => ({ name: d.name, version: d.version, ecosystem, source: d.source }))
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
  // PyPI/Go/Ruby license enrichment via deps.dev reuses the deps the three
  // dependency scanners already parsed (no manifest re-fetch). It chains off
  // ONLY those three promises — not the whole batch — so its deps.dev fan-out
  // overlaps scanRepo/posture/IAM instead of running serially after them. The
  // `.then` makes the "license scan needs the parsed deps first" ordering
  // structural rather than a comment. (npm licenses come from npmResult, read
  // straight from the lockfile — zero network.)
  const pythonP = scanPythonDependencies(owner, repo, accessToken)
  const goP = scanGoDependencies(owner, repo, accessToken)
  const rubyP = scanRubyDependencies(owner, repo, accessToken)
  const registryLicenseP = Promise.all([pythonP, goP, rubyP]).then(([py, go, ruby]) =>
    scanRegistryLicenses(owner, repo, accessToken, undefined, [
      ...toRegistryDeps(py.parsedDeps, "PyPI"),
      ...toRegistryDeps(go.parsedDeps, "Go"),
      ...toRegistryDeps(ruby.parsedDeps, "RubyGems"),
    ]),
  )

  const [
    secretsResult,
    npmResult,
    pythonResult,
    goResult,
    rubyResult,
    jvmResult,
    phpResult,
    containerResult,
    postureResult,
    iamResult,
    supplyChainResult,
    registryLicenseResult,
  ] = await Promise.all([
    scanRepo(accessToken, owner, repo, explicitBranch, pathPrefix, {
      validateSecrets: options.allowSecretValidation ?? false,
    }),
    scanDependencies(owner, repo, accessToken),
    pythonP,
    goP,
    rubyP,
    scanJvmDependencies(owner, repo, accessToken),
    scanPhpDependencies(owner, repo, accessToken),
    scanContainerVulns(owner, repo, accessToken),
    assessPosture(owner, repo, accessToken),
    assessIAM(owner, repo, accessToken),
    assessSupplyChain(owner, repo, accessToken, explicitBranch),
    registryLicenseP,
  ])

  const fullResult = {
    ...secretsResult,
    dependencies: npmResult.vulns,
    pythonDependencies: pythonResult.findings,
    goDependencies: goResult.findings,
    rubyDependencies: rubyResult.findings,
    jvmDependencies: jvmResult.findings,
    phpDependencies: phpResult.findings,
    containerDependencies: containerResult.findings,
    licenseFindings: [
      ...npmResult.licenseFindings,
      ...registryLicenseResult.findings,
    ],
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
    ...(jvmResult.degraded ? [jvmResult.degraded] : []),
    ...(phpResult.degraded ? [phpResult.degraded] : []),
    ...(containerResult.degraded ? [containerResult.degraded] : []),
    ...(registryLicenseResult.degraded ? [registryLicenseResult.degraded] : []),
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
    jvmVulnsCount: jvmResult.findings.length,
    phpVulnsCount: phpResult.findings.length,
    containerVulnsCount: containerResult.findings.length,
    degraded: aggregateDegraded.length > 0 ? aggregateDegraded : undefined,
  }
}
