import { auth } from "@/auth"
import {
  scanRepo,
  GitHubRateLimitError,
  GitHubRepoNotFoundError,
  fetchSuppressionsFile,
} from "@/lib/scan"
import { scanDependencies } from "@/lib/deps"
import { scanPythonDependencies } from "@/lib/python-deps"
import { assessPosture } from "@/lib/posture"
import { assessIAM } from "@/lib/iam"
import { assessSupplyChain } from "@/lib/supply-chain"
import { supabase } from "@/lib/supabase"
import { flattenScan, scoreRepo } from "@/lib/risk"
import { parseSuppressions, applySuppressions } from "@/lib/suppressions"
import { NextResponse } from "next/server"

type RouteParams = {
  params: Promise<{
    owner: string
    repo: string
  }>
}

export async function POST(
  request: Request,
  { params }: RouteParams
) {
  const session = await auth()
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  // @ts-expect-error - accessToken custom field
  const accessToken = session.accessToken as string | undefined
  if (!accessToken) {
    return NextResponse.json(
      { error: "No access token available. Please sign in again." },
      { status: 401 },
    )
  }

  const { owner, repo } = await params

  let explicitBranch: string | undefined
  try {
    const body = await request.json()
    if (typeof body?.defaultBranch === "string" && body.defaultBranch.length > 0) {
      explicitBranch = body.defaultBranch
    }
  } catch {
    // no body - scanRepo auto-detects
  }

  try {
    const [
      secretsResult,
      npmResult,
      pythonDeps,
      postureResult,
      iamResult,
      supplyChainResult,
    ] = await Promise.all([
      scanRepo(accessToken, owner, repo, explicitBranch),
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

    // Best-effort: if explicitBranch is undefined, GitHub Contents API resolves
    // to default branch independently of scanRepo's resolution. Tiny race window
    // is acceptable for MVP - worst case is suppressions from a slightly different
    // commit, which only affects which findings get filtered (no security risk).
    // Backlog: thread commit SHA through ScanResult to eliminate the race.
    const suppressionsContent = await fetchSuppressionsFile(
      accessToken,
      owner,
      repo,
      explicitBranch,
    )
    const parsedSuppressions = suppressionsContent
      ? parseSuppressions(suppressionsContent)
      : []
    const suppressionResult = applySuppressions(flatFindings, parsedSuppressions)

    const assessment = scoreRepo(suppressionResult.kept)

    const userId = session.user?.name ?? session.user?.email ?? "unknown"
    const { error: dbError } = await supabase.from("scans").insert({
      user_id: userId,
      owner,
      repo,
      result: fullResult,
      duration_ms: secretsResult.durationMs,
      files_scanned: secretsResult.filesScanned,
      secrets_count: secretsResult.findings.length,
      deps_count: npmResult.vulns.length + pythonDeps.length,
      risk_score: assessment.score,
      // Persisted from migration 006 to lock the user-visible breakdown +
      // prioritized list against future rule changes and to make scan-diff
      // a single DB read instead of a re-derive.
      risk_breakdown: assessment.breakdown,
      prioritized_findings: assessment.prioritized,
      suppressed_count: suppressionResult.suppressed.length,
      posture_score: postureResult.score,
      posture_grade: postureResult.grade,
      posture_breakdown: postureResult.breakdown,
      posture_quick_wins: postureResult.quickWins,
      iam_score: iamResult.score,
      iam_level: iamResult.level,
      iam_breakdown: iamResult.breakdown,
      iam_findings: iamResult.findings,
      iam_files_scanned: iamResult.filesScanned,
      supply_chain_score: supplyChainResult.score,
      supply_chain_level: supplyChainResult.level,
      supply_chain_breakdown: supplyChainResult.categories,
      supply_chain_findings: supplyChainResult.findings,
      supply_chain_scanned: supplyChainResult.scanned,
    })

    if (dbError) {
      console.error("[scan] Failed to persist scan:", dbError.message)
    }

    return NextResponse.json({
      ...fullResult,
      riskScore: assessment.score,
      riskBreakdown: assessment.breakdown,
      prioritized: assessment.prioritized,
      suppressed: suppressionResult.suppressed,
      expiredSuppressionsCount: suppressionResult.expiredSuppressionsCount,
      posture: postureResult,
      iam: iamResult,
      supplyChain: supplyChainResult,
    })
  } catch (error) {
    if (error instanceof GitHubRateLimitError) {
      return NextResponse.json(
        {
          error: "GitHub API rate limit exceeded.",
          retryAfterSeconds: error.retryAfterSeconds,
        },
        {
          status: 429,
          headers: { "Retry-After": String(error.retryAfterSeconds) },
        },
      )
    }
    if (error instanceof GitHubRepoNotFoundError) {
      return NextResponse.json(
        { error: `Repository ${error.owner}/${error.repo} not found or inaccessible.` },
        { status: 404 },
      )
    }
    const message = error instanceof Error ? error.message : "Unknown error"
    return NextResponse.json({ error: `Scan failed: ${message}` }, { status: 500 })
  }
}

export async function GET(
  request: Request,
  routeCtx: RouteParams,
) {
  return POST(request, routeCtx)
}
