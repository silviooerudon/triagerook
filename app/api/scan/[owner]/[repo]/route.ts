import { auth } from "@/auth"
import { getUserId } from "@/lib/auth-utils"
import { GitHubRateLimitError, GitHubRepoNotFoundError } from "@/lib/scan"
import { supabase } from "@/lib/supabase"
import { runFullScan } from "@/lib/scan-pipeline"
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
  const userId = getUserId(session)
  if (!userId || !session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const accessToken = session.accessToken
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
    const {
      fullResult,
      assessment,
      suppressionResult,
      postureResult,
      iamResult,
      supplyChainResult,
      npmVulnsCount,
      pythonVulnsCount,
    } = await runFullScan(accessToken, owner, repo, explicitBranch)

    const { error: dbError } = await supabase.from("scans").insert({
      user_id: userId,
      owner,
      repo,
      result: fullResult,
      duration_ms: fullResult.durationMs,
      files_scanned: fullResult.filesScanned,
      secrets_count: fullResult.findings.length,
      deps_count: npmVulnsCount + pythonVulnsCount,
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
