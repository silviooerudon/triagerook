import { GitHubRateLimitError, GitHubRepoNotFoundError } from "@/lib/scan"
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
    } = await runFullScan(null, owner, repo, explicitBranch)

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
          error: "GitHub API rate limit exceeded for anonymous scans.",
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
        { error: `Repository ${error.owner}/${error.repo} not found. It may be private or not exist.` },
        { status: 404 },
      )
    }
    const message = error instanceof Error ? error.message : "Unknown error"
    return NextResponse.json({ error: `Scan failed: ${message}` }, { status: 500 })
  }
}
