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
      scanRepo(null, owner, repo, explicitBranch),
      scanDependencies(owner, repo, null),
      scanPythonDependencies(owner, repo, null),
      assessPosture(owner, repo, null),
      assessIAM(owner, repo, null),
      assessSupplyChain(owner, repo, null, explicitBranch),
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

    // Best-effort: anonymous scan (no accessToken). Same race window caveat as
    // the authenticated route - see app/api/scan/[owner]/[repo]/route.ts for
    // rationale.
    const suppressionsContent = await fetchSuppressionsFile(
      null,
      owner,
      repo,
      explicitBranch,
    )
    const parsedSuppressions = suppressionsContent
      ? parseSuppressions(suppressionsContent)
      : []
    const suppressionResult = applySuppressions(flatFindings, parsedSuppressions)

    const assessment = scoreRepo(suppressionResult.kept)

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

export async function GET(
  request: Request,
  routeCtx: RouteParams,
) {
  return POST(request, routeCtx)
}
