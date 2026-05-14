import { isSafeOwnerRepo, isSafeRepoFilePath } from "@/lib/path-validation"
import { GitHubRateLimitError, GitHubRepoNotFoundError } from "@/lib/scan"
import { runFullScan } from "@/lib/scan-pipeline"
import { checkAndIncrement, PUBLIC_SCAN_POLICY } from "@/lib/rate-limit"
import { NextResponse } from "next/server"

// Best-effort caller IP for rate limiting. Vercel populates
// x-forwarded-for with the real client IP at the edge; we fall back
// to "unknown" so missing headers do not bypass the limit (the
// "unknown" bucket gets rate-limited like any other key).
function getCallerIp(request: Request): string {
  const xff = request.headers.get("x-forwarded-for")
  if (xff) return xff.split(",")[0].trim() || "unknown"
  const realIp = request.headers.get("x-real-ip")
  if (realIp) return realIp
  return "unknown"
}

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
  if (!isSafeOwnerRepo(owner) || !isSafeOwnerRepo(repo)) {
    return NextResponse.json({ error: "Invalid owner or repo format" }, { status: 400 })
  }

  const ip = getCallerIp(request)
  const rl = await checkAndIncrement(ip, PUBLIC_SCAN_POLICY)
  if (!rl.allowed) {
    return NextResponse.json(
      {
        error: `Too many anonymous scans. Try again in ${rl.retryAfterSeconds}s, or sign in for a higher limit.`,
        retryAfterSeconds: rl.retryAfterSeconds,
      },
      {
        status: 429,
        headers: {
          "Retry-After": String(rl.retryAfterSeconds),
          "X-RateLimit-Limit": String(PUBLIC_SCAN_POLICY.limit),
          "X-RateLimit-Remaining": String(rl.remaining),
        },
      },
    )
  }

  let explicitBranch: string | undefined
  let pathPrefix: string | undefined
  try {
    const body = await request.json()
    if (typeof body?.defaultBranch === "string" && body.defaultBranch.length > 0) {
      explicitBranch = body.defaultBranch
    }
    if (typeof body?.pathPrefix === "string" && body.pathPrefix.length > 0) {
      if (!isSafeRepoFilePath(body.pathPrefix)) {
        return NextResponse.json(
          { error: "Invalid pathPrefix format" },
          { status: 400 },
        )
      }
      pathPrefix = body.pathPrefix
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
    } = await runFullScan(null, owner, repo, explicitBranch, {}, pathPrefix)

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
