import { isSafeGitRef, isSafeOwnerRepo, isSafeRepoFilePath } from "@/lib/path-validation"
import { GitHubRateLimitError, GitHubRepoNotFoundError } from "@/lib/scan"
import { runFullScan } from "@/lib/scan-pipeline"
import {
  checkAndIncrement,
  PUBLIC_SCAN_POLICY,
  PUBLIC_SCAN_PER_REPO_POLICY,
} from "@/lib/rate-limit"
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

  // Two-axis throttle for anonymous scans: per-IP catches the common
  // "one user clicks too much" case; per-repo stops "rotate the IP to
  // keep hammering the same target" abuse. Both fail closed: if
  // Supabase is unreachable, the scan would fail downstream anyway, so
  // refusing here is the honest behaviour rather than silently
  // dropping the limit.
  const ip = getCallerIp(request)
  const ipRl = await checkAndIncrement(ip, PUBLIC_SCAN_POLICY, {
    failClosed: true,
  })
  if (!ipRl.allowed) {
    return NextResponse.json(
      {
        error: `Too many anonymous scans. Try again in ${ipRl.retryAfterSeconds}s, or sign in for a higher limit.`,
        retryAfterSeconds: ipRl.retryAfterSeconds,
      },
      {
        status: 429,
        headers: {
          "Retry-After": String(ipRl.retryAfterSeconds),
          "X-RateLimit-Limit": String(PUBLIC_SCAN_POLICY.limit),
          "X-RateLimit-Remaining": String(ipRl.remaining),
        },
      },
    )
  }

  const repoKey = `repo:${owner.toLowerCase()}/${repo.toLowerCase()}`
  const repoRl = await checkAndIncrement(repoKey, PUBLIC_SCAN_PER_REPO_POLICY, {
    failClosed: true,
  })
  if (!repoRl.allowed) {
    return NextResponse.json(
      {
        error: `This repo has been scanned too many times this hour. Try again in ${repoRl.retryAfterSeconds}s, or sign in to scan with your own GitHub quota.`,
        retryAfterSeconds: repoRl.retryAfterSeconds,
      },
      {
        status: 429,
        headers: {
          "Retry-After": String(repoRl.retryAfterSeconds),
          "X-RateLimit-Limit": String(PUBLIC_SCAN_PER_REPO_POLICY.limit),
          "X-RateLimit-Remaining": String(repoRl.remaining),
        },
      },
    )
  }

  let explicitBranch: string | undefined
  let pathPrefix: string | undefined
  try {
    const body = await request.json()
    if (typeof body?.defaultBranch === "string" && body.defaultBranch.length > 0) {
      if (!isSafeGitRef(body.defaultBranch)) {
        return NextResponse.json(
          { error: "Invalid defaultBranch format" },
          { status: 400 },
        )
      }
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
      degraded,
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
      degraded,
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
    // Log the real message server-side; return a generic message to
    // the caller so internal Supabase/GitHub error text isn't echoed
    // to an anonymous client.
    const message = error instanceof Error ? error.message : "Unknown error"
    console.error("[scan-public] Unhandled scan failure:", message)
    return NextResponse.json(
      { error: "Scan failed. Try again in a moment." },
      { status: 500 },
    )
  }
}
