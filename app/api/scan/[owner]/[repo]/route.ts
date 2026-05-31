import { auth, getAccessToken } from "@/auth"
import { getUserId } from "@/lib/auth-utils"
import { isSafeGitRef, isSafeOwnerRepo, isSafeRepoFilePath } from "@/lib/path-validation"
import {
  assertPublicRepo,
  GitHubRateLimitError,
  GitHubRepoNotFoundError,
  PrivateRepoRefusedError,
} from "@/lib/scan"
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

  const accessToken = await getAccessToken(request)
  if (!accessToken) {
    return NextResponse.json(
      { error: "No access token available. Please sign in again." },
      { status: 401 },
    )
  }

  const { owner, repo } = await params
  if (!isSafeOwnerRepo(owner) || !isSafeOwnerRepo(repo)) {
    return NextResponse.json({ error: "Invalid owner or repo format" }, { status: 400 })
  }

  let explicitBranch: string | undefined
  let pathPrefix: string | undefined
  try {
    const body = await request.json()
    if (typeof body?.defaultBranch === "string" && body.defaultBranch.length > 0) {
      // Validate ref shape before letting it reach GitHub URL paths.
      // Without this, anything that survives the JSON parse would be
      // concatenated into /repos/{owner}/{repo}/git/trees/{ref} — a
      // malicious caller could reshape the URL or hit a different
      // endpoint via path traversal in the ref segment.
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
    // /security promises "we only scan public repositories" — enforce
    // it at the boundary before any GitHub tree/blob fetch runs.
    // Doing this here (instead of inside scanRepo) also gives us the
    // resolved default branch in one round-trip, which scanRepo would
    // otherwise re-fetch when no explicit branch is supplied.
    const { defaultBranch: resolvedBranch } = await assertPublicRepo(
      accessToken,
      owner,
      repo,
    )

    const {
      fullResult,
      assessment,
      suppressionResult,
      postureResult,
      iamResult,
      supplyChainResult,
      npmVulnsCount,
      pythonVulnsCount,
      goVulnsCount,
      rubyVulnsCount,
      jvmVulnsCount,
      phpVulnsCount,
      containerVulnsCount,
      degraded,
    } = await runFullScan(
      accessToken,
      owner,
      repo,
      explicitBranch ?? resolvedBranch,
      { userIdForDbSuppressions: userId, allowSecretValidation: true },
      pathPrefix,
    )

    const { error: dbError } = await supabase.from("scans").insert({
      user_id: userId,
      owner,
      repo,
      result: fullResult,
      duration_ms: fullResult.durationMs,
      files_scanned: fullResult.filesScanned,
      secrets_count: fullResult.findings.length,
      // deps_count is a single rolled-up number across every supported
      // ecosystem (npm + PyPI + Go + RubyGems + Maven + Composer + container
      // OS packages from Trivy SARIF). The per-ecosystem counts aren't
      // persisted separately yet — readers that need a breakdown derive it
      // from prioritized_findings.
      deps_count:
        npmVulnsCount +
        pythonVulnsCount +
        goVulnsCount +
        rubyVulnsCount +
        jvmVulnsCount +
        phpVulnsCount +
        containerVulnsCount,
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
      degraded,
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
    if (error instanceof PrivateRepoRefusedError) {
      return NextResponse.json(
        {
          error: `Repository ${error.owner}/${error.repo} is private. TriageRook only scans public repositories.`,
        },
        { status: 403 },
      )
    }
    // Internal error: log the real message server-side, return a
    // generic one to the client. Echoing raw error text leaked
    // Supabase / GitHub internals in past incident reports.
    const message = error instanceof Error ? error.message : "Unknown error"
    console.error("[scan] Unhandled scan failure:", message)
    return NextResponse.json(
      { error: "Scan failed. Try again in a moment." },
      { status: 500 },
    )
  }
}
