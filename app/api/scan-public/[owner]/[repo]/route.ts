import { isSafeGitRef, isSafeOwnerRepo, isSafeRepoFilePath } from "@/lib/path-validation"
import { GitHubRateLimitError, GitHubRepoNotFoundError } from "@/lib/scan"
import { runFullScan } from "@/lib/scan-pipeline"
import {
  checkAndIncrement,
  PUBLIC_SCAN_POLICY,
  PUBLIC_SCAN_PER_REPO_POLICY,
} from "@/lib/rate-limit"
import { scanToSarif, TRIAGEROOK_INFO_URI } from "@/lib/sarif"
import { resolveCatalogEntry, ruleIdToSlug } from "@/lib/rule-catalog"
import { getPublicScanFallbackToken } from "@/lib/public-scan-token"
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

  // ?format=sarif switches the response from the rich UI-shaped JSON
  // to a SARIF 2.1.0 document with `application/sarif+json` content
  // type. This is what lets the bundled GitHub Actions workflow pipe
  // the result straight into `github/codeql-action/upload-sarif`
  // without any client-side conversion step.
  const url = new URL(request.url)
  const wantsSarif = url.searchParams.get("format") === "sarif"

  const startedAt = Date.now()
  // Fall back to the server-side PAT when present. Lifts the effective
  // GitHub quota for anonymous scans from 60/h shared to 5000/h shared,
  // which is the difference between "survives Show HN" and "stops
  // responding to anonymous visitors at the first surge". If the env
  // var is unset, scanToken stays null and behaviour is unchanged.
  const scanToken = getPublicScanFallbackToken()

  try {
    const {
      fullResult,
      assessment,
      suppressionResult,
      postureResult,
      iamResult,
      supplyChainResult,
      degraded,
    } = await runFullScan(scanToken, owner, repo, explicitBranch, {}, pathPrefix)

    logScanEvent({
      ok: true,
      owner,
      repo,
      pathPrefix,
      format: wantsSarif ? "sarif" : "json",
      withFallbackToken: scanToken !== null,
      durationMs: Date.now() - startedAt,
      findings: assessment.prioritized.length,
      riskScore: assessment.score,
      degradedCount: degraded?.length ?? 0,
    })

    if (wantsSarif) {
      const sarif = scanToSarif({
        owner,
        repo,
        scannedAt: fullResult.scannedAt,
        riskScore: assessment.score,
        // Use the suppressionResult.kept list so SARIF reflects the
        // same set of findings the UI shows — `.repoguardignore`
        // suppressions are honored here too.
        findings: suppressionResult.kept,
        getHelpUri: (sarifRuleId) => {
          const entry = resolveCatalogEntry(sarifRuleId)
          if (!entry) return undefined
          return `${TRIAGEROOK_INFO_URI}/docs/rules/${ruleIdToSlug(entry.id)}`
        },
      })
      const filename = `triagerook-${owner}-${repo}.sarif.json`
      return new NextResponse(JSON.stringify(sarif, null, 2), {
        status: 200,
        headers: {
          "Content-Type": "application/sarif+json",
          "Content-Disposition": `attachment; filename="${filename}"`,
          "Cache-Control": "no-store",
        },
      })
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
    const durationMs = Date.now() - startedAt
    if (error instanceof GitHubRateLimitError) {
      logScanEvent({
        ok: false,
        owner,
        repo,
        pathPrefix,
        format: wantsSarif ? "sarif" : "json",
        withFallbackToken: scanToken !== null,
        durationMs,
        reason: "github_rate_limit",
      })
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
      logScanEvent({
        ok: false,
        owner,
        repo,
        pathPrefix,
        format: wantsSarif ? "sarif" : "json",
        withFallbackToken: scanToken !== null,
        durationMs,
        reason: "repo_not_found",
      })
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
    logScanEvent({
      ok: false,
      owner,
      repo,
      pathPrefix,
      format: wantsSarif ? "sarif" : "json",
      withFallbackToken: scanToken !== null,
      durationMs,
      reason: "internal",
    })
    return NextResponse.json(
      { error: "Scan failed. Try again in a moment." },
      { status: 500 },
    )
  }
}

// One JSON line per public-scan attempt, written to stdout so Vercel's
// runtime logs capture it. The schema is tight on purpose: easy to
// grep, easy to pipe through `jq` or paste into the manual queries in
// docs/analytics-queries.md. Does NOT include the caller IP or any
// other PII — owner/repo and outcome are enough for spike analysis
// without storing personal data.
type ScanEvent =
  | {
      ok: true
      owner: string
      repo: string
      pathPrefix?: string
      format: "json" | "sarif"
      withFallbackToken: boolean
      durationMs: number
      findings: number
      riskScore: number
      degradedCount: number
    }
  | {
      ok: false
      owner: string
      repo: string
      pathPrefix?: string
      format: "json" | "sarif"
      withFallbackToken: boolean
      durationMs: number
      reason: "github_rate_limit" | "repo_not_found" | "internal"
    }

function logScanEvent(event: ScanEvent): void {
  try {
    console.log(
      JSON.stringify({
        event: "scan_public",
        ts: new Date().toISOString(),
        ...event,
      }),
    )
  } catch {
    // logging must never break the request flow
  }
}
