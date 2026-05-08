import { auth } from "@/auth"
import { supabase } from "@/lib/supabase"
import { flattenScan, scoreRepo } from "@/lib/risk"
import { NextResponse } from "next/server"

type RouteParams = {
  params: Promise<{ id: string }>
}

export async function GET(_request: Request, { params }: RouteParams) {
  // 1. Authentication
  const session = await auth()
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const userId = session.user?.name ?? session.user?.email ?? "unknown"
  const { id } = await params

  // 2. Fetch scan from DB - includes 12 dedicated columns from migrations 003-005
  const { data, error } = await supabase
    .from("scans")
    .select(
      [
        "id",
        "owner",
        "repo",
        "scanned_at",
        "result",
        "duration_ms",
        "files_scanned",
        "secrets_count",
        "deps_count",
        "user_id",
        "risk_score",
        "suppressed_count",
        "posture_score",
        "posture_grade",
        "posture_breakdown",
        "posture_quick_wins",
        "iam_score",
        "iam_level",
        "iam_breakdown",
        "iam_findings",
        "supply_chain_score",
        "supply_chain_level",
        "supply_chain_breakdown",
        "supply_chain_findings",
      ].join(", "),
    )
    .eq("id", id)
    .single<Record<string, unknown>>()

  if (error || !data) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 })
  }

  // 3. Authorization: user can only see own scans
  if (data.user_id !== userId) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 })
  }

  // 4. Re-compute risk breakdown + prioritized list from result JSONB.
  // Note: this re-scores ALL findings in the saved result, including any that
  // were filtered out by .repoguardignore at scan-time (the persisted result
  // JSONB does not record which findings were suppressed). The persisted
  // `risk_score` column reflects post-suppression. We use the recomputed
  // values here for internal consistency between gauge / breakdown /
  // prioritized list. Score may differ slightly from persisted in scans
  // that had active suppressions.
  // Backlog: persist breakdown + prioritized + suppressed in DB to avoid drift.
  let riskScore: number | null = null
  let riskBreakdown: ReturnType<typeof scoreRepo>["breakdown"] | null = null
  let prioritized: ReturnType<typeof scoreRepo>["prioritized"] | null = null
  try {
    const result = (data.result as Parameters<typeof flattenScan>[0]) ?? null
    if (result) {
      const flat = flattenScan(result)
      const assessment = scoreRepo(flat)
      riskScore = assessment.score
      riskBreakdown = assessment.breakdown
      prioritized = assessment.prioritized
    }
  } catch (recomputeErr) {
    console.error("[scans/[id]] Failed to recompute risk:", recomputeErr)
    riskScore =
      typeof data.risk_score === "number" ? data.risk_score : null
  }

  // 5. Reconstruct nested feature objects from dedicated columns.
  // Old scans (pre-Bloco-2) won't have these columns populated => null,
  // which makes the UI omit those cards (decision: show TUDO with N/A
  // implicit via card-level conditional render).
  const posture =
    data.posture_score !== null && data.posture_grade !== null
      ? {
          score: data.posture_score,
          grade: data.posture_grade,
          breakdown: data.posture_breakdown ?? [],
          quickWins: data.posture_quick_wins ?? [],
          // `degraded` flag is not persisted; default to false. Acceptable
          // since historic scans don't surface degraded state in any UI.
          degraded: false,
        }
      : null

  const iam =
    data.iam_score !== null && data.iam_level !== null
      ? {
          score: data.iam_score,
          level: data.iam_level,
          breakdown: data.iam_breakdown ?? [],
          findings: data.iam_findings ?? [],
          // `filesScanned` is not persisted in a dedicated column. The
          // IamCard renders a "across N files" footer; defaulting to 0 is a
          // best-effort approximation for historic scans.
          filesScanned: 0,
        }
      : null

  const supplyChain =
    data.supply_chain_score !== null && data.supply_chain_level !== null
      ? {
          score: data.supply_chain_score,
          level: data.supply_chain_level,
          // The CREATE handler persists `supplyChainResult.categories` into
          // the `supply_chain_breakdown` column. Reconstructing matches.
          categories: data.supply_chain_breakdown ?? [],
          findings: data.supply_chain_findings ?? [],
          // `scanned` counts (packageJsonCount / setupPyCount / etc) are not
          // persisted. Defaulting to zeros surfaces "across 0 manifests" in
          // the card footer, which signals the data is not available without
          // crashing the render.
          scanned: {
            packageJsonCount: 0,
            setupPyCount: 0,
            pyprojectCount: 0,
            depsAnalyzed: 0,
          },
        }
      : null

  // 6. Return reshaped scan without leaking user_id and DB column names
  return NextResponse.json({
    scan: {
      id: data.id,
      owner: data.owner,
      repo: data.repo,
      scanned_at: data.scanned_at,
      result: data.result,
      duration_ms: data.duration_ms,
      files_scanned: data.files_scanned,
      secrets_count: data.secrets_count,
      deps_count: data.deps_count,
      riskScore,
      riskBreakdown,
      prioritized,
      posture,
      iam,
      supplyChain,
    },
  })
}
