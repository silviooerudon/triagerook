import { auth } from "@/auth"
import { supabase } from "@/lib/supabase"
import { flattenScan, scoreRepo } from "@/lib/risk"
import type { PrioritizedFinding, RiskBreakdown } from "@/lib/risk"
import { diffScans, type ScanSnapshot } from "@/lib/scan-diff"
import { NextResponse } from "next/server"

const SELECT_COLUMNS = [
  "id",
  "owner",
  "repo",
  "scanned_at",
  "user_id",
  "risk_score",
  "risk_breakdown",
  "prioritized_findings",
  "result",
].join(", ")

type ScanRow = {
  id: string
  owner: string
  repo: string
  scanned_at: string
  user_id: string
  risk_score: number | null
  risk_breakdown: RiskBreakdown | null
  prioritized_findings: PrioritizedFinding[] | null
  result: Parameters<typeof flattenScan>[0] | null
}

function rowToSnapshot(row: ScanRow): ScanSnapshot {
  // Post-migration-006 scans persist breakdown + prioritized; legacy scans
  // are re-derived from the result JSONB so the diff still works for
  // history that predates the migration.
  if (row.risk_breakdown && row.prioritized_findings) {
    return {
      id: row.id,
      scannedAt: row.scanned_at,
      riskScore: row.risk_score,
      riskBreakdown: row.risk_breakdown,
      findings: row.prioritized_findings,
    }
  }
  try {
    if (row.result) {
      const assessment = scoreRepo(flattenScan(row.result))
      return {
        id: row.id,
        scannedAt: row.scanned_at,
        riskScore: assessment.score,
        riskBreakdown: assessment.breakdown,
        findings: assessment.prioritized,
      }
    }
  } catch (err) {
    console.error("[scans/diff] Failed to re-derive legacy scan:", err)
  }
  return {
    id: row.id,
    scannedAt: row.scanned_at,
    riskScore: row.risk_score,
    riskBreakdown: null,
    findings: [],
  }
}

export async function GET(request: Request) {
  const session = await auth()
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }
  const userId = session.user?.name ?? session.user?.email ?? "unknown"

  const url = new URL(request.url)
  const fromId = url.searchParams.get("from")
  const toId = url.searchParams.get("to")
  if (!fromId || !toId) {
    return NextResponse.json(
      { error: "Both `from` and `to` query params are required." },
      { status: 400 },
    )
  }
  if (fromId === toId) {
    return NextResponse.json(
      { error: "`from` and `to` must reference different scans." },
      { status: 400 },
    )
  }

  const { data, error } = await supabase
    .from("scans")
    .select(SELECT_COLUMNS)
    .in("id", [fromId, toId])
    .returns<ScanRow[]>()

  if (error) {
    console.error("[scans/diff] Supabase error:", error.message)
    return NextResponse.json({ error: "Failed to load scans" }, { status: 500 })
  }
  if (!data || data.length !== 2) {
    return NextResponse.json({ error: "One or both scans not found" }, { status: 404 })
  }
  if (data.some((row) => row.user_id !== userId)) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 })
  }

  const [first, second] = data
  if (first.owner !== second.owner || first.repo !== second.repo) {
    return NextResponse.json(
      { error: "Cannot diff scans across different repositories." },
      { status: 400 },
    )
  }

  // Order by scanned_at: the older one becomes `from`, the newer is `to`.
  const ascending = new Date(first.scanned_at) <= new Date(second.scanned_at)
  const fromRow = ascending ? first : second
  const toRow = ascending ? second : first

  // Honor the caller's intent if they explicitly inverted from/to.
  const fromIsRequested = fromRow.id === fromId
  const finalFrom = fromIsRequested ? fromRow : toRow
  const finalTo = fromIsRequested ? toRow : fromRow

  const diff = diffScans(rowToSnapshot(finalFrom), rowToSnapshot(finalTo))

  return NextResponse.json({
    owner: fromRow.owner,
    repo: fromRow.repo,
    diff,
  })
}
