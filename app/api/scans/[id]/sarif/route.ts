import { auth } from "@/auth"
import { supabase } from "@/lib/supabase"
import { getUserId } from "@/lib/auth-utils"
import { flattenScan, type AnyFinding, type PrioritizedFinding } from "@/lib/risk"
import { scanToSarif } from "@/lib/sarif"
import { NextResponse } from "next/server"

export const dynamic = "force-dynamic"

type RouteParams = {
  params: Promise<{ id: string }>
}

type ScanRow = {
  owner: string
  repo: string
  scanned_at: string
  user_id: string
  result: Parameters<typeof flattenScan>[0] | null
  prioritized_findings: PrioritizedFinding[] | null
  risk_score: number | null
}

export async function GET(_request: Request, { params }: RouteParams) {
  const session = await auth()
  const userId = getUserId(session)
  if (!userId) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const { id } = await params

  const { data, error } = await supabase
    .from("scans")
    .select("owner, repo, scanned_at, user_id, result, prioritized_findings, risk_score")
    .eq("id", id)
    .single<ScanRow>()

  if (error || !data) {
    return NextResponse.json({ error: "Scan not found" }, { status: 404 })
  }
  if (data.user_id !== userId) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 })
  }

  // Prefer the persisted prioritized list (migration 006 onwards); fall
  // back to re-flattening the raw result for legacy rows. Either way we
  // strip the score wrapper from PrioritizedFinding to get plain
  // AnyFinding before handing to the SARIF mapper, since SARIF doesn't
  // care about our internal score.
  let findings: AnyFinding[]
  if (data.prioritized_findings && Array.isArray(data.prioritized_findings)) {
    findings = data.prioritized_findings.map(
      ({ kind, data: d }) => ({ kind, data: d } as AnyFinding),
    )
  } else if (data.result) {
    findings = flattenScan(data.result)
  } else {
    findings = []
  }

  const sarif = scanToSarif({
    owner: data.owner,
    repo: data.repo,
    scannedAt: data.scanned_at,
    riskScore: data.risk_score,
    findings,
  })

  // Friendly default filename for browser download via the button: SARIF
  // tools (GitHub Code Scanning, Defender) typically expect `.sarif` or
  // `.sarif.json`.
  const filename = `repoguard-${data.owner}-${data.repo}-${id.slice(0, 8)}.sarif.json`

  return new NextResponse(JSON.stringify(sarif, null, 2), {
    status: 200,
    headers: {
      "Content-Type": "application/sarif+json",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Cache-Control": "no-store",
    },
  })
}
