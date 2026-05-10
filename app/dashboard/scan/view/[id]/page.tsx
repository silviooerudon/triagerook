"use client"

import { useEffect, useState, use } from "react"
import Link from "next/link"
import { AlertTriangleIcon } from "@/app/components/icons"
import type { ScanResult } from "@/lib/scan"
import type { DependencyFinding } from "@/lib/types"
import type { PrioritizedFinding, RiskBreakdown } from "@/lib/risk"
import type { PostureResult } from "@/lib/posture"
import type { IAMResult } from "@/lib/iam"
import type { SupplyChainResult } from "@/lib/supply-chain"
import {
  AllClear,
  CodeFindingsSection,
  DependenciesSection,
  IaCFindingsSection,
  PrioritizedList,
  SecretsSection,
  SensitiveFilesSection,
  SummaryCard,
  countBySeverity,
  totalCount,
  type AllFindings,
} from "@/app/components/scan-findings"
import { RiskGauge } from "@/app/components/risk-gauge"
import { RiskBreakdownChart } from "@/app/components/risk-breakdown"
import { ViewToggleButton } from "@/app/components/view-toggle"
import { PostureCard } from "@/app/components/posture-card"
import { IamCard } from "@/app/components/iam-card"
import { SupplyChainCard } from "@/app/components/supply-chain-card"

type ScanResultFull = ScanResult & {
  dependencies?: DependencyFinding[]
  pythonDependencies?: DependencyFinding[]
}

type SavedScan = {
  id: string
  owner: string
  repo: string
  scanned_at: string
  result: ScanResultFull
  duration_ms: number
  files_scanned: number
  secrets_count: number
  deps_count: number
  riskScore: number | null
  riskBreakdown: RiskBreakdown | null
  prioritized: PrioritizedFinding[] | null
  posture: PostureResult | null
  iam: IAMResult | null
  supplyChain: SupplyChainResult | null
}

type PageProps = {
  params: Promise<{ id: string }>
}

export default function ScanViewPage({ params }: PageProps) {
  const { id } = use(params)

  const [status, setStatus] = useState<"loading" | "done" | "error">("loading")
  const [scan, setScan] = useState<SavedScan | null>(null)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  useEffect(() => {
    async function fetchScan() {
      try {
        const res = await fetch(`/api/scans/${id}`)
        if (!res.ok) {
          const body = await res.json().catch(() => ({}))
          throw new Error(body.error ?? `Failed (${res.status})`)
        }
        const data = await res.json()
        setScan(data.scan)
        setStatus("done")
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : "Unknown error")
        setStatus("error")
      }
    }
    fetchScan()
  }, [id])

  return (
    <main className="min-h-screen bg-gradient-to-b from-slate-950 to-slate-900 text-white px-6 py-12">
      <div className="max-w-5xl mx-auto">
        <div className="flex items-center justify-between mb-10">
          <Link
            href="/dashboard/history"
            className="text-slate-400 hover:text-white text-sm flex items-center gap-1 transition"
          >
            ← Back to history
          </Link>
        </div>

        {status === "loading" && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center">
            <div className="inline-block w-8 h-8 border-4 border-blue-500/30 border-t-blue-500 rounded-full animate-spin mb-4" />
            <p className="text-slate-300">Loading scan…</p>
          </div>
        )}

        {status === "error" && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6">
            <p className="text-red-400 font-semibold mb-1 flex items-center gap-2">
              <AlertTriangleIcon size={16} aria-hidden="true" />
              Failed to load
            </p>
            <p className="text-red-300/80 text-sm">{errorMessage}</p>
          </div>
        )}

        {status === "done" && scan && <SavedScanView scan={scan} />}
      </div>
    </main>
  )
}

function SavedScanView({ scan }: { scan: SavedScan }) {
  const [view, setView] = useState<"prioritized" | "by-detector">("prioritized")

  const dateStr = new Date(scan.scanned_at).toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })

  const all: AllFindings = {
    secrets: (scan.result.findings ?? []).filter(
      (f) => !f.source || f.source === "tree",
    ),
    historySecrets: scan.result.historyFindings ?? [],
    sensitiveFiles: scan.result.sensitiveFiles ?? [],
    codeFindings: scan.result.codeFindings ?? [],
    iacFindings: scan.result.iacFindings ?? [],
    npmDependencies: scan.result.dependencies ?? [],
    pythonDependencies: scan.result.pythonDependencies ?? [],
  }

  const counts = countBySeverity(all)
  const total = totalCount(all)
  const hasRisk =
    typeof scan.riskScore === "number" &&
    !!scan.riskBreakdown &&
    !!scan.prioritized

  const summaryRow = (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      <SummaryCard
        label="Files scanned"
        value={scan.files_scanned.toString()}
        tone="neutral"
      />
      <SummaryCard
        label="Critical"
        value={counts.critical.toString()}
        tone={counts.critical > 0 ? "red" : "neutral"}
      />
      <SummaryCard
        label="High"
        value={counts.high.toString()}
        tone={counts.high > 0 ? "orange" : "neutral"}
      />
      <SummaryCard
        label="Medium + Low"
        value={(counts.medium + counts.low).toString()}
        tone={counts.medium + counts.low > 0 ? "yellow" : "neutral"}
      />
    </div>
  )

  const legacySections = (
    <>
      {total === 0 && <AllClear />}
      <SecretsSection findings={all.secrets} sourceLabel="tree" />
      <SensitiveFilesSection findings={all.sensitiveFiles} />
      <CodeFindingsSection findings={all.codeFindings} />
      <DependenciesSection findings={all.npmDependencies} label="npm" />
      <DependenciesSection findings={all.pythonDependencies} label="Python" />
      <IaCFindingsSection findings={all.iacFindings} />
      <SecretsSection findings={all.historySecrets} sourceLabel="history" />
    </>
  )

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold mb-2">
          <span className="text-blue-400 font-mono">
            {scan.owner}/{scan.repo}
          </span>
        </h1>
        <p className="text-slate-400 text-sm">
          Scanned on {dateStr} • {scan.files_scanned} files •{" "}
          {(scan.duration_ms / 1000).toFixed(2)}s
        </p>
      </div>

      {summaryRow}

      {hasRisk && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col md:flex-row gap-6 items-center md:items-stretch">
          <div className="shrink-0 flex items-center justify-center">
            <RiskGauge score={scan.riskScore!} />
          </div>
          <div className="flex-1 w-full flex flex-col justify-center">
            <h2 className="text-sm uppercase tracking-wider text-slate-500 mb-3">
              Where the score comes from
            </h2>
            <RiskBreakdownChart breakdown={scan.riskBreakdown!} />
            <p className="text-xs text-slate-500 mt-4">
              {scan.prioritized!.length} finding
              {scan.prioritized!.length === 1 ? "" : "s"} ranked by risk.
            </p>
          </div>
        </div>
      )}

      {scan.posture && <PostureCard posture={scan.posture} />}
      {scan.iam && <IamCard iam={scan.iam} />}
      {scan.supplyChain && <SupplyChainCard supplyChain={scan.supplyChain} />}

      {hasRisk ? (
        <>
          <div className="flex items-center gap-2">
            <ViewToggleButton
              active={view === "prioritized"}
              onClick={() => setView("prioritized")}
            >
              Sorted by risk
            </ViewToggleButton>
            <ViewToggleButton
              active={view === "by-detector"}
              onClick={() => setView("by-detector")}
            >
              Group by detector
            </ViewToggleButton>
          </div>

          {view === "prioritized" ? (
            <PrioritizedList findings={scan.prioritized!} />
          ) : (
            legacySections
          )}
        </>
      ) : (
        legacySections
      )}
    </div>
  )
}
