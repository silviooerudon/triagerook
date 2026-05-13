"use client"

import { use, useEffect, useState } from "react"
import Link from "next/link"
import { AlertTriangleIcon, CheckIcon } from "@/app/components/icons"
import type { ScanDiff } from "@/lib/scan-diff"
import type { PrioritizedFinding } from "@/lib/risk"

type DiffResponse = {
  owner: string
  repo: string
  diff: ScanDiff
}

type PageProps = {
  params: Promise<{ fromId: string; toId: string }>
}

export default function ScanDiffPage({ params }: PageProps) {
  const { fromId, toId } = use(params)

  const [status, setStatus] = useState<"loading" | "done" | "error">("loading")
  const [data, setData] = useState<DiffResponse | null>(null)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    async function load() {
      try {
        const res = await fetch(
          `/api/scans/diff?from=${encodeURIComponent(fromId)}&to=${encodeURIComponent(toId)}`,
          { signal: controller.signal },
        )
        if (!res.ok) {
          const body = await res.json().catch(() => ({}))
          throw new Error(body.error ?? `Failed (${res.status})`)
        }
        setData(await res.json())
        setStatus("done")
      } catch (err) {
        if (err instanceof Error && err.name === "AbortError") return
        setErrorMessage(err instanceof Error ? err.message : "Unknown error")
        setStatus("error")
      }
    }
    load()
    return () => controller.abort()
  }, [fromId, toId])

  return (
    <main className="px-6 py-12">
      <div className="max-w-5xl mx-auto">
        <Link
          href="/dashboard/history"
          className="inline-flex items-center gap-1 text-xs font-mono text-slate-500 hover:text-amber-400 transition mb-8"
        >
          ← history
        </Link>

        {status === "loading" && (
          <div className="space-y-3">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 h-[140px] animate-pulse" />
            <div className="grid sm:grid-cols-3 gap-3">
              {[0, 1, 2].map((i) => (
                <div
                  key={i}
                  className="bg-slate-900 border border-slate-800 rounded-xl p-5 h-[88px] animate-pulse"
                />
              ))}
            </div>
          </div>
        )}

        {status === "error" && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6">
            <p className="text-red-400 font-semibold mb-1 flex items-center gap-2">
              <AlertTriangleIcon size={16} aria-hidden="true" />
              Failed to load diff
            </p>
            <p className="text-red-300/80 text-sm">{errorMessage}</p>
          </div>
        )}

        {status === "done" && data && <DiffView data={data} />}
      </div>
    </main>
  )
}

function DiffView({ data }: { data: DiffResponse }) {
  const { owner, repo, diff } = data
  const totalNew = diff.newFindings.length
  const totalResolved = diff.resolvedFindings.length
  const totalCarried = diff.carriedFindings.length

  return (
    <>
      <h1 className="text-3xl font-bold mb-1">
        Diff for <span className="font-mono text-amber-400">{owner}/{repo}</span>
      </h1>
      <p className="text-slate-400 text-sm mb-8">
        {formatDate(diff.from.scannedAt)} → {formatDate(diff.to.scannedAt)}
      </p>

      <ScoreCard diff={diff} />

      <div className="mt-8 grid sm:grid-cols-3 gap-3 mb-8">
        <CountTile
          label="New"
          count={totalNew}
          tone="red"
          subline={totalNew === 0 ? "nothing introduced" : "since the previous scan"}
        />
        <CountTile
          label="Resolved"
          count={totalResolved}
          tone="green"
          subline={totalResolved === 0 ? "nothing fixed" : "no longer present"}
        />
        <CountTile
          label="Carried over"
          count={totalCarried}
          tone="neutral"
          subline={totalCarried === 0 ? "" : "still open"}
        />
      </div>

      <FindingsSection
        title="New findings"
        accent="red"
        findings={diff.newFindings}
        emptyHint="No new issues introduced since the previous scan."
      />
      <FindingsSection
        title="Resolved findings"
        accent="green"
        findings={diff.resolvedFindings}
        emptyHint="No findings were resolved since the previous scan."
      />
      <FindingsSection
        title="Carried over"
        accent="neutral"
        findings={diff.carriedFindings}
        emptyHint="No findings carried over."
        defaultOpen={false}
      />
    </>
  )
}

function ScoreCard({ diff }: { diff: ScanDiff }) {
  // Display health (100 - penalty), not raw penalty, so this card reads the
  // same direction as the RiskGauge on every other page (higher = better).
  // scoreDelta in the data model is penalty change; invert sign for health.
  const fromHealth = diff.from.riskScore === null ? null : 100 - diff.from.riskScore
  const toHealth = diff.to.riskScore === null ? null : 100 - diff.to.riskScore
  const healthDelta = diff.scoreDelta === null ? null : -diff.scoreDelta

  const deltaLabel =
    healthDelta === null
      ? "—"
      : healthDelta === 0
        ? "no change"
        : healthDelta > 0
          ? `+${healthDelta} (better)`
          : `${healthDelta} (worse)`
  const deltaColor =
    healthDelta === null
      ? "text-slate-400"
      : healthDelta === 0
        ? "text-slate-400"
        : healthDelta > 0
          ? "text-emerald-400"
          : "text-red-400"

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
      <div className="grid sm:grid-cols-3 gap-6 items-center">
        <div>
          <div className="text-xs uppercase tracking-wider text-slate-500 mb-1">
            Previous health
          </div>
          <div className="text-4xl font-bold font-mono text-slate-300">
            {fromHealth ?? "—"}
            <span className="text-slate-600 text-xl"> /100</span>
          </div>
          <div className="text-xs text-slate-500 mt-1">
            {formatDate(diff.from.scannedAt)}
          </div>
        </div>
        <div className="text-center">
          <div className="text-xs uppercase tracking-wider text-slate-500 mb-1">
            Change
          </div>
          <div className={`text-3xl font-bold ${deltaColor}`}>{deltaLabel}</div>
          <div className="text-[10px] text-slate-600 mt-1 font-mono">higher is better</div>
        </div>
        <div className="sm:text-right">
          <div className="text-xs uppercase tracking-wider text-slate-500 mb-1">
            Current health
          </div>
          <div className="text-4xl font-bold font-mono text-slate-100">
            {toHealth ?? "—"}
            <span className="text-slate-600 text-xl"> /100</span>
          </div>
          <div className="text-xs text-slate-500 mt-1">
            {formatDate(diff.to.scannedAt)}
          </div>
        </div>
      </div>
    </div>
  )
}

function CountTile({
  label,
  count,
  tone,
  subline,
}: {
  label: string
  count: number
  tone: "red" | "green" | "neutral"
  subline: string
}) {
  const toneClass =
    tone === "red"
      ? "border-red-500/30 text-red-300"
      : tone === "green"
        ? "border-emerald-500/30 text-emerald-300"
        : "border-slate-700 text-slate-300"
  return (
    <div className={`bg-slate-900 border rounded-xl p-5 ${toneClass}`}>
      <div className="text-xs uppercase tracking-wider opacity-70 mb-1">
        {label}
      </div>
      <div className="text-3xl font-bold font-mono">{count}</div>
      {subline && <div className="text-xs mt-1 opacity-60">{subline}</div>}
    </div>
  )
}

function FindingsSection({
  title,
  accent,
  findings,
  emptyHint,
  defaultOpen = true,
}: {
  title: string
  accent: "red" | "green" | "neutral"
  findings: PrioritizedFinding[]
  emptyHint: string
  defaultOpen?: boolean
}) {
  const dotClass =
    accent === "red"
      ? "bg-red-400"
      : accent === "green"
        ? "bg-emerald-400"
        : "bg-slate-500"

  return (
    <details className="mb-4 group" open={defaultOpen && findings.length > 0}>
      <summary className="cursor-pointer flex items-center gap-3 px-5 py-3 bg-slate-900 border border-slate-800 rounded-xl list-none hover:border-slate-700 transition">
        <span className={`w-2 h-2 rounded-full ${dotClass}`} />
        <span className="font-semibold flex-1">{title}</span>
        <span className="text-slate-500 font-mono text-sm">
          {findings.length}
        </span>
        <span className="text-slate-600 group-open:rotate-180 transition-transform">
          ▾
        </span>
      </summary>
      <div className="mt-3 space-y-2">
        {findings.length === 0 ? (
          <p className="text-slate-500 text-sm px-5 py-2 italic flex items-center gap-2">
            {accent === "green" ? (
              <CheckIcon size={14} aria-hidden="true" />
            ) : null}
            {emptyHint}
          </p>
        ) : (
          findings.map((f, idx) => <FindingRow key={idx} finding={f} />)
        )}
      </div>
    </details>
  )
}

function FindingRow({ finding }: { finding: PrioritizedFinding }) {
  const sevClass =
    finding.data.severity === "critical"
      ? "text-red-400 bg-red-500/10 border-red-500/20"
      : finding.data.severity === "high"
        ? "text-orange-400 bg-orange-500/10 border-orange-500/20"
        : finding.data.severity === "medium" || finding.data.severity === "moderate"
          ? "text-yellow-400 bg-yellow-500/10 border-yellow-500/20"
          : "text-slate-400 bg-slate-700/30 border-slate-600/30"

  return (
    <div className="bg-slate-900/50 border border-slate-800 rounded-lg px-4 py-3 flex items-center gap-3">
      <span
        className={`text-[10px] uppercase font-mono font-bold px-2 py-0.5 rounded border ${sevClass} whitespace-nowrap`}
      >
        {finding.data.severity}
      </span>
      <div className="flex-1 min-w-0">
        <div className="font-mono text-sm text-slate-200 truncate">
          {findingTitle(finding)}
        </div>
        <div className="font-mono text-xs text-slate-500 truncate">
          {findingLocation(finding)}
        </div>
      </div>
    </div>
  )
}

function findingTitle(f: PrioritizedFinding): string {
  switch (f.kind) {
    case "secret":
      return f.data.patternName
    case "code":
      return f.data.ruleName
    case "iac":
      return f.data.ruleName
    case "sensitive-file":
      return f.data.name
    case "dependency":
      return `${f.data.package} — ${f.data.title}`
  }
}

function findingLocation(f: PrioritizedFinding): string {
  switch (f.kind) {
    case "secret":
    case "code":
      return `${f.data.filePath}:${f.data.lineNumber}`
    case "iac":
      return f.data.lineNumber
        ? `${f.data.filePath}:${f.data.lineNumber}`
        : f.data.filePath
    case "sensitive-file":
      return f.data.filePath
    case "dependency":
      return f.data.ghsa ? `${f.data.ghsa}` : `version ${f.data.version}`
  }
}

function formatDate(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })
}
