"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { AlertTriangleIcon, CheckIcon, InboxIcon } from "@/app/components/icons"
import { CliLoader } from "@/app/components/cli-loader"

type ScanSummary = {
  id: string
  owner: string
  repo: string
  scanned_at: string
  secrets_count: number
  deps_count: number
  files_scanned: number
  duration_ms: number
}

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanSummary[]>([])
  const [status, setStatus] = useState<"loading" | "done" | "error">("loading")
  const [errorMessage, setErrorMessage] = useState<string | null>(null)

  useEffect(() => {
    async function fetchScans() {
      try {
        const res = await fetch("/api/scans")
        if (!res.ok) {
          const body = await res.json().catch(() => ({}))
          throw new Error(body.error ?? `Failed (${res.status})`)
        }
        const data = await res.json()
        setScans(data.scans ?? [])
        setStatus("done")
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : "Unknown error")
        setStatus("error")
      }
    }
    fetchScans()
  }, [])

  return (
    <main className="px-6 py-12">
      <div className="max-w-5xl mx-auto">
        <h1 className="font-display text-3xl md:text-4xl font-bold tracking-tight mb-2">Scan history</h1>
        <p className="text-slate-400 text-sm mb-8">
          {scans.length === 0
            ? "No scans yet."
            : `${scans.length} ${scans.length === 1 ? "scan" : "scans"}, most recent first.`}
        </p>

        {status === "loading" && (
          <CliLoader
            label="triagerook history --tail 50"
            hint="fetching your most-recent scans from supabase…"
          />
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

        {status === "done" && scans.length === 0 && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-8">
            <div className="flex items-start gap-4">
              <InboxIcon
                size={36}
                className="text-slate-500 shrink-0 mt-1"
                aria-hidden="true"
              />
              <div className="min-w-0">
                <p className="font-mono text-xs text-amber-400 mb-1">
                  {"// $ history --tail 1"}
                </p>
                <h2 className="font-display text-xl md:text-2xl font-bold mb-2 tracking-tight">
                  no scans yet.
                </h2>
                <p className="text-slate-400 text-sm leading-relaxed">
                  Once you scan a repo, every run lands here with a one-click
                  diff against the previous one. Pick one to start.
                </p>
                <Link
                  href="/dashboard"
                  className="mt-5 inline-flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-amber-400 border-b border-dashed border-slate-700 hover:border-amber-400 transition"
                >
                  → pick a repo to scan
                </Link>
              </div>
            </div>
          </div>
        )}

        {status === "done" && scans.length > 0 && (
          <div className="space-y-3">
            {scans.map((scan, idx) => (
              <ScanRow
                key={scan.id}
                scan={scan}
                previous={findPreviousOfSameRepo(scans, idx)}
              />
            ))}
          </div>
        )}
      </div>
    </main>
  )
}

function findPreviousOfSameRepo(
  scans: ScanSummary[],
  currentIdx: number,
): ScanSummary | null {
  // /api/scans returns most-recent first, so the "previous" scan of the
  // same repo is the next item in the array with the same owner/repo.
  const current = scans[currentIdx]
  for (let i = currentIdx + 1; i < scans.length; i++) {
    if (scans[i].owner === current.owner && scans[i].repo === current.repo) {
      return scans[i]
    }
  }
  return null
}

function ScanRow({
  scan,
  previous,
}: {
  scan: ScanSummary
  previous: ScanSummary | null
}) {
  const date = new Date(scan.scanned_at)
  const dateStr = date.toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })

  const hasFindings = scan.secrets_count > 0 || scan.deps_count > 0

  return (
    <div className="bg-slate-900 border border-slate-800 hover:border-slate-700 rounded-xl transition">
      <Link
        href={`/dashboard/scan/view/${scan.id}`}
        className="block p-5"
      >
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="flex-1 min-w-0">
            <h3 className="font-semibold font-mono truncate">
              {scan.owner}/{scan.repo}
            </h3>
            <p className="text-xs text-slate-500 mt-1">
              {dateStr} • {scan.files_scanned} files • {(scan.duration_ms / 1000).toFixed(1)}s
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <CountBadge
              count={scan.secrets_count}
              label="secrets"
              tone={scan.secrets_count > 0 ? "red" : "neutral"}
            />
            <CountBadge
              count={scan.deps_count}
              label="deps"
              tone={scan.deps_count > 0 ? "orange" : "neutral"}
            />
            {!hasFindings && (
              <span className="text-xs px-2 py-0.5 rounded-full border bg-green-500/10 border-green-500/20 text-green-400 inline-flex items-center gap-1">
                <CheckIcon size={12} aria-hidden="true" />
                clean
              </span>
            )}
          </div>
        </div>
      </Link>
      {previous && (
        <div className="border-t border-slate-800/60 px-5 py-2.5 flex items-center justify-end">
          <Link
            href={`/dashboard/scan/diff/${previous.id}/${scan.id}`}
            className="text-xs font-mono text-slate-400 hover:text-amber-400 transition inline-flex items-center gap-1.5"
          >
            ↔ diff vs previous scan
          </Link>
        </div>
      )}
    </div>
  )
}

function CountBadge({
  count,
  label,
  tone,
}: {
  count: number
  label: string
  tone: "neutral" | "red" | "orange"
}) {
  if (count === 0) return null

  const colors = {
    neutral: "bg-slate-800 border-slate-700 text-slate-400",
    red: "bg-red-500/10 border-red-500/20 text-red-400",
    orange: "bg-orange-500/10 border-orange-500/20 text-orange-400",
  }

  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border font-mono ${colors[tone]}`}>
      {count} {label}
    </span>
  )
}