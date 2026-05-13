"use client"

import { useEffect, useState, use } from "react"
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
import { ScanProgress } from "@/app/components/scan-progress"
import { SupplyChainCard } from "@/app/components/supply-chain-card"

type ScanResultFull = ScanResult & {
  dependencies?: DependencyFinding[]
  pythonDependencies?: DependencyFinding[]
  riskScore?: number
  riskBreakdown?: RiskBreakdown
  prioritized?: PrioritizedFinding[]
  posture?: PostureResult
  iam?: IAMResult
  supplyChain?: SupplyChainResult
}

type PageProps = {
  params: Promise<{ owner: string; repo: string }>
  searchParams: Promise<{ branch?: string }>
}

export default function PublicScanPage({ params, searchParams }: PageProps) {
  const { owner, repo } = use(params)
  const { branch } = use(searchParams)

  const [status, setStatus] = useState<"running" | "done" | "error" | "rate-limited">("running")
  const [result, setResult] = useState<ScanResultFull | null>(null)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [retryAfterSeconds, setRetryAfterSeconds] = useState<number | null>(null)

  useEffect(() => {
    const controller = new AbortController()

    async function runScan() {
      try {
        const response = await fetch(`/api/scan-public/${owner}/${repo}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(branch ? { defaultBranch: branch } : {}),
          signal: controller.signal,
        })

        if (response.status === 429) {
          const body = await response.json().catch(() => ({}))
          const retryAfter =
            typeof body?.retryAfterSeconds === "number"
              ? body.retryAfterSeconds
              : Number.parseInt(response.headers.get("Retry-After") ?? "", 10)
          setRetryAfterSeconds(Number.isFinite(retryAfter) ? retryAfter : null)
          setStatus("rate-limited")
          return
        }

        if (!response.ok) {
          const errorBody = await response.json().catch(() => ({}))
          throw new Error(errorBody.error ?? `Scan failed (${response.status})`)
        }

        const data: ScanResultFull = await response.json()
        setResult(data)
        setStatus("done")
      } catch (err) {
        if (err instanceof Error && err.name === "AbortError") return
        setErrorMessage(err instanceof Error ? err.message : "Unknown error")
        setStatus("error")
      }
    }

    runScan()
    return () => controller.abort()
  }, [owner, repo, branch])

  return (
    <main className="px-6 py-12">
      <div className="max-w-5xl mx-auto">
        <h1 className="text-3xl font-semibold tracking-tight mb-2">
          <span className="text-slate-400">scanning</span>{" "}
          <span className="font-mono text-amber-400">
            {owner}/{repo}
          </span>
        </h1>
        <p className="text-slate-400 text-sm mb-8">
          Public scan — no login required. Secrets, dependencies, code
          vulnerabilities, CI/IaC configuration and git history
          {branch ? ` on ${branch}` : ""}.
        </p>

        {status === "running" && <ScanProgress />}

        {status === "error" && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6">
            <p className="text-red-400 font-semibold mb-1 flex items-center gap-2">
              <AlertTriangleIcon size={16} aria-hidden="true" />
              Scan failed
            </p>
            <p className="text-red-300/80 text-sm">{errorMessage}</p>
            <p className="text-slate-400 text-xs mt-3">
              Public scans are limited to 60 requests per hour (GitHub API
              limit). Sign in for unlimited scans.
            </p>
          </div>
        )}

        {status === "rate-limited" && (
          <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl p-6">
            <p className="text-amber-300 font-semibold mb-1">
              Anonymous scans rate-limited
            </p>
            <p className="text-amber-200/80 text-sm">
              Public scans share a pool of 60 GitHub requests per hour.
              {retryAfterSeconds !== null && (
                <>
                  {" "}
                  Try again in{" "}
                  <span className="font-mono">
                    {formatRetryAfter(retryAfterSeconds)}
                  </span>
                  .
                </>
              )}
            </p>
            <div className="mt-4">
              <a
                href="/signin"
                className="inline-block px-4 py-2 rounded-lg bg-amber-400 hover:bg-amber-300 transition text-slate-950 text-sm font-medium"
              >
                Sign in for unlimited scans
              </a>
            </div>
          </div>
        )}

        {status === "done" && result && (
          <>
            <ScanResultView result={result} />
            <SignInCTA />
          </>
        )}
      </div>
    </main>
  )
}

function formatRetryAfter(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  const minutes = Math.ceil(seconds / 60)
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"}`
  const hours = Math.floor(minutes / 60)
  const remaining = minutes % 60
  return remaining === 0
    ? `${hours} hour${hours === 1 ? "" : "s"}`
    : `${hours}h ${remaining}m`
}

function SignInCTA() {
  return (
    <div className="mt-10 bg-slate-900 border border-amber-400/20 rounded-xl p-6 text-center">
      <h2 className="text-xl font-semibold mb-2">Liked this scan?</h2>
      <p className="text-slate-400 text-sm mb-5 max-w-md mx-auto">
        Sign in to scan unlimited repos, save history, diff against previous
        scans, and unlock the auto-fix PR feature. Free during beta.
      </p>
      <a
        href="/signin"
        className="inline-block px-6 py-3 rounded-lg bg-amber-400 hover:bg-amber-300 transition text-slate-950 font-medium"
      >
        Sign in with GitHub
      </a>
    </div>
  )
}

function ScanResultView({ result }: { result: ScanResultFull }) {
  const [view, setView] = useState<"prioritized" | "by-detector">("prioritized")

  const all: AllFindings = {
    secrets: (result.findings ?? []).filter(
      (f) => !f.source || f.source === "tree",
    ),
    historySecrets: result.historyFindings ?? [],
    sensitiveFiles: result.sensitiveFiles ?? [],
    codeFindings: result.codeFindings ?? [],
    iacFindings: result.iacFindings ?? [],
    npmDependencies: result.dependencies ?? [],
    pythonDependencies: result.pythonDependencies ?? [],
  }

  const counts = countBySeverity(all)
  const total = totalCount(all)
  const hasRisk =
    typeof result.riskScore === "number" &&
    !!result.riskBreakdown &&
    !!result.prioritized

  const summaryRow = (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      <SummaryCard
        label="Files scanned"
        value={result.filesScanned.toString()}
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

  const meta = (
    <p className="text-xs text-slate-500">
      Scan took {(result.durationMs / 1000).toFixed(2)}s •{" "}
      {result.filesSkipped} files skipped
      {result.truncated && " • results truncated (repo too large)"}
    </p>
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

  if (!hasRisk) {
    return (
      <div className="space-y-6">
        {summaryRow}
        {meta}
        {legacySections}
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {summaryRow}

      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col md:flex-row gap-6 items-center md:items-stretch">
        <div className="shrink-0 flex items-center justify-center">
          <RiskGauge score={result.riskScore!} />
        </div>
        <div className="flex-1 w-full flex flex-col justify-center">
          <h2 className="text-sm uppercase tracking-wider text-slate-500 mb-3">
            Where the score comes from
          </h2>
          <RiskBreakdownChart breakdown={result.riskBreakdown!} />
          <p className="text-xs text-slate-500 mt-4">
            {result.prioritized!.length} finding
            {result.prioritized!.length === 1 ? "" : "s"} ranked by risk.
          </p>
        </div>
      </div>

      {result.posture && <PostureCard posture={result.posture} />}
      {result.iam && <IamCard iam={result.iam} />}
      {result.supplyChain && <SupplyChainCard supplyChain={result.supplyChain} />}

      {meta}

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
        <PrioritizedList findings={result.prioritized!} />
      ) : (
        legacySections
      )}
    </div>
  )
}
