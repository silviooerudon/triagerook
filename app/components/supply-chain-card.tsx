"use client"

import { useState } from "react"
import type {
  SupplyChainResult,
  SupplyChainFinding,
  SupplyChainSeverity,
  SupplyChainCategoryBreakdown,
} from "@/lib/supply-chain"
import { SupplyChainGauge } from "./supply-chain-gauge"

type SupplyChainCardProps = {
  supplyChain: SupplyChainResult
}

function categoryLabel(id: string): string {
  if (id === "typosquatting") return "Typosquatting"
  if (id === "postinstall") return "Install hooks"
  return id
}

function severityColor(sev: SupplyChainSeverity | null): string {
  if (sev === "HIGH") return "#f97316"
  if (sev === "MEDIUM") return "#eab308"
  if (sev === "LOW") return "#3b82f6"
  return "#374151"
}

function severityRank(sev: SupplyChainSeverity): number {
  if (sev === "HIGH") return 3
  if (sev === "MEDIUM") return 2
  return 1
}

function highestSeverity(
  cat: SupplyChainCategoryBreakdown,
): SupplyChainSeverity | null {
  if (cat.severityCounts.HIGH > 0) return "HIGH"
  if (cat.severityCounts.MEDIUM > 0) return "MEDIUM"
  if (cat.severityCounts.LOW > 0) return "LOW"
  return null
}

function FindingItem({ finding }: { finding: SupplyChainFinding }) {
  const [open, setOpen] = useState(false)
  const color = severityColor(finding.severity)
  const locationSuffix =
    finding.line !== undefined && finding.line !== null
      ? ":" + finding.line
      : ""

  return (
    <li className="border border-gray-800 rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 px-3 py-2 text-left hover:bg-gray-800/50 transition"
      >
        <span
          className="text-xs uppercase tracking-wider font-bold shrink-0 w-20"
          style={{ color }}
        >
          {finding.severity}
        </span>
        <span className="flex-1 text-sm text-gray-200 truncate">
          {finding.pattern}
          {finding.package ? " - " + finding.package : ""}
        </span>
        <span className="text-xs text-gray-500 font-mono truncate max-w-[40%]">
          {finding.file}
          {locationSuffix}
        </span>
        <span className="text-gray-500 shrink-0">{open ? "-" : "+"}</span>
      </button>
      {open ? (
        <div className="px-3 py-3 border-t border-gray-800 bg-gray-950/50 space-y-3">
          <div>
            <div className="text-xs uppercase tracking-wider text-gray-500 mb-1">
              What this means
            </div>
            <p className="text-sm text-gray-300">{finding.message}</p>
          </div>
          {finding.evidence ? (
            <div>
              <div className="text-xs uppercase tracking-wider text-gray-500 mb-1">
                Evidence
              </div>
              <pre className="text-xs text-gray-400 font-mono bg-black/40 rounded p-2 overflow-x-auto whitespace-pre-wrap break-all">
                {finding.evidence}
              </pre>
            </div>
          ) : null}
          <div className="text-xs text-gray-500 font-mono">
            id: {finding.id}
          </div>
        </div>
      ) : null}
    </li>
  )
}

export function SupplyChainCard({ supplyChain }: SupplyChainCardProps) {
  const [showAll, setShowAll] = useState(false)

  const sortedFindings = [...supplyChain.findings].sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity),
  )

  const total = sortedFindings.length
  const visibleLimit = 5
  const visible = showAll ? sortedFindings : sortedFindings.slice(0, visibleLimit)
  const hidden = total - visible.length

  const manifestsScanned =
    supplyChain.scanned.packageJsonCount +
    supplyChain.scanned.setupPyCount +
    supplyChain.scanned.pyprojectCount

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 flex flex-col md:flex-row gap-6 items-center md:items-stretch">
      <div className="shrink-0 flex items-center justify-center">
        <SupplyChainGauge score={supplyChain.score} level={supplyChain.level} />
      </div>
      <div className="flex-1 w-full flex flex-col justify-center min-w-0">
        <h2 className="text-sm uppercase tracking-wider text-gray-500 mb-3">
          Supply chain risk
        </h2>

        <div className="space-y-2 mb-5">
          {supplyChain.categories.map((cat) => {
            const sev = highestSeverity(cat)
            const color = severityColor(sev)
            return (
              <div
                key={cat.id}
                className="flex items-center justify-between gap-3 text-sm"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span
                    className="inline-block w-2 h-2 rounded-full shrink-0"
                    style={{ backgroundColor: color }}
                  />
                  <span className="text-gray-300 truncate">
                    {categoryLabel(cat.id)}
                  </span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {sev ? (
                    <span
                      className="text-xs uppercase tracking-wider font-semibold"
                      style={{ color }}
                    >
                      {sev}
                    </span>
                  ) : null}
                  <span className="text-gray-500 font-mono text-xs">
                    {cat.findingCount}{" "}
                    {cat.findingCount === 1 ? "finding" : "findings"}
                  </span>
                </div>
              </div>
            )
          })}
        </div>

        {total > 0 ? (
          <div>
            <h3 className="text-xs uppercase tracking-wider text-gray-500 mb-2">
              Findings ({total})
            </h3>
            <ul className="space-y-2">
              {visible.map((f) => (
                <FindingItem key={f.id} finding={f} />
              ))}
            </ul>
            {hidden > 0 ? (
              <button
                type="button"
                onClick={() => setShowAll(true)}
                className="mt-2 text-xs text-gray-400 hover:text-gray-200 underline"
              >
                Show {hidden} more
              </button>
            ) : null}
          </div>
        ) : (
          <p className="text-sm text-gray-500">
            {manifestsScanned > 0
              ? "No supply chain risks detected across " +
                manifestsScanned +
                " " +
                (manifestsScanned === 1
                  ? "package manifest"
                  : "package manifests") +
                "."
              : "No package manifests found in this repository."}
          </p>
        )}
      </div>
    </div>
  )
}

export default SupplyChainCard
