"use client"

import { useState } from "react"
import type { IAMResult, IAMFinding, IAMSeverity } from "@/lib/iam"
import { IamGauge } from "./iam-gauge"

type IamCardProps = {
  iam: IAMResult
}

function categoryLabel(id: string): string {
  if (id === "oidc") return "GitHub OIDC trust"
  if (id === "privesc") return "Privilege escalation"
  if (id === "admin") return "Admin equivalents"
  return id
}

function severityColor(sev: IAMSeverity | null): string {
  if (sev === "critical") return "#ef4444"
  if (sev === "high") return "#f97316"
  if (sev === "medium") return "#eab308"
  if (sev === "low") return "#3b82f6"
  return "#374151"
}


function FindingItem({ finding }: { finding: IAMFinding }) {
  const [open, setOpen] = useState(false)
  const color = severityColor(finding.severity)

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
          {finding.ruleName}
        </span>
        <span className="text-xs text-gray-500 font-mono truncate max-w-[40%]">
          {finding.filePath}
          {finding.lineNumber !== null ? ":" + finding.lineNumber : ""}
        </span>
        <span className="text-gray-500 shrink-0">{open ? "-" : "+"}</span>
      </button>
      {open ? (
        <div className="px-3 py-3 border-t border-gray-800 bg-gray-950/50 space-y-3">
          <div>
            <div className="text-xs uppercase tracking-wider text-gray-500 mb-1">
              Description
            </div>
            <p className="text-sm text-gray-300">{finding.description}</p>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wider text-gray-500 mb-1">
              Remediation
            </div>
            <p className="text-sm text-gray-300">{finding.remediation}</p>
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
            rule: {finding.ruleId}
          </div>
        </div>
      ) : null}
    </li>
  )
}

export function IamCard({ iam }: IamCardProps) {
  const [showAll, setShowAll] = useState(false)
  const findings = iam.findings
  const total = findings.length
  const visibleLimit = 5
  const visible = showAll ? findings : findings.slice(0, visibleLimit)
  const hidden = total - visible.length

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 flex flex-col md:flex-row gap-6 items-center md:items-stretch">
      <div className="shrink-0 flex items-center justify-center">
        <IamGauge
          score={iam.score}
          level={iam.level}
          degraded={iam.degraded}
        />
      </div>
      <div className="flex-1 w-full flex flex-col justify-center min-w-0">
        <h2 className="text-sm uppercase tracking-wider text-gray-500 mb-3">
          IAM risk
        </h2>

        <div className="space-y-2 mb-5">
          {iam.breakdown.map((cat) => {
            const color = severityColor(cat.highestSeverity)
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
                  {cat.highestSeverity ? (
                    <span
                      className="text-xs uppercase tracking-wider font-semibold"
                      style={{ color }}
                    >
                      {cat.highestSeverity}
                    </span>
                  ) : null}
                  <span className="text-gray-500 font-mono text-xs">
                    {cat.findings} {cat.findings === 1 ? "finding" : "findings"}
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
              {visible.map((f, i) => (
                <FindingItem
                  key={f.ruleId + ":" + f.filePath + ":" + (f.lineNumber ?? i)}
                  finding={f}
                />
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
            No IAM risks detected across {iam.filesScanned}{" "}
            {iam.filesScanned === 1 ? "file" : "files"}.
          </p>
        )}
      </div>
    </div>
  )
}

export default IamCard
