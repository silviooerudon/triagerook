import type { RiskBreakdown } from "@/lib/risk"

type Row = {
  key: keyof RiskBreakdown
  label: string
  barClass: string
  labelClass: string
  dim?: boolean
}

const ROWS: Row[] = [
  {
    key: "critical",
    label: "Critical",
    barClass: "bg-red-500",
    labelClass: "text-red-400",
  },
  {
    key: "high",
    label: "High",
    barClass: "bg-orange-500",
    labelClass: "text-orange-400",
  },
  {
    key: "medium",
    label: "Medium",
    barClass: "bg-yellow-500",
    labelClass: "text-yellow-400",
  },
  {
    key: "low",
    label: "Low",
    barClass: "bg-slate-400",
    labelClass: "text-slate-400",
  },
  {
    key: "fixture",
    label: "Fixture",
    barClass: "bg-slate-500",
    labelClass: "text-slate-500",
    dim: true,
  },
]

export function RiskBreakdownChart({ breakdown }: { breakdown: RiskBreakdown }) {
  const values = ROWS.map((r) => breakdown[r.key])
  const max = Math.max(...values)

  if (max === 0) {
    return (
      <div className="text-sm text-slate-500">
        No findings contribute to score yet.
      </div>
    )
  }

  return (
    <div className="space-y-2">
      {ROWS.map((row) => {
        const value = breakdown[row.key]
        const widthPct = max > 0 ? (value / max) * 100 : 0
        return (
          <div
            key={row.key}
            className={`flex items-center gap-3 ${row.dim ? "opacity-60" : ""}`}
          >
            <div
              className={`w-20 shrink-0 text-xs uppercase tracking-wider font-semibold ${row.labelClass}`}
            >
              {row.label}
            </div>
            <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${row.barClass}`}
                style={{ width: `${widthPct}%` }}
              />
            </div>
            <div className="w-12 text-right text-xs font-mono text-slate-400">
              {Math.round(value)}
            </div>
          </div>
        )
      })}
    </div>
  )
}

export default RiskBreakdownChart
