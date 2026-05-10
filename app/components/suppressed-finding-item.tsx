import type { SuppressedFinding } from "@/lib/suppressions"
import type { PrioritizedFinding } from "@/lib/risk"
import { FindingCard } from "./finding-card"

type Props = { item: SuppressedFinding }

function formatRelative(iso: string, now: Date = new Date()): string {
  const target = new Date(iso + "T00:00:00Z")
  if (Number.isNaN(target.getTime())) return ""
  const diffMs = target.getTime() - now.getTime()
  const diffDays = Math.round(diffMs / (1000 * 60 * 60 * 24))
  if (diffDays === 0) return "today"
  const abs = Math.abs(diffDays)
  const past = diffDays < 0
  if (abs < 30) {
    return past ? `${abs} day${abs === 1 ? "" : "s"} ago` : `in ${abs} day${abs === 1 ? "" : "s"}`
  }
  const months = Math.round(abs / 30)
  if (months < 12) {
    return past
      ? `${months} month${months === 1 ? "" : "s"} ago`
      : `in ${months} month${months === 1 ? "" : "s"}`
  }
  const years = Math.round(abs / 365)
  return past
    ? `${years} year${years === 1 ? "" : "s"} ago`
    : `in ${years} year${years === 1 ? "" : "s"}`
}

function ExpiresLabel({ expires, expired }: { expires?: string; expired: boolean }) {
  if (!expires) return null
  const rel = formatRelative(expires)
  return (
    <span className={expired ? "text-red-400" : "text-slate-400"}>
      Expires: <span className="font-mono">{expires}</span>
      {rel && ` (${rel})`}
    </span>
  )
}

export function SuppressedFindingItem({ item }: Props) {
  const { suppression, expired } = item
  const cardFinding = { ...item.finding, score: 0 } as PrioritizedFinding
  return (
    <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-4 space-y-3 opacity-90">
      <header className="text-xs text-slate-400 space-y-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-slate-500">Suppressed by:</span>
          <code className="font-mono text-slate-300 bg-black/40 px-2 py-0.5 rounded">
            {suppression.pathGlob}
          </code>
          {suppression.ruleGlob && (
            <>
              <span className="text-slate-500">rule:</span>
              <code className="font-mono text-slate-300 bg-black/40 px-2 py-0.5 rounded">
                {suppression.ruleGlob}
              </code>
            </>
          )}
          {expired && (
            <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-full border bg-red-500/10 border-red-500/30 text-red-400">
              Expired
            </span>
          )}
        </div>
        <div className="flex items-center gap-3 flex-wrap text-xs">
          {suppression.reason && (
            <span>
              <span className="text-slate-500">Reason:</span>{" "}
              <span className="text-slate-300">{suppression.reason}</span>
            </span>
          )}
          <ExpiresLabel expires={suppression.expires} expired={expired} />
          <span className="text-slate-500">
            Line {suppression.sourceLine} of .repoguardignore
          </span>
        </div>
      </header>
      <FindingCard finding={cardFinding} />
    </div>
  )
}