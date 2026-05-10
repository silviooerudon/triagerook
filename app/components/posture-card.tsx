import type { PostureResult } from "@/lib/posture"
import { PostureGauge } from "./posture-gauge"

type PostureCardProps = {
  posture: PostureResult
}

function categoryLabel(id: string): string {
  if (id === "branch") return "Branch protection"
  if (id === "docs") return "Documentation"
  if (id === "deps") return "Dependencies"
  if (id === "governance") return "Governance"
  return id
}

function barColor(pointsEarned: number, pointsMax: number): string {
  if (pointsMax === 0) return "#374151"
  const pct = (pointsEarned / pointsMax) * 100
  if (pct >= 90) return "#22c55e"
  if (pct >= 75) return "#3b82f6"
  if (pct >= 60) return "#eab308"
  if (pct >= 40) return "#f97316"
  return "#ef4444"
}

export function PostureCard({ posture }: PostureCardProps) {
  const hasQuickWins = posture.quickWins.length > 0

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col md:flex-row gap-6 items-center md:items-stretch">
      <div className="shrink-0 flex items-center justify-center">
        <PostureGauge
          score={posture.score}
          grade={posture.grade}
          degraded={posture.degraded}
        />
      </div>
      <div className="flex-1 w-full flex flex-col justify-center">
        <h2 className="text-sm uppercase tracking-wider text-slate-500 mb-3">
          Repo posture
        </h2>

        <div className="space-y-3 mb-5">
          {posture.breakdown.map((cat) => {
            const pct = cat.pointsMax === 0 ? 0 : (cat.pointsEarned / cat.pointsMax) * 100
            const color = barColor(cat.pointsEarned, cat.pointsMax)
            return (
              <div key={cat.id}>
                <div className="flex items-center justify-between text-xs mb-1">
                  <span className="text-slate-300">{categoryLabel(cat.id)}</span>
                  <span className="text-slate-500 font-mono">
                    {cat.pointsEarned} / {cat.pointsMax}
                  </span>
                </div>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{
                      width: `${pct}%`,
                      backgroundColor: color,
                      transition: "width 300ms ease, background-color 300ms ease",
                    }}
                  />
                </div>
              </div>
            )
          })}
        </div>

        {hasQuickWins ? (
          <div>
            <h3 className="text-xs uppercase tracking-wider text-slate-500 mb-2">
              Quick wins to improve
            </h3>
            <ul className="space-y-1">
              {posture.quickWins.map((qw) => (
                <li
                  key={qw.signalId}
                  className="text-sm text-slate-300 flex items-baseline justify-between gap-3"
                >
                  <span>- {qw.label}</span>
                  <span className="text-xs text-slate-500 font-mono shrink-0">
                    +{qw.pointsAvailable} pts
                  </span>
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <p className="text-sm text-slate-500">No quick wins remaining - solid posture.</p>
        )}
      </div>
    </div>
  )
}

export default PostureCard
