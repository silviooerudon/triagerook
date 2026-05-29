import { AlertTriangleIcon } from "@/app/components/icons"
import type { DetectorHealth } from "@/lib/types"

// Surfaced above the summary row whenever one or more detectors
// soft-failed (rate limit, registry outage, etc.) and returned empty
// results instead of throwing. Without this banner, the user sees a
// reassuring "0 findings" panel without realising that, say, the npm
// vulnerability scan never ran. Per AGENTS.md, silent partial scans
// erode trust faster than honest partial scans.
//
// The banner is intentionally separate from <TruncationBanner /> —
// truncation is "the scan ran but ran out of room", degradation is
// "specific detectors didn't run at all". A scan can be both at once.
const DETECTOR_LABELS: Record<DetectorHealth["detector"], string> = {
  history: "Git history secrets",
  "npm-audit": "npm vulnerabilities",
  osv: "Python (PyPI) vulnerabilities",
  "blob-fetch": "File contents",
  "suppressions-file": "Repo suppressions file",
  "license-registry": "PyPI/Go/Ruby licenses",
}

export function DegradedBanner({
  degraded,
}: {
  degraded?: DetectorHealth[]
}) {
  if (!degraded || degraded.length === 0) return null

  return (
    <div
      role="status"
      aria-live="polite"
      className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 flex items-start gap-3"
    >
      <span className="text-amber-300 mt-0.5">
        <AlertTriangleIcon size={16} aria-hidden="true" />
      </span>
      <div className="flex-1 min-w-0">
        <p className="font-semibold text-amber-200 text-sm mb-2">
          {degraded.length === 1
            ? "One detector ran in degraded mode"
            : `${degraded.length} detectors ran in degraded mode`}
        </p>
        <ul className="space-y-1.5">
          {degraded.map((entry, i) => (
            <li
              key={`${entry.detector}-${i}`}
              className="text-amber-100/85 text-xs leading-relaxed"
            >
              <span className="font-mono text-amber-300">
                {DETECTOR_LABELS[entry.detector] ?? entry.detector}
              </span>
              {" — "}
              {entry.reason}
            </li>
          ))}
        </ul>
        <p className="text-amber-100/60 text-[11px] mt-2 leading-relaxed">
          The score below reflects only the detectors that completed. Re-run
          in a few minutes if you need the full picture.
        </p>
      </div>
    </div>
  )
}
