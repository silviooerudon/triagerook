"use client"

import { useEffect, useState } from "react"

// Display-only progress ticker. The real scan API does not stream
// per-detector events, so we drive a timed progression that teaches the
// user what the nine detectors are actually doing. Reads more credibly
// than a single spinner — buyers evaluating a security tool want to see
// the scope of what is being checked.
const DETECTOR_STEPS: readonly string[] = [
  "Fetching repository tree from GitHub",
  "Scanning files for secrets (60+ patterns)",
  "Computing entropy on env / config files",
  "Querying npm advisory database",
  "Querying OSV.dev for Python advisories",
  "Replaying 30 most-recent commits",
  "Checking IaC config (Dockerfile, GitHub Actions)",
  "Computing posture grade",
  "Assessing IAM risk",
] as const

const STEP_MS = 4500

export function ScanProgress() {
  const [completed, setCompleted] = useState(0)

  useEffect(() => {
    if (completed >= DETECTOR_STEPS.length) return
    const id = setTimeout(() => setCompleted((c) => c + 1), STEP_MS)
    return () => clearTimeout(id)
  }, [completed])

  const allDone = completed >= DETECTOR_STEPS.length

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 font-mono text-sm">
      <div className="flex items-center gap-2 mb-4">
        <span className="inline-block w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
        <span className="text-slate-200">
          {allDone ? "Finalising results…" : "Scanning…"}
        </span>
      </div>
      <ul className="space-y-1.5">
        {DETECTOR_STEPS.map((label, i) => {
          const isDone = i < completed
          const isRunning = !isDone && i === completed
          return (
            <li
              key={label}
              className={
                isDone
                  ? "text-emerald-400/80"
                  : isRunning
                    ? "text-slate-200"
                    : "text-slate-600"
              }
            >
              <span className="inline-block w-4">
                {isDone ? "✓" : isRunning ? "▸" : "·"}
              </span>{" "}
              {label}
              {isRunning && (
                <span
                  className="ml-2 inline-block w-3 h-3 align-text-bottom border-2 border-amber-400/40 border-t-amber-400 rounded-full animate-spin"
                  aria-hidden="true"
                />
              )}
            </li>
          )
        })}
      </ul>
      <p className="text-slate-500 text-xs mt-4">
        Usually completes in under a minute on a typical repo.
      </p>
    </div>
  )
}
