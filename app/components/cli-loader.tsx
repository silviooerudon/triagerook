"use client"

// CLI-style loader. Replaces the generic `animate-pulse` skeletons on
// the history, suppressions, scan-view and scan-diff pages with the
// same terminal aesthetic as <ScanProgress />. Keeps the brand voice
// during the moment the user is waiting for data — a brief but
// repeated UI surface that used to feel like a generic SaaS skeleton.
//
// This is a display-only loader: there is no real progress to report
// for a single API GET. The spinner pulse on the prompt is enough to
// communicate "we're working" without staging a fake step list.
export function CliLoader({
  label,
  hint,
}: {
  // The "command" we're pretending to run, shown after the prompt.
  // Examples: "history --tail 50", "suppressions --list".
  label: string
  // Optional muted-grey line below the prompt — short, e.g.
  // "fetching most-recent scans…"
  hint?: string
}) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="bg-slate-900 border border-slate-800 rounded-xl p-5 font-mono text-sm"
    >
      <div className="flex items-center gap-2">
        <span className="text-amber-400 select-none">$</span>
        <span className="text-slate-200">{label}</span>
        <span
          aria-hidden="true"
          className="ml-1 inline-block w-2 h-3.5 bg-amber-400/70 animate-pulse align-middle"
        />
      </div>
      {hint && (
        <p className="mt-2 text-xs text-slate-500 leading-relaxed">{hint}</p>
      )}
    </div>
  )
}
