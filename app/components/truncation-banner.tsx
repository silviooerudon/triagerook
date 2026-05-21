import { AlertTriangleIcon } from "@/app/components/icons"

// Surfaced above the summary row whenever ScanResult.truncated is true.
// Was originally a tiny footnote at the bottom of the scan view — easy
// to miss when a 15,000-file monorepo only had 1,000 of its files
// actually inspected. Making this visible up-front avoids users
// over-trusting a "clean" result that's really "we ran out of time /
// hit the file cap."
//
// Inputs are explicit because the truncation can have three causes:
//   - we hit MAX_FILES_TO_SCAN (file ceiling) → `filesSkipped > 0`
//   - we hit MAX_SCAN_TIME_MS                → `filesSkipped` may be 0
//   - the GitHub tree response itself was truncated by GitHub
// We render a single banner that names the visible cause(s) inferable
// from the numbers.
export function TruncationBanner({
  truncated,
  filesScanned,
  filesSkipped,
}: {
  truncated: boolean
  filesScanned: number
  filesSkipped: number
}) {
  if (!truncated) return null

  const filesSkippedNote =
    filesSkipped > 0
      ? `${filesSkipped.toLocaleString()} files were not inspected (file cap reached).`
      : "the scan ran out of time before reaching every file."

  return (
    <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 flex items-start gap-3">
      <span className="text-amber-300 mt-0.5">
        <AlertTriangleIcon size={16} aria-hidden="true" />
      </span>
      <div className="flex-1 min-w-0">
        <p className="font-semibold text-amber-200 text-sm mb-1">
          Partial scan — repo is larger than TriageRook&apos;s per-run budget
        </p>
        <p className="text-amber-100/80 text-xs leading-relaxed">
          {filesScanned.toLocaleString()} files were inspected; {filesSkippedNote}{" "}
          The score below reflects only the inspected slice. For monorepos this
          is usually fine for triage but means a genuinely-clean signal can&apos;t
          be given here. Re-run after pushing a fix to the inspected area or
          narrow the scan by branch.
        </p>
      </div>
    </div>
  )
}
