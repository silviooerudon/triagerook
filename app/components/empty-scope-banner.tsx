"use client"

import { useRouter, usePathname, useSearchParams } from "next/navigation"
import { AlertTriangleIcon } from "@/app/components/icons"

// Shown when ?path=<x> narrows the scan but zero scannable files
// matched. Without this banner the UI would render the default
// 100/100 EXCELLENT score (no findings, so no penalty) — which is
// actively misleading because we didn't actually inspect anything.
//
// Common cause: the user typed a path that doesn't exist in the repo
// (e.g. `packages/storage-js` against supabase/supabase, when that
// package actually lives in a separate `supabase/storage-js` repo).
//
// We replace the score/summary block with this banner. Posture, IAM
// and Supply Chain results are still shown alongside because those
// are repo-level signals — they don't depend on which files we
// inspected, so they remain useful information.
export function EmptyScopeBanner({
  pathPrefix,
  repoFullName,
}: {
  pathPrefix: string
  repoFullName: string
}) {
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()

  function clearNarrowScope() {
    const params = new URLSearchParams(searchParams.toString())
    params.delete("path")
    const query = params.toString()
    router.push(query ? `${pathname}?${query}` : pathname)
  }

  return (
    <div className="rounded-xl border border-red-500/40 bg-red-500/10 p-6">
      <p className="font-semibold text-red-200 text-sm mb-2 flex items-center gap-2">
        <AlertTriangleIcon size={16} aria-hidden="true" />
        No files found at this scope
      </p>
      <p className="text-red-100/80 text-sm leading-relaxed mb-4">
        We narrowed the scan to{" "}
        <code className="font-mono text-amber-300">
          {repoFullName}/{pathPrefix}
        </code>{" "}
        but found zero scannable files there. The path probably
        doesn&apos;t exist in this repo — double-check the spelling
        (case matters), or clear the narrow scope to scan the whole
        repository.
      </p>
      <button
        type="button"
        onClick={clearNarrowScope}
        className="text-xs font-mono px-3 py-1.5 border border-amber-400/40 text-amber-300 hover:bg-amber-400 hover:text-slate-950 transition rounded"
      >
        Clear narrow scope
      </button>
    </div>
  )
}
