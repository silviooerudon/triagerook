"use client"

import { useRouter, usePathname, useSearchParams } from "next/navigation"
import { useState } from "react"

// Header-strip widget that shows the current scope and lets the user
// narrow / clear it. Submitting reloads the page with a new ?path=
// search param, which triggers a fresh scan against just the named
// subfolder.
//
// Used by both the authenticated scan view and the anonymous public
// scan view. Lives in app/components/ so neither owns it.
export function ScopeControl({
  currentPathPrefix,
  repoFullName,
}: {
  // Echo of result.pathPrefix once the scan returns. Undefined while
  // the scan is still running OR when no scope filter was applied.
  currentPathPrefix?: string
  // For display only ("scope inside vercel/next.js").
  repoFullName: string
}) {
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const [open, setOpen] = useState(false)
  const [draft, setDraft] = useState(currentPathPrefix ?? "")

  function submit(next: string | null) {
    const params = new URLSearchParams(searchParams.toString())
    if (next) params.set("path", next)
    else params.delete("path")
    const query = params.toString()
    router.push(query ? `${pathname}?${query}` : pathname)
  }

  return (
    <div className="text-xs font-mono text-slate-500 flex flex-wrap items-center gap-2 mb-6">
      <span>scope:</span>
      {currentPathPrefix ? (
        <>
          <span className="text-amber-300 truncate" title={currentPathPrefix}>
            {repoFullName}/{currentPathPrefix}
          </span>
          <button
            type="button"
            onClick={() => submit(null)}
            className="text-slate-400 hover:text-amber-400 underline decoration-dashed underline-offset-2"
          >
            clear narrow scope
          </button>
        </>
      ) : (
        <>
          <span className="text-slate-400">entire repo</span>
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="text-slate-400 hover:text-amber-400 underline decoration-dashed underline-offset-2"
          >
            narrow to a subfolder
          </button>
        </>
      )}
      {open && !currentPathPrefix && (
        <form
          onSubmit={(e) => {
            e.preventDefault()
            const trimmed = draft.trim().replace(/^\/+|\/+$/g, "")
            if (trimmed) submit(trimmed)
          }}
          className="flex items-center gap-2 w-full mt-1"
        >
          <input
            type="text"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            placeholder="packages/auth"
            spellCheck={false}
            className="flex-1 max-w-md bg-slate-900 border border-slate-800 rounded px-2 py-1 text-slate-200 placeholder-slate-600 focus:outline-none focus:border-amber-400/40"
          />
          <button
            type="submit"
            className="px-3 py-1 border border-amber-400/40 text-amber-300 hover:bg-amber-400 hover:text-slate-950 transition rounded"
          >
            rescan
          </button>
        </form>
      )}
    </div>
  )
}
