"use client"

import { useCallback, useEffect, useState } from "react"

type Suppression = {
  id: string
  owner: string
  repo: string
  path_glob: string
  rule_glob: string | null
  reason: string | null
  expires_at: string | null
  created_at: string
}

export default function SuppressionsPage() {
  const [status, setStatus] = useState<"loading" | "done" | "error">("loading")
  const [rows, setRows] = useState<Suppression[]>([])
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<string | null>(null)

  const load = useCallback(async () => {
    try {
      setStatus("loading")
      const res = await fetch("/api/suppressions")
      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.error ?? `Failed (${res.status})`)
      }
      const data = await res.json()
      setRows(data.suppressions ?? [])
      setStatus("done")
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : "Unknown error")
      setStatus("error")
    }
  }, [])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- load-on-mount pattern; setStatus("loading") inside load() is intentional.
    load()
  }, [load])

  async function deleteRow(id: string) {
    setDeleting(id)
    try {
      const res = await fetch(`/api/suppressions/${id}`, { method: "DELETE" })
      if (!res.ok && res.status !== 404) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body.error ?? `Delete failed (${res.status})`)
      }
      setRows((current) => current.filter((r) => r.id !== id))
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : "Delete failed")
    } finally {
      setDeleting(null)
    }
  }

  return (
    <main className="px-6 py-12">
      <div className="max-w-4xl mx-auto space-y-6">
        <header>
          <h1 className="text-3xl font-semibold tracking-tight">Suppressions</h1>
          <p className="text-slate-400 text-sm mt-2">
            Personal, per-repo. Hidden from your scan results until you remove
            them here. Doesn&apos;t affect anyone else who scans the same repo.
          </p>
        </header>

        {status === "loading" && (
          <div className="space-y-3">
            {[0, 1].map((i) => (
              <div
                key={i}
                className="bg-slate-900 border border-slate-800 rounded-xl p-5 h-[88px] animate-pulse"
              />
            ))}
          </div>
        )}

        {status === "error" && errorMessage && (
          <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4">
            <p className="text-red-300 text-sm">{errorMessage}</p>
          </div>
        )}

        {status === "done" && rows.length === 0 && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center">
            <p className="text-slate-400">No suppressions yet.</p>
            <p className="text-slate-500 text-sm mt-1">
              Click &quot;Suppress&quot; on any finding to add one.
            </p>
          </div>
        )}

        {status === "done" && rows.length > 0 && (
          <div className="space-y-3">
            {rows.map((row) => (
              <article
                key={row.id}
                className="bg-slate-900 border border-slate-800 rounded-xl p-5"
              >
                <header className="flex items-center justify-between gap-3 flex-wrap">
                  <h2 className="font-semibold text-white font-mono text-sm">
                    {row.owner}/{row.repo}
                  </h2>
                  <button
                    type="button"
                    onClick={() => deleteRow(row.id)}
                    disabled={deleting === row.id}
                    className="text-xs px-3 py-1.5 rounded-lg border border-red-500/30 bg-red-500/10 text-red-300 hover:bg-red-500/20 disabled:opacity-50"
                  >
                    {deleting === row.id ? "Removing…" : "Remove"}
                  </button>
                </header>
                <dl className="mt-3 grid grid-cols-1 md:grid-cols-3 gap-y-2 gap-x-4 text-xs">
                  <div>
                    <dt className="text-slate-500 uppercase tracking-wider">
                      Path
                    </dt>
                    <dd className="text-slate-200 font-mono">{row.path_glob}</dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 uppercase tracking-wider">
                      Rule
                    </dt>
                    <dd className="text-slate-200 font-mono">
                      {row.rule_glob ?? "—"}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-slate-500 uppercase tracking-wider">
                      Expires
                    </dt>
                    <dd className="text-slate-200">
                      {row.expires_at
                        ? new Date(row.expires_at).toISOString().slice(0, 10)
                        : "never"}
                    </dd>
                  </div>
                </dl>
                {row.reason && (
                  <p className="mt-3 text-sm text-slate-400">
                    <span className="text-slate-500">Reason:</span> {row.reason}
                  </p>
                )}
                <p className="mt-2 text-[10px] text-slate-500">
                  Added{" "}
                  {new Date(row.created_at).toISOString().slice(0, 10)}
                </p>
              </article>
            ))}
          </div>
        )}
      </div>
    </main>
  )
}
