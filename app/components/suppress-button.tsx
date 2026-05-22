"use client"

import { useEffect, useState } from "react"
import type { PrioritizedFinding } from "@/lib/risk"
import { findRuleIdForFinding, getFindingPath } from "@/lib/suppressions"
import { useModalFocus } from "./use-modal-focus"

type Props = {
  owner: string
  repo: string
  finding: PrioritizedFinding
  onSuppressed?: () => void
}

type Scope = "this-finding" | "rule-everywhere"

export function SuppressButton({ owner, repo, finding, onSuppressed }: Props) {
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState(false)

  const defaultPath = getFindingPath(finding) || "**"
  const ruleId = findRuleIdForFinding(finding)
  const [scope, setScope] = useState<Scope>("this-finding")
  const [reason, setReason] = useState("")
  const [expiresAt, setExpiresAt] = useState("")

  async function submit() {
    setLoading(true)
    setError(null)
    try {
      const pathGlob = scope === "this-finding" ? defaultPath : "**"
      const resp = await fetch("/api/suppressions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          owner,
          repo,
          pathGlob,
          ruleGlob: ruleId,
          reason: reason || null,
          expiresAt: expiresAt || null,
        }),
      })
      if (!resp.ok) {
        const body = await resp.json().catch(() => ({}))
        throw new Error(body.error ?? `Suppress failed (${resp.status})`)
      }
      setDone(true)
      onSuppressed?.()
    } catch (err) {
      setError(err instanceof Error ? err.message : "Suppress failed")
    } finally {
      setLoading(false)
    }
  }

  function closeModal() {
    setOpen(false)
    setError(null)
    setReason("")
    setExpiresAt("")
    setScope("this-finding")
    setDone(false)
  }

  // Esc closes the modal — keyboard parity with the X button and the
  // overlay-click handler. Skips registration when the modal is closed
  // so it does not steal Esc from anything else on the page.
  useEffect(() => {
    if (!open) return
    function handler(e: KeyboardEvent) {
      if (e.key === "Escape") closeModal()
    }
    document.addEventListener("keydown", handler)
    return () => document.removeEventListener("keydown", handler)
  }, [open])

  // Focus trap: Tab cycles within the modal while it's open and focus
  // returns to the trigger button on close. role="dialog" already set.
  const modalRef = useModalFocus(open)

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="text-xs px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800/40 text-slate-300 hover:bg-slate-800 transition"
        title="Hide this finding from your dashboard going forward"
      >
        Suppress
      </button>
      {open && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="suppress-modal-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
          onClick={closeModal}
        >
          <div
            ref={modalRef}
            className="bg-slate-900 border border-amber-400/10 rounded-xl shadow-2xl shadow-amber-400/[0.04] max-w-lg w-full"
            onClick={(e) => e.stopPropagation()}
          >
            <header className="px-6 py-4 border-b border-slate-800/60 flex items-start gap-3">
              <span aria-hidden className="font-mono text-amber-400 text-sm mt-0.5 select-none">
                [T/]
              </span>
              <div className="flex-1 min-w-0">
                <h2
                  id="suppress-modal-title"
                  className="font-display text-lg font-bold text-white tracking-tight"
                >
                  Suppress finding
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Adds a personal suppression for{" "}
                  <span className="font-mono text-slate-200">{ruleId}</span>.
                  Only hidden in{" "}
                  <span className="font-mono">{owner}/{repo}</span>.
                </p>
              </div>
            </header>

            {done ? (
              <div className="px-6 py-4 space-y-3">
                <p className="text-green-300 text-sm">
                  Suppression saved. Future scans of this repo will hide the
                  matching findings until you remove the suppression from
                  /dashboard/suppressions.
                </p>
                <button
                  type="button"
                  onClick={closeModal}
                  className="text-sm px-4 py-2 rounded-lg border border-slate-700 text-slate-200 hover:bg-slate-800/50"
                >
                  Close
                </button>
              </div>
            ) : (
              <div className="px-6 py-4 space-y-4">
                <fieldset className="space-y-2">
                  <legend className="text-xs uppercase tracking-wider text-slate-500">
                    Scope
                  </legend>
                  <label className="flex items-start gap-2 text-sm text-slate-200">
                    <input
                      type="radio"
                      name="scope"
                      value="this-finding"
                      checked={scope === "this-finding"}
                      onChange={() => setScope("this-finding")}
                      className="mt-1"
                    />
                    <span>
                      Only this file:{" "}
                      <span className="font-mono text-slate-300">{defaultPath}</span>
                    </span>
                  </label>
                  <label className="flex items-start gap-2 text-sm text-slate-200">
                    <input
                      type="radio"
                      name="scope"
                      value="rule-everywhere"
                      checked={scope === "rule-everywhere"}
                      onChange={() => setScope("rule-everywhere")}
                      className="mt-1"
                    />
                    <span>This rule across the whole repo</span>
                  </label>
                </fieldset>

                <label className="block">
                  <span className="text-xs uppercase tracking-wider text-slate-500">
                    Reason (optional)
                  </span>
                  <input
                    type="text"
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    placeholder="False positive, fixture, etc."
                    className="mt-1 w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-sm text-slate-200 placeholder:text-slate-500"
                    maxLength={500}
                  />
                </label>

                <label className="block">
                  <span className="text-xs uppercase tracking-wider text-slate-500">
                    Expires (optional)
                  </span>
                  <input
                    type="date"
                    value={expiresAt}
                    onChange={(e) => setExpiresAt(e.target.value)}
                    className="mt-1 w-full px-3 py-2 rounded-lg bg-slate-950 border border-slate-700 text-sm text-slate-200"
                  />
                </label>

                {error && (
                  <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
                    <p className="text-red-300 text-sm">{error}</p>
                  </div>
                )}

                <div className="flex items-center justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={closeModal}
                    className="text-sm px-4 py-2 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800/50"
                  >
                    Cancel
                  </button>
                  <button
                    type="button"
                    onClick={submit}
                    disabled={loading}
                    className="text-sm px-4 py-2 rounded-lg border border-red-500/40 bg-red-500/10 text-red-300 hover:bg-red-500/20 hover:border-red-500/60 transition disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {loading ? "Saving…" : "Suppress"}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  )
}

export default SuppressButton
