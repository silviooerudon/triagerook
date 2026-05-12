"use client"

import { useState } from "react"
import type { PrioritizedFinding } from "@/lib/risk"

type Patch = { path: string; content: string }

type PreviewResponse = {
  kind: "dep-bump" | "secret-extract"
  summary: string
  patches: Patch[]
  baseBranch: string
}

type CreatedPrResponse = {
  kind: "dep-bump" | "secret-extract"
  summary: string
  prUrl: string
  prNumber: number
  branch: string
}

type ApiError = {
  message: string
  code: string | null
}

const APP_INSTALL_URL =
  "https://github.com/apps/repoguard-security/installations/new"

type Props = {
  owner: string
  repo: string
  finding: PrioritizedFinding
}

async function readApiError(resp: Response, fallback: string): Promise<ApiError> {
  const body = (await resp.json().catch(() => ({}))) as { error?: string; code?: string }
  return {
    message: body.error ?? `${fallback} (${resp.status})`,
    code: body.code ?? null,
  }
}

export function FixPrButton({ owner, repo, finding }: Props) {
  const [open, setOpen] = useState(false)
  const [preview, setPreview] = useState<PreviewResponse | null>(null)
  const [createdPr, setCreatedPr] = useState<CreatedPrResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)

  async function openModal() {
    setOpen(true)
    setError(null)
    setCreatedPr(null)
    if (preview) return
    setLoading(true)
    try {
      const resp = await fetch("/api/findings/fix-preview", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ owner, repo, finding }),
      })
      if (!resp.ok) {
        setError(await readApiError(resp, "Preview failed"))
        return
      }
      const data: PreviewResponse = await resp.json()
      setPreview(data)
    } catch (err) {
      setError({
        message: err instanceof Error ? err.message : "Preview failed",
        code: null,
      })
    } finally {
      setLoading(false)
    }
  }

  function closeModal() {
    setOpen(false)
  }

  async function confirmAndCreate() {
    setLoading(true)
    setError(null)
    try {
      const resp = await fetch("/api/findings/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ owner, repo, finding }),
      })
      if (!resp.ok) {
        setError(await readApiError(resp, "PR creation failed"))
        return
      }
      const data: CreatedPrResponse = await resp.json()
      setCreatedPr(data)
    } catch (err) {
      setError({
        message: err instanceof Error ? err.message : "PR creation failed",
        code: null,
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={openModal}
        className="text-xs px-3 py-1.5 rounded-lg border border-blue-500/40 bg-blue-500/10 text-blue-300 hover:bg-blue-500/20 transition"
      >
        Open fix PR
      </button>
      {open && (
        <FixModal
          loading={loading}
          error={error}
          preview={preview}
          createdPr={createdPr}
          onClose={closeModal}
          onConfirm={confirmAndCreate}
        />
      )}
    </>
  )
}

function FixModal({
  loading,
  error,
  preview,
  createdPr,
  onClose,
  onConfirm,
}: {
  loading: boolean
  error: ApiError | null
  preview: PreviewResponse | null
  createdPr: CreatedPrResponse | null
  onClose: () => void
  onConfirm: () => void
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
      onClick={onClose}
    >
      <div
        className="bg-slate-900 border border-slate-800 rounded-xl shadow-2xl max-w-3xl w-full max-h-[85vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        <header className="flex items-start justify-between px-6 py-4 border-b border-slate-800">
          <div>
            <h2 className="font-semibold text-white">
              {createdPr ? "Pull request opened" : "Preview fix"}
            </h2>
            {preview && !createdPr && (
              <p className="text-sm text-slate-400 mt-1">{preview.summary}</p>
            )}
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-400 hover:text-white px-2 leading-none text-xl"
            aria-label="Close"
          >
            ×
          </button>
        </header>

        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-4">
          {loading && (
            <p className="text-slate-300 text-sm flex items-center gap-2">
              <span className="inline-block w-4 h-4 border-2 border-blue-500/30 border-t-blue-500 rounded-full animate-spin" />
              {createdPr ? "Done." : preview ? "Opening pull request…" : "Loading preview…"}
            </p>
          )}

          {error && error.code === "app_not_installed" && (
            <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 space-y-2">
              <p className="text-amber-300 text-sm font-semibold">
                RepoGuard Security App not installed on this repo
              </p>
              <p className="text-amber-200/80 text-sm">
                The App needs to be granted access to this repository before
                RepoGuard can open a pull request. You stay in control of which
                repos are exposed — the App only sees what you select.
              </p>
              <a
                href={APP_INSTALL_URL}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-block text-sm text-amber-200 hover:underline"
              >
                Configure repository access →
              </a>
            </div>
          )}

          {error && error.code !== "app_not_installed" && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
              <p className="text-red-300 text-sm">{error.message}</p>
            </div>
          )}

          {createdPr && (
            <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4 space-y-2">
              <p className="text-green-300 text-sm">
                PR <span className="font-mono">#{createdPr.prNumber}</span> opened on the{" "}
                <span className="font-mono">{createdPr.branch}</span> branch.
              </p>
              <a
                href={createdPr.prUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-block text-sm text-blue-300 hover:underline"
              >
                Open on GitHub →
              </a>
            </div>
          )}

          {preview && !createdPr && (
            <>
              <p className="text-xs text-slate-500">
                Base branch: <span className="font-mono">{preview.baseBranch}</span>
              </p>
              {preview.patches.map((patch) => (
                <div key={patch.path}>
                  <p className="text-xs uppercase tracking-wider text-slate-400 mb-1 font-mono">
                    {patch.path}
                  </p>
                  <pre className="font-mono text-xs bg-black/40 border border-slate-800 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap text-slate-300 max-h-64 overflow-y-auto">
                    <code>{patch.content}</code>
                  </pre>
                </div>
              ))}
              <p className="text-xs text-slate-500">
                RepoGuard will commit these files on a new branch and open a pull request.
                Nothing touches your default branch until you review and merge.
              </p>
            </>
          )}
        </div>

        <footer className="px-6 py-4 border-t border-slate-800 flex items-center justify-end gap-3">
          <button
            type="button"
            onClick={onClose}
            className="text-sm px-4 py-2 rounded-lg border border-slate-700 text-slate-300 hover:bg-slate-800/50 transition"
          >
            {createdPr ? "Close" : "Cancel"}
          </button>
          {!createdPr && preview && (
            <button
              type="button"
              onClick={onConfirm}
              disabled={loading}
              className="text-sm px-4 py-2 rounded-lg bg-blue-500 hover:bg-blue-600 text-white transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Open pull request
            </button>
          )}
        </footer>
      </div>
    </div>
  )
}

export default FixPrButton
