"use client"

import { useRouter } from "next/navigation"
import { useState } from "react"
import { parseGitHubUrl } from "@/lib/parse-github-url"

export default function PublicScanInput() {
  const router = useRouter()
  const [input, setInput] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  function handleScan() {
    setError(null)
    const parsed = parseGitHubUrl(input)
    if (!parsed) {
      setError(
        "Please enter a valid GitHub repo URL (e.g. https://github.com/owner/repo)",
      )
      return
    }
    setLoading(true)
    router.push(`/scan-public/${parsed.owner}/${parsed.repo}`)
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter") {
      handleScan()
    }
  }

  return (
    <div className="max-w-2xl">
      <div className="flex flex-col sm:flex-row gap-2 group">
        <div className="flex-1 flex items-stretch border border-slate-700 focus-within:border-amber-400 transition bg-slate-950">
          <span
            aria-hidden
            className="px-3 flex items-center font-mono text-amber-400 text-sm select-none border-r border-slate-800"
          >
            ▶
          </span>
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="https://github.com/owner/repo"
            className="flex-1 px-3 py-3 bg-transparent font-mono text-sm text-slate-100 placeholder-slate-600 focus:outline-none"
            disabled={loading}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
          />
        </div>
        <button
          type="button"
          onClick={handleScan}
          disabled={loading || !input.trim()}
          className="px-5 py-3 font-mono text-sm bg-amber-400 text-slate-950 hover:bg-amber-300 disabled:bg-slate-800 disabled:text-slate-600 disabled:cursor-not-allowed transition font-semibold inline-flex items-center justify-center gap-2"
        >
          {loading ? (
            <>
              <span className="inline-block w-2 h-2 bg-slate-950 animate-pulse" />
              scanning…
            </>
          ) : (
            <>scan →</>
          )}
        </button>
      </div>
      {error && (
        <p className="text-red-400 text-xs font-mono mt-2">{"// "}{error}</p>
      )}
      <p className="text-xs font-mono text-slate-500 mt-3">
        {"// no login required · 10 scans/h per IP · 5 scans/h per repo · public repos only"}
      </p>
    </div>
  )
}
