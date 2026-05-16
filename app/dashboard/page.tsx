import { auth, getAccessToken } from "@/auth"
import Link from "next/link"
import { fetchUserRepos, type GitHubRepo } from "@/lib/github"
import { AlertTriangleIcon, StarIcon } from "@/app/components/icons"
import { getUserId } from "@/lib/auth-utils"
import { supabase } from "@/lib/supabase"

// Shape of the last-scan badge surfaced on each repo card. Built from
// a single query that returns the user's most recent scan per repo.
type LastScan = {
  id: string
  scanned_at: string
  secrets_count: number
  deps_count: number
  risk_score: number | null
}

// Returns a map of "owner/repo" → most recent scan for this user.
// One DB round-trip per dashboard load; we sort + dedupe in memory
// rather than per-repo to keep latency flat regardless of repo count.
async function fetchLatestScansByRepo(
  userId: string,
): Promise<Map<string, LastScan>> {
  const { data, error } = await supabase
    .from("scans")
    .select("id, owner, repo, scanned_at, secrets_count, deps_count, risk_score")
    .eq("user_id", userId)
    .order("scanned_at", { ascending: false })
    .limit(200)

  if (error || !data) return new Map()

  const map = new Map<string, LastScan>()
  for (const row of data) {
    const key = `${row.owner}/${row.repo}`
    if (!map.has(key)) {
      map.set(key, {
        id: row.id,
        scanned_at: row.scanned_at,
        secrets_count: row.secrets_count,
        deps_count: row.deps_count,
        risk_score: row.risk_score,
      })
    }
  }
  return map
}

// Auth gate + AppNav are handled by app/dashboard/layout.tsx — pages
// only render content beneath the nav.
export default async function Dashboard() {
  const accessToken = await getAccessToken()
  const session = await auth()
  const userId = getUserId(session)

  let repos: GitHubRepo[] = []
  let fetchError: string | null = null
  let latestScans = new Map<string, LastScan>()

  if (accessToken) {
    try {
      const [reposResult, scansResult] = await Promise.all([
        fetchUserRepos(accessToken),
        userId
          ? fetchLatestScansByRepo(userId)
          : Promise.resolve(new Map<string, LastScan>()),
      ])
      repos = reposResult
      latestScans = scansResult
    } catch (error) {
      fetchError = error instanceof Error ? error.message : "Unknown error"
    }
  } else {
    fetchError = "No access token found in session"
  }

  return (
    <main className="px-6 py-12">
      <div className="max-w-5xl mx-auto">
        <div className="mb-10">
          <h1 className="font-display text-3xl md:text-4xl font-bold tracking-tight mb-2">
            Your repositories
          </h1>
          <p className="text-slate-400 text-sm">
            {fetchError
              ? "Could not load repositories."
              : `${repos.length} ${repos.length === 1 ? "repository" : "repositories"} found. Select one to scan for security issues.`}
          </p>
          <p className="text-slate-500 text-xs mt-2 font-mono">
            public repos only · private support on the roadmap
          </p>
        </div>

        {fetchError && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 mb-6">
            <p className="text-red-400 text-sm flex items-center gap-2">
              <AlertTriangleIcon size={14} aria-hidden="true" />
              {fetchError}
            </p>
          </div>
        )}

        {!fetchError && repos.length === 0 && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-8">
            <p className="font-mono text-xs text-amber-400 mb-2">
              {"// no public repos"}
            </p>
            <h2 className="font-display text-xl md:text-2xl font-bold mb-2 tracking-tight">
              nothing to scan yet.
            </h2>
            <p className="text-slate-400 text-sm leading-relaxed max-w-md">
              RepoGuard can only see your public repositories. Create one on
              GitHub, refresh this page, and scan it in one click.
            </p>
            <a
              href="https://github.com/new"
              target="_blank"
              rel="noopener noreferrer"
              className="mt-5 inline-flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-amber-400 border-b border-dashed border-slate-700 hover:border-amber-400 transition"
            >
              → create a repo on github
            </a>
          </div>
        )}

        {!fetchError && repos.length > 0 && (
          <div className="grid gap-3">
            {repos.map((repo) => {
              const last = latestScans.get(`${repo.owner.login}/${repo.name}`)
              return (
                <div
                  key={repo.id}
                  className="bg-slate-900 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <h3 className="font-semibold text-lg truncate mb-1 font-mono">
                        {repo.name}
                      </h3>

                      {repo.description && (
                        <p className="text-slate-400 text-sm mb-3 line-clamp-2">
                          {repo.description}
                        </p>
                      )}

                      <div className="flex items-center gap-4 text-xs text-slate-500 flex-wrap font-mono">
                        {repo.language && (
                          <span className="flex items-center gap-1">
                            <span className="w-2 h-2 rounded-full bg-amber-400" />
                            {repo.language}
                          </span>
                        )}
                        <span className="inline-flex items-center gap-1">
                          <StarIcon size={12} aria-hidden="true" />
                          {repo.stargazers_count}
                        </span>
                        <span>
                          Updated{" "}
                          {new Date(repo.updated_at).toLocaleDateString(
                            "en-US",
                            { month: "short", day: "numeric", year: "numeric" },
                          )}
                        </span>
                      </div>
                    </div>

                    <Link
                      href={`/dashboard/scan/${repo.owner.login}/${repo.name}?branch=${encodeURIComponent(repo.default_branch)}`}
                      className="shrink-0 px-4 py-2 rounded-lg bg-amber-400 hover:bg-amber-300 transition text-slate-950 text-sm font-medium"
                    >
                      {last ? "Rescan" : "Scan"}
                    </Link>
                  </div>

                  {last && <LastScanBadge scan={last} />}
                </div>
              )
            })}
          </div>
        )}
      </div>
    </main>
  )
}

// Inline-strip rendered under a repo card when a scan exists. Reads
// like a CLI status line: "last scan: 3d ago · 12 findings · 87/100".
// Colour comes from health score (100 - penalty) so it matches the
// gauge on the result page.
function LastScanBadge({ scan }: { scan: LastScan }) {
  const findings = scan.secrets_count + scan.deps_count
  const health =
    typeof scan.risk_score === "number"
      ? Math.max(0, Math.min(100, 100 - scan.risk_score))
      : null
  const healthColor =
    health === null
      ? "text-slate-500"
      : health >= 90
        ? "text-emerald-400"
        : health >= 70
          ? "text-sky-400"
          : health >= 50
            ? "text-yellow-400"
            : "text-red-400"

  return (
    <Link
      href={`/dashboard/scan/view/${scan.id}`}
      className="mt-4 pt-3 border-t border-slate-800/60 flex items-center gap-x-5 gap-y-1 flex-wrap text-xs font-mono text-slate-500 hover:text-slate-300 transition"
    >
      <span>
        last scan{" "}
        <span className="text-slate-300">{formatRelative(scan.scanned_at)}</span>
      </span>
      <span>
        findings{" "}
        <span
          className={
            findings === 0 ? "text-emerald-400" : "text-amber-300"
          }
        >
          {findings}
        </span>
      </span>
      {health !== null && (
        <span>
          health <span className={healthColor}>{health}/100</span>
        </span>
      )}
      <span className="text-slate-600 ml-auto">→ view</span>
    </Link>
  )
}

// Compact relative-time formatter ("3h ago", "2d ago", "5w ago"). For
// scans older than 60 days we fall back to a short absolute date — at
// that age relative readings stop being useful.
function formatRelative(iso: string): string {
  const then = new Date(iso).getTime()
  const now = Date.now()
  const diffMs = Math.max(0, now - then)
  const min = Math.floor(diffMs / 60_000)
  if (min < 1) return "just now"
  if (min < 60) return `${min}m ago`
  const hr = Math.floor(min / 60)
  if (hr < 24) return `${hr}h ago`
  const d = Math.floor(hr / 24)
  if (d < 7) return `${d}d ago`
  const w = Math.floor(d / 7)
  if (w < 9) return `${w}w ago`
  return new Date(iso).toLocaleDateString("en-GB", {
    day: "2-digit",
    month: "short",
  })
}
