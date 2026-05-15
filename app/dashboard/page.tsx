import { getAccessToken } from "@/auth"
import Link from "next/link"
import { fetchUserRepos, type GitHubRepo } from "@/lib/github"
import { AlertTriangleIcon, StarIcon } from "@/app/components/icons"

// Auth gate + AppNav are handled by app/dashboard/layout.tsx — pages
// only render content beneath the nav.
export default async function Dashboard() {
  const accessToken = await getAccessToken()

  let repos: GitHubRepo[] = []
  let fetchError: string | null = null

  if (accessToken) {
    try {
      repos = await fetchUserRepos(accessToken)
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
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center">
            <p className="text-slate-400">
              You don&apos;t have any public repositories yet. Create one on GitHub
              to get started.
            </p>
          </div>
        )}

        {!fetchError && repos.length > 0 && (
          <div className="grid gap-3">
            {repos.map((repo) => (
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
                        {new Date(repo.updated_at).toLocaleDateString("en-US", {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                        })}
                      </span>
                    </div>
                  </div>

                  <Link
                    href={`/dashboard/scan/${repo.owner.login}/${repo.name}?branch=${encodeURIComponent(repo.default_branch)}`}
                    className="shrink-0 px-4 py-2 rounded-lg bg-amber-400 hover:bg-amber-300 transition text-slate-950 text-sm font-medium"
                  >
                    Scan
                  </Link>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </main>
  )
}
