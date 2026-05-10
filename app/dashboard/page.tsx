import { auth, signOut } from "@/auth"
import { redirect } from "next/navigation"
import Link from "next/link"
import { fetchUserRepos, type GitHubRepo } from "@/lib/github"
import { AlertTriangleIcon, StarIcon } from "@/app/components/icons"

export default async function Dashboard() {
  const session = await auth()

  // Guard: se não tem sessão, volta pra landing
  if (!session) {
    redirect("/")
  }

  // @ts-expect-error - accessToken custom field
  const accessToken = session.accessToken as string | undefined

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
    <main className="min-h-screen bg-gradient-to-b from-slate-950 to-slate-900 text-white px-6 py-12">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-12">
          <h1 className="text-3xl font-bold">
            Repo<span className="text-blue-500">Guard</span>
          </h1>

          <div className="flex items-center gap-4">
            {session.user?.image && (
              <img
                src={session.user.image}
                alt={session.user.name ?? "User"}
                className="w-10 h-10 rounded-full border border-slate-700"
              />
            )}
            <span className="text-sm text-slate-400 hidden sm:inline">
              {session.user?.name}
            </span>

            <Link
              href="/dashboard/history"
              className="px-4 py-2 rounded-lg border border-slate-700 hover:border-slate-500 transition text-sm font-medium"
            >
              History
            </Link>

            <form
              action={async () => {
                "use server"
                await signOut({ redirectTo: "/" })
              }}
            >
              <button
                type="submit"
                className="px-4 py-2 rounded-lg border border-slate-700 hover:border-slate-500 transition text-sm font-medium"
              >
                Sign out
              </button>
            </form>
          </div>
        </div>

        {/* Section title */}
        <div className="mb-8">
          <h2 className="text-2xl font-semibold mb-2">Your repositories</h2>
          <p className="text-slate-400 text-sm">
            {fetchError
              ? "Could not load repositories."
              : `${repos.length} ${repos.length === 1 ? "repository" : "repositories"} found. Select one to scan for security issues.`}
          </p>
          <p className="text-slate-500 text-xs mt-2">
            Showing public repositories only. Private repo support coming soon.
          </p>
        </div>

        {/* Error state */}
        {fetchError && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 mb-6">
            <p className="text-red-400 text-sm flex items-center gap-2">
              <AlertTriangleIcon size={14} aria-hidden="true" />
              {fetchError}
            </p>
          </div>
        )}

        {/* Empty state */}
        {!fetchError && repos.length === 0 && (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center">
            <p className="text-slate-400">
              You don&apos;t have any repositories yet. Create one on GitHub to get started.
            </p>
          </div>
        )}

        {/* Repo list */}
        {!fetchError && repos.length > 0 && (
          <div className="grid gap-3">
            {repos.map((repo) => (
              <div
                key={repo.id}
                className="bg-slate-900 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <h3 className="font-semibold text-lg truncate mb-1">
                      {repo.name}
                    </h3>

                    {repo.description && (
                      <p className="text-slate-400 text-sm mb-3 line-clamp-2">
                        {repo.description}
                      </p>
                    )}

                    <div className="flex items-center gap-4 text-xs text-slate-500 flex-wrap">
                      {repo.language && (
                        <span className="flex items-center gap-1">
                          <span className="w-2 h-2 rounded-full bg-blue-500" />
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

                  <a
                    href={`/dashboard/scan/${repo.owner.login}/${repo.name}?branch=${encodeURIComponent(repo.default_branch)}`}
                    className="shrink-0 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 transition text-white text-sm font-medium"
                  >
                    Scan
                  </a>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </main>
  )
}