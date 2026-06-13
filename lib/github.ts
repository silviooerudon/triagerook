export type GitHubRepo = {
  id: number
  name: string
  full_name: string
  description: string | null
  private: boolean
  html_url: string
  language: string | null
  updated_at: string
  default_branch: string
  stargazers_count: number
  owner: {
    login: string
    avatar_url: string
  }
}

import { buildGitHubHeaders } from "./github-fetch"

// GitHub returns at most 100 repos per page. The dashboard prints the count
// ("N repositories found"), so fetching a single page silently truncated the
// list — a user with >30 owned public repos saw the wrong number and a missing
// repo. Page through until a short page signals the end, with a safety cap so a
// pathological account can't fan out unbounded requests.
const REPOS_PER_PAGE = 100
const MAX_REPO_PAGES = 10 // up to 1000 owned public repos

export async function fetchUserRepos(accessToken: string): Promise<GitHubRepo[]> {
  const all: GitHubRepo[] = []

  for (let page = 1; page <= MAX_REPO_PAGES; page++) {
    const response = await fetch(
      `https://api.github.com/user/repos?per_page=${REPOS_PER_PAGE}&page=${page}&sort=updated&affiliation=owner&visibility=public`,
      {
        headers: buildGitHubHeaders(accessToken),
        // Always read fresh — the dashboard reflects live repo state.
        cache: "no-store",
      }
    )

    if (!response.ok) {
      throw new Error(`GitHub API error: ${response.status} ${response.statusText}`)
    }

    const batch = (await response.json()) as GitHubRepo[]
    all.push(...batch)
    if (batch.length < REPOS_PER_PAGE) break // last page reached
  }

  return all
}