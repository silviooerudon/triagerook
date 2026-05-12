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

export async function fetchUserRepos(accessToken: string): Promise<GitHubRepo[]> {
  const response = await fetch(
    "https://api.github.com/user/repos?per_page=30&sort=updated&affiliation=owner&visibility=public",
    {
      headers: buildGitHubHeaders(accessToken),
      // Não cachear — queremos dados frescos
      cache: "no-store",
    }
  )

  if (!response.ok) {
    throw new Error(`GitHub API error: ${response.status} ${response.statusText}`)
  }

  const repos = await response.json()
  return repos as GitHubRepo[]
}