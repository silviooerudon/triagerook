import { createAppAuth } from "@octokit/auth-app"

export type GitHubAppCredentials = {
  appId: string
  privateKey: string
  installationId: string
}

function readEnvCredentials(): GitHubAppCredentials {
  const appId = process.env.AUTH_GITHUB_APP_ID
  const privateKey = process.env.AUTH_GITHUB_APP_PRIVATE_KEY
  const installationId = process.env.AUTH_GITHUB_APP_INSTALLATION_ID

  if (!appId || !privateKey || !installationId) {
    throw new Error(
      "GitHub App credentials missing. Required env vars: AUTH_GITHUB_APP_ID, AUTH_GITHUB_APP_PRIVATE_KEY, AUTH_GITHUB_APP_INSTALLATION_ID"
    )
  }

  return { appId, privateKey, installationId }
}

export async function getInstallationToken(
  credentials: GitHubAppCredentials = readEnvCredentials()
): Promise<string> {
  const auth = createAppAuth({
    appId: credentials.appId,
    privateKey: credentials.privateKey,
    installationId: credentials.installationId,
  })

  const result = await auth({ type: "installation" })
  return result.token
}

const GH_API = "https://api.github.com"

type FetchOptions = {
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE"
  body?: unknown
}

export async function ghFetch<T>(
  token: string,
  path: string,
  options: FetchOptions = {}
): Promise<T> {
  const url = path.startsWith("http") ? path : `${GH_API}${path}`
  const response = await fetch(url, {
    method: options.method ?? "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
    },
    body: options.body ? JSON.stringify(options.body) : undefined,
    cache: "no-store",
  })

  if (!response.ok) {
    const text = await response.text().catch(() => "")
    throw new Error(
      `GitHub API ${options.method ?? "GET"} ${path} failed: ${response.status} ${response.statusText} ${text}`
    )
  }

  return (await response.json()) as T
}

export type FilePatch = {
  path: string
  content: string
}

export type CreatePullRequestParams = {
  owner: string
  repo: string
  baseBranch: string
  newBranch: string
  commitMessage: string
  prTitle: string
  prBody: string
  patches: FilePatch[]
}

type RepoInfo = { default_branch: string }
type RefObject = { object: { sha: string } }
type CreatedPr = { html_url: string; number: number }
type FileBlob = { sha: string; content?: string }

export async function createPullRequestFromPatches(
  token: string,
  params: CreatePullRequestParams
): Promise<{ url: string; number: number }> {
  const { owner, repo, baseBranch, newBranch, commitMessage, prTitle, prBody, patches } = params

  const baseRef = await ghFetch<RefObject>(
    token,
    `/repos/${owner}/${repo}/git/refs/heads/${baseBranch}`
  )
  const baseSha = baseRef.object.sha

  await ghFetch(token, `/repos/${owner}/${repo}/git/refs`, {
    method: "POST",
    body: { ref: `refs/heads/${newBranch}`, sha: baseSha },
  })

  for (const patch of patches) {
    let existingSha: string | undefined
    try {
      const existing = await ghFetch<FileBlob>(
        token,
        `/repos/${owner}/${repo}/contents/${encodeURIComponent(patch.path)}?ref=${newBranch}`
      )
      existingSha = existing.sha
    } catch {
      existingSha = undefined
    }

    await ghFetch(token, `/repos/${owner}/${repo}/contents/${encodeURIComponent(patch.path)}`, {
      method: "PUT",
      body: {
        message: commitMessage,
        content: Buffer.from(patch.content, "utf8").toString("base64"),
        branch: newBranch,
        ...(existingSha ? { sha: existingSha } : {}),
      },
    })
  }

  const pr = await ghFetch<CreatedPr>(token, `/repos/${owner}/${repo}/pulls`, {
    method: "POST",
    body: {
      title: prTitle,
      body: prBody,
      head: newBranch,
      base: baseBranch,
    },
  })

  return { url: pr.html_url, number: pr.number }
}

export async function getRepoDefaultBranch(
  token: string,
  owner: string,
  repo: string
): Promise<string> {
  const info = await ghFetch<RepoInfo>(token, `/repos/${owner}/${repo}`)
  return info.default_branch
}

export async function getFileContent(
  token: string,
  owner: string,
  repo: string,
  path: string,
  ref?: string
): Promise<string> {
  const refQs = ref ? `?ref=${encodeURIComponent(ref)}` : ""
  const blob = await ghFetch<FileBlob>(
    token,
    `/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}${refQs}`
  )
  if (!blob.content) {
    throw new Error(`File ${path} has no content (likely a symlink or directory)`)
  }
  return Buffer.from(blob.content, "base64").toString("utf8")
}
