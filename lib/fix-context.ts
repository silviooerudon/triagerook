import type { Session } from "next-auth"
import type { PrioritizedFinding } from "@/lib/risk"
import { findingSupportsFix, runFixEngine, type RunFixResult } from "@/lib/fix-engines"
import { getInstallationToken, getFileContent, getRepoDefaultBranch } from "@/lib/octokit-app"
import { isSafeRepoFilePath } from "@/lib/path-validation"
import { userHasPushAccess } from "@/lib/repo-access"

// Shared between POST /api/findings/fix-preview and POST /api/findings/fix.
// Both routes need the same gates (auth + owner/repo regex + push access +
// supported kind + installation token + safe target path + file fetch +
// engine execution) before they diverge — fix-preview returns the engine
// result, fix goes on to open a PR with it.

const SAFE_OWNER_REPO = /^[A-Za-z0-9._-]+$/

export type FixContextRequestBody = {
  owner: string
  repo: string
  finding: PrioritizedFinding
}

export type FixContext = {
  token: string
  owner: string
  repo: string
  finding: PrioritizedFinding
  defaultBranch: string
  engineResult: RunFixResult
}

export type FixContextOutcome =
  | { ok: true; ctx: FixContext }
  | { ok: false; status: number; error: string }

function resolveTargetPath(finding: PrioritizedFinding): string | null {
  if (finding.kind === "dependency") return finding.data.source ?? null
  if (finding.kind === "secret" || finding.kind === "code") return finding.data.filePath
  return null
}

export async function prepareFixContext(
  session: Session,
  body: FixContextRequestBody,
  logPrefix: string,
): Promise<FixContextOutcome> {
  const { owner, repo, finding } = body
  if (!owner || !repo || !finding) {
    return { ok: false, status: 400, error: "Missing required fields: owner, repo, finding" }
  }
  if (!SAFE_OWNER_REPO.test(owner) || !SAFE_OWNER_REPO.test(repo)) {
    return { ok: false, status: 400, error: "Invalid owner or repo format" }
  }

  const userToken = session.accessToken
  if (!userToken) {
    return { ok: false, status: 401, error: "No access token in session" }
  }
  if (!(await userHasPushAccess(userToken, owner, repo))) {
    return { ok: false, status: 403, error: "You do not have push access to this repository" }
  }

  const supportedKind = findingSupportsFix(finding)
  if (!supportedKind) {
    return { ok: false, status: 422, error: "This finding is not supported for auto-fix in v1" }
  }

  let token: string
  try {
    token = await getInstallationToken()
  } catch (err) {
    console.error(`[${logPrefix}] Failed to get installation token:`, err)
    return {
      ok: false,
      status: 500,
      error: "GitHub App auth failed (is the app installed on this repo?)",
    }
  }

  const targetPath = resolveTargetPath(finding)
  if (!targetPath) {
    return { ok: false, status: 422, error: "Cannot resolve target file path from finding" }
  }
  if (!isSafeRepoFilePath(targetPath)) {
    return { ok: false, status: 400, error: "Refusing finding with unsafe file path" }
  }

  let defaultBranch: string
  let fileContent: string
  let envExampleContent: string | null = null

  try {
    defaultBranch = await getRepoDefaultBranch(token, owner, repo)
    fileContent = await getFileContent(token, owner, repo, targetPath, defaultBranch)
  } catch (err) {
    console.error(`[${logPrefix}] Failed to fetch repo state:`, err)
    return {
      ok: false,
      status: 502,
      error: "Could not fetch repository state via the GitHub App",
    }
  }

  if (supportedKind === "secret-extract") {
    try {
      envExampleContent = await getFileContent(token, owner, repo, ".env.example", defaultBranch)
    } catch {
      envExampleContent = null
    }
  }

  let engineResult: RunFixResult
  try {
    engineResult = runFixEngine({ finding, fileContent, envExampleContent })
  } catch (err) {
    const message = err instanceof Error ? err.message : "Engine failed"
    return { ok: false, status: 422, error: message }
  }

  return {
    ok: true,
    ctx: { token, owner, repo, finding, defaultBranch, engineResult },
  }
}
