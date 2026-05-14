import type { PrioritizedFinding } from "@/lib/risk"
import { findingSupportsFix, runFixEngine, type RunFixResult } from "@/lib/fix-engines"
import {
  getInstallationTokenForRepo,
  getFileContent,
  getRepoDefaultBranch,
  GitHubAppFetchError,
} from "@/lib/octokit-app"
import { isSafeOwnerRepo, isSafeRepoFilePath } from "@/lib/path-validation"
import { userHasPushAccess } from "@/lib/repo-access"

// Stable error codes the UI can switch on. Keep the set small — every new
// code is a new dialog the user might see.
export type FixContextErrorCode =
  | "invalid_body"
  | "invalid_owner_repo"
  | "missing_access_token"
  | "no_push_access"
  | "unsupported_finding"
  | "app_auth_failed"
  | "app_not_installed"
  | "no_target_path"
  | "unsafe_target_path"
  | "fetch_failed"
  | "engine_failed"

// Shared between POST /api/findings/fix-preview and POST /api/findings/fix.
// Both routes need the same gates (auth + owner/repo regex + push access +
// supported kind + installation token + safe target path + file fetch +
// engine execution) before they diverge — fix-preview returns the engine
// result, fix goes on to open a PR with it.

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
  | { ok: false; status: number; error: string; code: FixContextErrorCode }

function resolveTargetPath(finding: PrioritizedFinding): string | null {
  if (finding.kind === "dependency") return finding.data.source ?? null
  if (finding.kind === "secret" || finding.kind === "code") return finding.data.filePath
  return null
}

export async function prepareFixContext(
  userAccessToken: string | undefined,
  body: FixContextRequestBody,
  logPrefix: string,
): Promise<FixContextOutcome> {
  const { owner, repo, finding } = body
  if (!owner || !repo || !finding) {
    return {
      ok: false,
      status: 400,
      error: "Missing required fields: owner, repo, finding",
      code: "invalid_body",
    }
  }
  if (!isSafeOwnerRepo(owner) || !isSafeOwnerRepo(repo)) {
    return {
      ok: false,
      status: 400,
      error: "Invalid owner or repo format",
      code: "invalid_owner_repo",
    }
  }

  if (!userAccessToken) {
    return {
      ok: false,
      status: 401,
      error: "No access token in session",
      code: "missing_access_token",
    }
  }
  if (!(await userHasPushAccess(userAccessToken, owner, repo))) {
    return {
      ok: false,
      status: 403,
      error: "You do not have push access to this repository",
      code: "no_push_access",
    }
  }

  const supportedKind = findingSupportsFix(finding)
  if (!supportedKind) {
    return {
      ok: false,
      status: 422,
      error: "This finding is not supported for auto-fix in v1",
      code: "unsupported_finding",
    }
  }

  let token: string
  try {
    token = await getInstallationTokenForRepo(owner, repo)
  } catch (err) {
    if (err instanceof GitHubAppFetchError && err.appNotInstalled()) {
      // Surface the install link UI early — we don't need to attempt the
      // file fetch to know the App isn't installed on this repo.
      return {
        ok: false,
        status: 403,
        error: "The RepoGuard Security GitHub App is not installed on this repository",
        code: "app_not_installed",
      }
    }
    console.error(`[${logPrefix}] Failed to get installation token:`, err)
    return {
      ok: false,
      status: 500,
      error: "GitHub App auth failed (server-side credentials missing or invalid)",
      code: "app_auth_failed",
    }
  }

  const targetPath = resolveTargetPath(finding)
  if (!targetPath) {
    return {
      ok: false,
      status: 422,
      error: "Cannot resolve target file path from finding",
      code: "no_target_path",
    }
  }
  if (!isSafeRepoFilePath(targetPath)) {
    return {
      ok: false,
      status: 400,
      error: "Refusing finding with unsafe file path",
      code: "unsafe_target_path",
    }
  }

  let defaultBranch: string
  let fileContent: string
  let envExampleContent: string | null = null

  try {
    defaultBranch = await getRepoDefaultBranch(token, owner, repo)
    fileContent = await getFileContent(token, owner, repo, targetPath, defaultBranch)
  } catch (err) {
    if (err instanceof GitHubAppFetchError && err.appNotInstalled()) {
      return {
        ok: false,
        status: 403,
        error: "The RepoGuard Security GitHub App is not installed on this repository",
        code: "app_not_installed",
      }
    }
    console.error(`[${logPrefix}] Failed to fetch repo state:`, err)
    return {
      ok: false,
      status: 502,
      error: "Could not fetch repository state via the GitHub App",
      code: "fetch_failed",
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
    return { ok: false, status: 422, error: message, code: "engine_failed" }
  }

  return {
    ok: true,
    ctx: { token, owner, repo, finding, defaultBranch, engineResult },
  }
}
