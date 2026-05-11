import { auth } from "@/auth"
import { NextResponse } from "next/server"
import type { PrioritizedFinding } from "@/lib/risk"
import { findingSupportsFix, runFixEngine } from "@/lib/fix-engines"
import { getInstallationToken, getFileContent, getRepoDefaultBranch } from "@/lib/octokit-app"
import { isSafeRepoFilePath } from "@/lib/path-validation"
import { userHasPushAccess } from "@/lib/repo-access"

const SAFE_OWNER_REPO = /^[A-Za-z0-9._-]+$/

export const dynamic = "force-dynamic"

type RequestBody = {
  owner: string
  repo: string
  finding: PrioritizedFinding
}

export async function POST(request: Request) {
  const session = await auth()
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  let body: RequestBody
  try {
    body = (await request.json()) as RequestBody
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 })
  }

  const { owner, repo, finding } = body
  if (!owner || !repo || !finding) {
    return NextResponse.json(
      { error: "Missing required fields: owner, repo, finding" },
      { status: 400 }
    )
  }
  if (!SAFE_OWNER_REPO.test(owner) || !SAFE_OWNER_REPO.test(repo)) {
    return NextResponse.json({ error: "Invalid owner or repo format" }, { status: 400 })
  }

  // Auth gate: the caller must demonstrate (via their own GitHub access
  // token) that they have push access to this repo. Without this check,
  // any logged-in RepoGuard user could trigger a fix preview / PR on
  // any repo where the GitHub App happens to be installed.
  const userToken = session.accessToken
  if (!userToken) {
    return NextResponse.json({ error: "No access token in session" }, { status: 401 })
  }
  if (!(await userHasPushAccess(userToken, owner, repo))) {
    return NextResponse.json(
      { error: "You do not have push access to this repository" },
      { status: 403 }
    )
  }

  const supportedKind = findingSupportsFix(finding)
  if (!supportedKind) {
    return NextResponse.json(
      { error: "This finding is not supported for auto-fix in v1" },
      { status: 422 }
    )
  }

  let token: string
  try {
    token = await getInstallationToken()
  } catch (err) {
    console.error("[fix-preview] Failed to get installation token:", err)
    return NextResponse.json(
      { error: "GitHub App auth failed (is the app installed on this repo?)" },
      { status: 500 }
    )
  }

  const targetPath = resolveTargetPath(finding)
  if (!targetPath) {
    return NextResponse.json(
      { error: "Cannot resolve target file path from finding" },
      { status: 422 }
    )
  }
  // Defence-in-depth: even though the finding came from our own scan,
  // it arrives via the request body and could be tampered with.
  if (!isSafeRepoFilePath(targetPath)) {
    return NextResponse.json(
      { error: "Refusing finding with unsafe file path" },
      { status: 400 }
    )
  }

  let defaultBranch: string
  let fileContent: string
  let envExampleContent: string | null = null

  try {
    defaultBranch = await getRepoDefaultBranch(token, owner, repo)
    fileContent = await getFileContent(token, owner, repo, targetPath, defaultBranch)
  } catch (err) {
    console.error("[fix-preview] Failed to fetch repo state:", err)
    return NextResponse.json(
      { error: "Could not fetch repository state via the GitHub App" },
      { status: 502 }
    )
  }

  if (supportedKind === "secret-extract") {
    try {
      envExampleContent = await getFileContent(token, owner, repo, ".env.example", defaultBranch)
    } catch {
      envExampleContent = null
    }
  }

  let result
  try {
    result = runFixEngine({ finding, fileContent, envExampleContent })
  } catch (err) {
    const message = err instanceof Error ? err.message : "Engine failed"
    return NextResponse.json({ error: message }, { status: 422 })
  }

  return NextResponse.json({
    kind: result.kind,
    summary: result.summary,
    patches: result.patches,
    baseBranch: defaultBranch,
  })
}

function resolveTargetPath(finding: PrioritizedFinding): string | null {
  if (finding.kind === "dependency") {
    return finding.data.source ?? null
  }
  if (finding.kind === "secret" || finding.kind === "code") {
    return finding.data.filePath
  }
  return null
}
