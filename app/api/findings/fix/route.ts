import { auth } from "@/auth"
import { NextResponse } from "next/server"
import type { PrioritizedFinding } from "@/lib/risk"
import { findingSupportsFix, runFixEngine } from "@/lib/fix-engines"
import {
  getInstallationToken,
  getFileContent,
  getRepoDefaultBranch,
  createPullRequestFromPatches,
} from "@/lib/octokit-app"
import { isSafeRepoFilePath } from "@/lib/path-validation"
import { userHasPushAccess } from "@/lib/repo-access"

const SAFE_OWNER_REPO = /^[A-Za-z0-9._-]+$/

export const dynamic = "force-dynamic"

type RequestBody = {
  owner: string
  repo: string
  finding: PrioritizedFinding
}

function slugify(input: string): string {
  return input
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40)
}

function timeSuffix(): string {
  const d = new Date()
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${d.getUTCFullYear()}${pad(d.getUTCMonth() + 1)}${pad(d.getUTCDate())}-${pad(d.getUTCHours())}${pad(d.getUTCMinutes())}${pad(d.getUTCSeconds())}`
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

  // Auth gate: caller must have push access to the target repo (proven
  // via their own GitHub access token) before we open a PR under the
  // GitHub App identity. Without this check, any logged-in RepoGuard
  // user could open PRs on any repo where the App happens to be
  // installed.
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
    console.error("[fix] Failed to get installation token:", err)
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
    console.error("[fix] Failed to fetch repo state:", err)
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

  let engineResult
  try {
    engineResult = runFixEngine({ finding, fileContent, envExampleContent })
  } catch (err) {
    const message = err instanceof Error ? err.message : "Engine failed"
    return NextResponse.json({ error: message }, { status: 422 })
  }

  const slug = slugify(engineResult.summary)
  const branchName = `repoguard/${supportedKind}-${slug}-${timeSuffix()}`

  const commitMessage = engineResult.summary
  const prTitle = engineResult.summary
  const prBody = buildPrBody(supportedKind, finding, engineResult.summary)

  try {
    const pr = await createPullRequestFromPatches(token, {
      owner,
      repo,
      baseBranch: defaultBranch,
      newBranch: branchName,
      commitMessage,
      prTitle,
      prBody,
      patches: engineResult.patches,
    })

    return NextResponse.json({
      kind: engineResult.kind,
      summary: engineResult.summary,
      prUrl: pr.url,
      prNumber: pr.number,
      branch: branchName,
    })
  } catch (err) {
    console.error("[fix] Failed to create PR:", err)
    const message = err instanceof Error ? err.message : "PR creation failed"
    return NextResponse.json({ error: message }, { status: 502 })
  }
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

function buildPrBody(
  kind: string,
  finding: PrioritizedFinding,
  summary: string
): string {
  const lines = [
    "Automated fix proposed by RepoGuard.",
    "",
    `**Fix:** ${summary}`,
    `**Kind:** \`${kind}\``,
    "",
    "## Finding",
    "",
  ]

  if (finding.kind === "dependency") {
    const d = finding.data
    lines.push(`- Package: \`${d.package}@${d.version}\``)
    lines.push(`- Severity: ${d.severity}`)
    if (d.ghsa) lines.push(`- Advisory: ${d.ghsa}`)
    lines.push(`- Vulnerable versions: \`${d.vulnerable_versions}\``)
    if (d.url) lines.push(`- Details: ${d.url}`)
  } else if (finding.kind === "secret") {
    const d = finding.data
    lines.push(`- Pattern: ${d.patternName}`)
    lines.push(`- Severity: ${d.severity}`)
    lines.push(`- Location: \`${d.filePath}:${d.lineNumber}\``)
  } else if (finding.kind === "code") {
    const d = finding.data
    lines.push(`- Rule: ${d.ruleName}`)
    lines.push(`- Severity: ${d.severity}`)
    lines.push(`- Location: \`${d.filePath}:${d.lineNumber}\``)
    if (d.cwe) lines.push(`- CWE: ${d.cwe}`)
  }

  lines.push("")
  lines.push("## Before merging")
  lines.push("")
  lines.push("- Review the diff manually.")
  lines.push("- Make sure your CI / tests pass on this branch.")

  if (kind === "dep-bump") {
    lines.push("- Run your package manager install command locally to refresh the lockfile.")
  }
  if (kind === "secret-extract") {
    lines.push("- Set the new env var in your deployment (Vercel, etc).")
    lines.push("- Rotate the leaked secret — extracting to env does not invalidate the old value.")
  }

  lines.push("")
  lines.push("Generated by RepoGuard.")
  return lines.join("\n")
}
