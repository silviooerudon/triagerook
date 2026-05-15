import { GitHubRateLimitError, parseGitHubRateLimit } from "./scan"
import { detectPrivilegeEscalation } from "./iam-privesc"
import { detectAdminEquivalents } from "./iam-admin"
import { buildGitHubHeaders } from "./github-fetch"

export type IAMSeverity = "critical" | "high" | "medium" | "low"

export type IAMLevel = "low" | "medium" | "high" | "critical"

export type IAMCategoryId = "oidc" | "privesc" | "admin"

export type IAMFinding = {
  ruleId: string
  ruleName: string
  severity: IAMSeverity
  category: IAMCategoryId
  description: string
  remediation: string
  filePath: string
  lineNumber: number | null
  evidence: string | null
}

export type IAMCategoryBreakdown = {
  id: IAMCategoryId
  label: string
  findings: number
  highestSeverity: IAMSeverity | null
}

export type IAMResult = {
  score: number
  level: IAMLevel
  breakdown: IAMCategoryBreakdown[]
  findings: IAMFinding[]
  filesScanned: number
  degraded: boolean
}

const SEVERITY_DEDUCTION: Record<IAMSeverity, number> = {
  critical: 20,
  high: 10,
  medium: 5,
  low: 2,
}

const SEVERITY_RANK: Record<IAMSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
}

const CATEGORY_LABEL: Record<IAMCategoryId, string> = {
  oidc: "GitHub OIDC trust",
  privesc: "Privilege escalation",
  admin: "Admin equivalents",
}

type GitHubTreeItem = {
  path: string
  type: "blob" | "tree" | "commit"
  size?: number
}

type GitHubTreeResponse = {
  tree: GitHubTreeItem[]
  truncated: boolean
}

async function fetchRepoTreeIam(
  owner: string,
  repo: string,
  branch: string,
  token: string | null,
): Promise<GitHubTreeResponse> {
  const url = `https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`
  const res = await fetch(url, {
    headers: buildGitHubHeaders(token, "application/vnd.github+json"),
    cache: "no-store",
  })
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    throw new Error(`GitHub tree fetch failed: ${res.status}`)
  }
  return (await res.json()) as GitHubTreeResponse
}

async function fetchDefaultBranch(
  owner: string,
  repo: string,
  token: string | null,
): Promise<string | null> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}`,
    {
      headers: buildGitHubHeaders(token, "application/vnd.github+json"),
      cache: "no-store",
    },
  )
  if (res.status === 404) return null
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    throw new Error(`GitHub repo fetch failed: ${res.status}`)
  }
  const json = (await res.json()) as { default_branch?: string }
  return json.default_branch ?? null
}

async function fetchFileRaw(
  owner: string,
  repo: string,
  path: string,
  token: string | null,
): Promise<string | null> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${path}`,
    {
      headers: buildGitHubHeaders(token, "application/vnd.github.v3.raw"),
      cache: "no-store",
    },
  )
  if (res.status === 404) return null
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    throw new Error(`GitHub raw fetch ${path} failed: ${res.status}`)
  }
  return res.text()
}

async function softFail<T>(
  p: Promise<T>,
  fallback: T,
  degradedFlag: { value: boolean },
): Promise<T> {
  try {
    return await p
  } catch (err) {
    if (err instanceof GitHubRateLimitError) throw err
    degradedFlag.value = true
    return fallback
  }
}

// ---------- File selection ----------

const MAX_IAM_FILES = 80
const MAX_IAM_FILE_SIZE = 256 * 1024

/**
 * Heuristic: only fetch files likely to contain IAM policies.
 * Avoids burning rate-limit on package-lock.json, tsconfig.json, etc.
 */
function looksLikeIamFile(path: string): boolean {
  const lower = path.toLowerCase()

  if (lower.includes("node_modules/")) return false
  if (lower.includes("/.next/")) return false
  if (lower.includes("/dist/")) return false
  if (lower.includes("/build/")) return false
  if (lower.endsWith("package-lock.json")) return false
  if (lower.endsWith("package.json")) return false
  if (lower.endsWith("tsconfig.json")) return false
  if (lower.endsWith("composer.lock")) return false

  if (lower.endsWith(".tf")) return true

  if (lower.endsWith("serverless.yml") || lower.endsWith("serverless.yaml")) return true

  const isJson = lower.endsWith(".json")
  const isYaml = lower.endsWith(".yml") || lower.endsWith(".yaml")
  if (!isJson && !isYaml) return false

  const hints = [
    "iam",
    "policy",
    "policies",
    "role",
    "roles",
    "trust",
    "cloudformation",
    "cfn",
    "sam-template",
    "template.yaml",
    "template.yml",
    "template.json",
  ]
  for (const h of hints) {
    if (lower.includes(h)) return true
  }
  return false
}

// ---------- Statement extraction ----------

type IamStatement = {
  effect: string | null
  principal: unknown
  actions: string[]
  resources: string[]
  conditions: unknown
  sourceLine: number | null
  rawSnippet: string
}

function extractStatements(content: string, filePath: string): IamStatement[] {
  const lower = filePath.toLowerCase()

  if (lower.endsWith(".json")) return extractStatementsFromJson(content)
  if (lower.endsWith(".tf")) return extractStatementsFromTerraform(content)
  if (lower.endsWith(".yml") || lower.endsWith(".yaml")) return extractStatementsFromYaml(content)
  return []
}

function extractStatementsFromJson(content: string): IamStatement[] {
  let parsed: unknown
  try {
    parsed = JSON.parse(content)
  } catch {
    return []
  }
  const statements: IamStatement[] = []
  walkForStatements(parsed, statements, content)
  return statements
}

/* eslint-disable @typescript-eslint/no-explicit-any */
function walkForStatements(node: any, out: IamStatement[], rawContent: string): void {
  if (node === null || typeof node !== "object") return
  if (node.Statement && (Array.isArray(node.Statement) || typeof node.Statement === "object")) {
    const stmts = Array.isArray(node.Statement) ? node.Statement : [node.Statement]
    for (const s of stmts) {
      if (s && typeof s === "object") {
        out.push(toStatement(s, rawContent))
      }
    }
  }
  if (Array.isArray(node)) {
    for (const child of node) walkForStatements(child, out, rawContent)
  } else {
    for (const k of Object.keys(node)) {
      walkForStatements(node[k], out, rawContent)
    }
  }
}

function toStatement(s: any, rawContent: string): IamStatement {
  const actions = normaliseStringList(s.Action ?? s.action)
  const notActions = normaliseStringList(s.NotAction ?? s.notAction)
  const resources = normaliseStringList(s.Resource ?? s.resource)
  const allActions = notActions.length > 0
    ? notActions.map((a) => `!${a}`)
    : actions
  const snippet = JSON.stringify(s).slice(0, 300)
  let sourceLine: number | null = null
  const probe = JSON.stringify(s).slice(0, 60)
  if (probe.length > 10) {
    const idx = rawContent.indexOf(probe.slice(1, 30))
    if (idx >= 0) {
      sourceLine = rawContent.slice(0, idx).split("\n").length
    }
  }
  return {
    effect: typeof s.Effect === "string" ? s.Effect : (typeof s.effect === "string" ? s.effect : null),
    principal: s.Principal ?? s.principal ?? null,
    actions: allActions,
    resources,
    conditions: s.Condition ?? s.condition ?? null,
    sourceLine,
    rawSnippet: snippet,
  }
}
/* eslint-enable @typescript-eslint/no-explicit-any */

function normaliseStringList(v: unknown): string[] {
  if (typeof v === "string") return [v]
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string")
  return []
}

function extractStatementsFromTerraform(content: string): IamStatement[] {
  const statements: IamStatement[] = []

  const jsonencodeRe = /jsonencode\s*\(\s*(\{[\s\S]*?\})\s*\)/g
  let m: RegExpExecArray | null
  while ((m = jsonencodeRe.exec(content)) !== null) {
    const inner = m[1]
    const cleaned = hclLikeToJson(inner)
    try {
      const parsed = JSON.parse(cleaned)
      walkForStatements(parsed, statements, content)
    } catch {
      // skip blocks we cannot normalize
    }
  }

  const dataDocRe = /data\s+"aws_iam_policy_document"[^{]*\{([\s\S]*?)\n\}\s*$/gm
  while ((m = dataDocRe.exec(content)) !== null) {
    const body = m[1]
    extractHclStatementBlocks(body, content, statements)
  }

  // Heredoc-style policies: policy = <<EOF { ... } EOF
  // Common in aws_iam_role_policy, aws_iam_user_policy, aws_iam_policy.
  // Supports both <<EOF and <<-EOF (indented), and any tag name (EOF, POLICY, etc.)
  const heredocRe = /<<-?([A-Z_][A-Z0-9_]*)\s*\n([\s\S]*?)\n\s*\1\s*$/gm
  while ((m = heredocRe.exec(content)) !== null) {
    const inner = m[2]
    // Heredoc bodies may contain Terraform interpolations like ${var.x}.
    // Replace them with a JSON-safe placeholder so JSON.parse succeeds.
    const cleaned = inner.replace(/\$\{[^}]+\}/g, "PLACEHOLDER")
    try {
      const parsed = JSON.parse(cleaned)
      walkForStatements(parsed, statements, content)
    } catch {
      // skip blocks that are not valid JSON (e.g. shell scripts in user_data)
    }
  }

  return statements
}

function hclLikeToJson(s: string): string {
  return s
    .replace(/^\s*#.*$/gm, "")
    .replace(/\/\/.*$/gm, "")
    .replace(/,(\s*[}\]])/g, "$1")
}

function extractHclStatementBlocks(
  body: string,
  fullContent: string,
  out: IamStatement[],
): void {
  const stmtRe = /statement\s*\{([\s\S]*?)\n\s*\}/g
  let m: RegExpExecArray | null
  while ((m = stmtRe.exec(body)) !== null) {
    const block = m[1]
    const effect = matchSingle(block, /effect\s*=\s*"([^"]+)"/i)
    const actions = matchAllStringList(block, /actions\s*=\s*\[([^\]]*)\]/i)
    const notActions = matchAllStringList(block, /not_actions\s*=\s*\[([^\]]*)\]/i)
    const resources = matchAllStringList(block, /resources\s*=\s*\[([^\]]*)\]/i)
    const principals: string[] = []
    const principalsRe = /principals\s*\{[^}]*type\s*=\s*"([^"]+)"[^}]*identifiers\s*=\s*\[([^\]]*)\][^}]*\}/g
    let pm: RegExpExecArray | null
    while ((pm = principalsRe.exec(block)) !== null) {
      const ids = pm[2]
        .split(",")
        .map((s) => s.trim().replace(/^"|"$/g, ""))
        .filter(Boolean)
      for (const id of ids) {
        principals.push(`${pm[1]}:${id}`)
      }
    }
    const hasCondition = /condition\s*\{/.test(block)
    const allActions = notActions.length > 0
      ? notActions.map((a) => `!${a}`)
      : actions
    let sourceLine: number | null = null
    const idx = fullContent.indexOf(m[0])
    if (idx >= 0) sourceLine = fullContent.slice(0, idx).split("\n").length
    out.push({
      effect: effect ?? "Allow",
      principal: principals.length > 0 ? { hcl: principals } : null,
      actions: allActions,
      resources,
      conditions: hasCondition ? { hcl: true } : null,
      sourceLine,
      rawSnippet: m[0].slice(0, 300),
    })
  }
}

function matchSingle(s: string, re: RegExp): string | null {
  const m = s.match(re)
  return m ? m[1] : null
}

function matchAllStringList(s: string, re: RegExp): string[] {
  const m = s.match(re)
  if (!m) return []
  return m[1]
    .split(",")
    .map((x) => x.trim().replace(/^"|"$/g, ""))
    .filter(Boolean)
}

function extractStatementsFromYaml(content: string): IamStatement[] {
  if (!/^\s*Statement:/m.test(content) && !/^\s*statement:/m.test(content)) {
    return []
  }
  const lines = content.split(/\r?\n/)
  const statements: IamStatement[] = []
  let inStatement = false
  let baseIndent = -1
  let currentBlock: string[] = []
  let currentStartLine = 0
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const trimmed = line.trim()
    if (/^Statement\s*:\s*$/i.test(trimmed)) {
      inStatement = true
      baseIndent = line.search(/\S/)
      continue
    }
    if (!inStatement) continue
    const indent = line.search(/\S/)
    if (indent <= baseIndent && trimmed.length > 0) {
      if (currentBlock.length > 0) {
        const stmt = parseYamlStatementBlock(currentBlock, currentStartLine + 1)
        if (stmt) statements.push(stmt)
      }
      inStatement = false
      currentBlock = []
      continue
    }
    if (trimmed.startsWith("- ") || trimmed === "-") {
      if (currentBlock.length > 0) {
        const stmt = parseYamlStatementBlock(currentBlock, currentStartLine + 1)
        if (stmt) statements.push(stmt)
      }
      currentBlock = [line]
      currentStartLine = i
    } else if (currentBlock.length > 0) {
      currentBlock.push(line)
    }
  }
  if (currentBlock.length > 0) {
    const stmt = parseYamlStatementBlock(currentBlock, currentStartLine + 1)
    if (stmt) statements.push(stmt)
  }
  return statements
}

function parseYamlStatementBlock(
  blockLines: string[],
  startLine: number,
): IamStatement | null {
  const blockText = blockLines.join("\n")
  const effect = matchSingle(blockText, /^[\s-]*Effect\s*:\s*"?([A-Za-z]+)"?/m)
  const actions = parseYamlList(blockText, /Action\s*:\s*([\s\S]*?)(?:\n\s+[A-Z][a-z]+\s*:|$)/)
  const notActions = parseYamlList(blockText, /NotAction\s*:\s*([\s\S]*?)(?:\n\s+[A-Z][a-z]+\s*:|$)/)
  const resources = parseYamlList(blockText, /Resource\s*:\s*([\s\S]*?)(?:\n\s+[A-Z][a-z]+\s*:|$)/)
  const principalText = matchSingle(blockText, /Principal\s*:\s*([\s\S]*?)(?:\n\s+[A-Z][a-z]+\s*:|$)/)
  const conditionText = /Condition\s*:/i.test(blockText)
  const allActions = notActions.length > 0
    ? notActions.map((a) => `!${a}`)
    : actions
  return {
    effect: effect ?? null,
    principal: principalText ? { yaml: principalText.trim() } : null,
    actions: allActions,
    resources,
    conditions: conditionText ? { yaml: true } : null,
    sourceLine: startLine,
    rawSnippet: blockText.slice(0, 300),
  }
}

function parseYamlList(text: string, re: RegExp): string[] {
  const m = text.match(re)
  if (!m) return []
  const body = m[1].trim()
  if (body.startsWith("[")) {
    return body
      .replace(/^\[|\]$/g, "")
      .split(",")
      .map((s) => s.trim().replace(/^"|"$/g, ""))
      .filter(Boolean)
  }
  if (!body.includes("\n") && !body.startsWith("-")) {
    return [body.replace(/^"|"$/g, "")]
  }
  return body
    .split(/\n/)
    .map((l) => l.trim())
    .filter((l) => l.startsWith("-"))
    .map((l) => l.replace(/^-\s*/, "").replace(/^"|"$/g, ""))
    .filter(Boolean)
}

// ---------- OIDC detection ----------

const GITHUB_OIDC_HOST = "token.actions.githubusercontent.com"

function isGithubOidcTrust(stmt: IamStatement): boolean {
  if (stmt.effect && stmt.effect.toLowerCase() !== "allow") return false
  if (!stmt.actions.some((a) => /sts:AssumeRoleWithWebIdentity/i.test(a))) return false
  return principalMentionsGithubOidc(stmt.principal)
}

function principalMentionsGithubOidc(principal: unknown): boolean {
  if (!principal) return false
  const flat = JSON.stringify(principal).toLowerCase()
  return flat.includes(GITHUB_OIDC_HOST)
}

function getOidcSubConstraint(stmt: IamStatement): {
  hasCondition: boolean
  subValue: string | null
  operator: string | null
} {
  if (!stmt.conditions) return { hasCondition: false, subValue: null, operator: null }
  const conditions = stmt.conditions as Record<string, unknown>
  if ("hcl" in conditions || "yaml" in conditions) {
    return { hasCondition: true, subValue: null, operator: null }
  }
  for (const op of Object.keys(conditions)) {
    const inner = conditions[op] as Record<string, unknown> | undefined
    if (!inner || typeof inner !== "object") continue
    for (const key of Object.keys(inner)) {
      if (/token\.actions\.githubusercontent\.com:sub/i.test(key)) {
        const val = inner[key]
        if (typeof val === "string") {
          return { hasCondition: true, subValue: val, operator: op }
        }
        if (Array.isArray(val) && val.length > 0 && typeof val[0] === "string") {
          return { hasCondition: true, subValue: val[0], operator: op }
        }
      }
    }
  }
  return { hasCondition: true, subValue: null, operator: null }
}

function makeFinding(
  ruleId: string,
  ruleName: string,
  severity: IAMSeverity,
  category: IAMCategoryId,
  description: string,
  remediation: string,
  filePath: string,
  stmt: IamStatement,
): IAMFinding {
  return {
    ruleId,
    ruleName,
    severity,
    category,
    description,
    remediation,
    filePath,
    lineNumber: stmt.sourceLine,
    evidence: stmt.rawSnippet,
  }
}

function detectOidcWeaknesses(
  stmt: IamStatement,
  filePath: string,
): IAMFinding[] {
  if (!isGithubOidcTrust(stmt)) return []
  const findings: IAMFinding[] = []
  const { hasCondition, subValue } = getOidcSubConstraint(stmt)

  if (!hasCondition) {
    findings.push(
      makeFinding(
        "iam-oidc-no-condition",
        "GitHub OIDC trust has no Condition block",
        "critical",
        "oidc",
        "This role can be assumed by any GitHub Actions workflow on the public OIDC provider, including workflows in repositories you do not own. Without a Condition restricting the sub claim, the trust relationship is global.",
        "Add a Condition block constraining token.actions.githubusercontent.com:sub to your specific repo and ref, e.g. StringEquals { sub: 'repo:org/repo:ref:refs/heads/main' }.",
        filePath,
        stmt,
      ),
    )
    return findings
  }

  if (subValue === null) {
    return findings
  }

  const subLower = subValue.toLowerCase()

  if (/^repo:[^/:]*\/\*:/.test(subValue) || /^repo:\*:/.test(subValue)) {
    findings.push(
      makeFinding(
        "iam-oidc-wildcard-repo",
        "GitHub OIDC trust uses wildcard repo in sub claim",
        "critical",
        "oidc",
        "The sub constraint matches any repository under the org (or any org). Any user able to push a workflow to a matching repo can assume this role.",
        "Pin the sub to a specific repo in the form 'repo:<org>/<repo>:<context>'. Avoid wildcards in the repo or org segments.",
        filePath,
        stmt,
      ),
    )
    return findings
  }

  if (subLower.endsWith(":pull_request")) {
    findings.push(
      makeFinding(
        "iam-oidc-pull-request-trust",
        "GitHub OIDC trust accepts pull_request context",
        "critical",
        "oidc",
        "The sub claim accepts the pull_request context, which means any pull request - including from a fork by an external contributor - can assume this role with full permissions.",
        "Restrict the trust to specific branches (ref:refs/heads/main) or environments (environment:production) rather than pull_request.",
        filePath,
        stmt,
      ),
    )
    return findings
  }

  if (
    /^repo:[^/:]+\/[^:]+:\*$/.test(subValue) ||
    /^repo:[^/:]+\/[^:]+:ref:\*/.test(subValue) ||
    subValue.endsWith(":*")
  ) {
    findings.push(
      makeFinding(
        "iam-oidc-wildcard-ref",
        "GitHub OIDC trust uses wildcard ref/environment in sub claim",
        "high",
        "oidc",
        "The sub constraint pins the repo but accepts any branch, tag, or environment. An attacker who can push any branch (or open a PR that triggers a workflow) can assume this role.",
        "Pin the sub to a specific branch (':ref:refs/heads/main') or environment (':environment:production').",
        filePath,
        stmt,
      ),
    )
    return findings
  }

  return findings
}

// Test-only export. Do not use outside of scripts/smoke-iam.ts.
export const __testExtractStatements = extractStatements

// ---------- Orchestration ----------

export function computeIAMResult(
  findings: IAMFinding[],
  filesScanned: number,
  degraded: boolean,
): IAMResult {
  let score = 100
  for (const f of findings) {
    score -= SEVERITY_DEDUCTION[f.severity]
  }
  if (score < 0) score = 0

  const level: IAMLevel =
    score >= 90 ? "low" :
    score >= 70 ? "medium" :
    score >= 50 ? "high" : "critical"

  const categories: IAMCategoryId[] = ["oidc", "privesc", "admin"]
  const breakdown: IAMCategoryBreakdown[] = categories.map((id) => {
    const inCat = findings.filter((f) => f.category === id)
    const highest = inCat.reduce<IAMSeverity | null>((acc, f) => {
      if (acc === null) return f.severity
      return SEVERITY_RANK[f.severity] > SEVERITY_RANK[acc] ? f.severity : acc
    }, null)
    return {
      id,
      label: CATEGORY_LABEL[id],
      findings: inCat.length,
      highestSeverity: highest,
    }
  })

  const sorted = [...findings].sort((a, b) => {
    const r = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
    if (r !== 0) return r
    if (a.category !== b.category) return a.category.localeCompare(b.category)
    return a.filePath.localeCompare(b.filePath)
  })

  return {
    score,
    level,
    breakdown,
    findings: sorted,
    filesScanned,
    degraded,
  }
}

export async function assessIAM(
  owner: string,
  repo: string,
  accessToken: string | null,
): Promise<IAMResult> {
  const degradedFlag = { value: false }

  const defaultBranch = await softFail(
    fetchDefaultBranch(owner, repo, accessToken),
    null,
    degradedFlag,
  )
  if (!defaultBranch) {
    return computeIAMResult([], 0, true)
  }

  const tree = await softFail(
    fetchRepoTreeIam(owner, repo, defaultBranch, accessToken),
    null,
    degradedFlag,
  )
  if (!tree) {
    return computeIAMResult([], 0, true)
  }

  const candidates = tree.tree
    .filter((item) => item.type === "blob")
    .filter((item) => looksLikeIamFile(item.path))
    .filter((item) => (item.size ?? 0) <= MAX_IAM_FILE_SIZE)
    .slice(0, MAX_IAM_FILES)

  const findings: IAMFinding[] = []
  let filesScanned = 0
  const BATCH = 8
  for (let i = 0; i < candidates.length; i += BATCH) {
    const batch = candidates.slice(i, i + BATCH)
    const contents = await Promise.all(
      batch.map((item) =>
        softFail(fetchFileRaw(owner, repo, item.path, accessToken), null, degradedFlag),
      ),
    )
    for (let j = 0; j < batch.length; j++) {
      const content = contents[j]
      if (!content) continue
      filesScanned++
      const stmts = extractStatements(content, batch[j].path)
      for (const stmt of stmts) {
        findings.push(...detectOidcWeaknesses(stmt, batch[j].path))
      }
      findings.push(...detectPrivilegeEscalation(stmts, batch[j].path))
      findings.push(...detectAdminEquivalents(stmts, batch[j].path))
    }
  }

  return computeIAMResult(findings, filesScanned, degradedFlag.value)
}
