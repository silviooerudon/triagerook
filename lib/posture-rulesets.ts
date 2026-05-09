import { GitHubRateLimitError, parseGitHubRateLimit } from "./scan"
import type { RulesetBypassFinding } from "./types"

// Reads GitHub repository rulesets to surface branch protection signals the
// classic /repos/.../branches/.../protection endpoint misses. Repos that
// protect branches via Rulesets sub-report on posture without this module.
//
// Decisions (Bloco J briefing - docs/plan-bloco-j-rulesets.md):
//  1. Union per signal with classic. This module only reports ruleset
//     observations; the integrating caller does the OR with classic.
//  2. Active rules with non-empty bypass_actors still count as satisfied;
//     bypass info surfaces side-channel via bypassInfos -> informational
//     finding (low severity, no score impact).
//  3. Only enforcement === "active" counts. "evaluate" is dry-run and
//     does not prevent anything.
//
// API gotcha: bypass_actors is only returned by the rulesets/{id} endpoint
// when the requesting user has write access to the ruleset. When absent,
// noBypassActors is reported as null (unknown) rather than assumed empty.

type RuleEntry = {
  type: string
  ruleset_id: number
  ruleset_source_type?: "Repository" | "Organization" | "Enterprise"
  ruleset_source?: string
  parameters?: Record<string, unknown>
}

type RulesetDetails = {
  id: number
  name: string
  enforcement: "active" | "evaluate" | "disabled"
  bypassActorsVisible: boolean
  bypassActorsCount: number
  bypassActorTypes: string[]
}

export type RulesetSignals = {
  prRequired: boolean
  statusChecksRequired: boolean
  signedCommitsRequired: boolean
  // true  = every active ruleset we could read had empty bypass_actors
  // false = at least one active ruleset has bypass_actors
  // null  = bypass_actors not visible on any active ruleset (insufficient
  //         access; integrating code should treat as unknown)
  noBypassActors: boolean | null
  bypassFindings: RulesetBypassFinding[]
}

function buildHeaders(token: string | null): HeadersInit {
  const h: Record<string, string> = { Accept: "application/vnd.github+json" }
  if (token) h.Authorization = `Bearer ${token}`
  return h
}

async function fetchRulesForBranch(
  owner: string,
  repo: string,
  branch: string,
  token: string | null,
): Promise<RuleEntry[] | null> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/rules/branches/${branch}`,
    { headers: buildHeaders(token), cache: "no-store" },
  )
  if (res.status === 404) return null
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    throw new Error(`GitHub rules/branches fetch failed: ${res.status}`)
  }
  const json = (await res.json()) as RuleEntry[]
  return Array.isArray(json) ? json : []
}

async function fetchRulesetDetails(
  owner: string,
  repo: string,
  rulesetId: number,
  sourceType: RuleEntry["ruleset_source_type"],
  rulesetSource: string | undefined,
  token: string | null,
): Promise<RulesetDetails | null> {
  let url: string
  if (sourceType === "Organization" && rulesetSource) {
    url = `https://api.github.com/orgs/${rulesetSource}/rulesets/${rulesetId}`
  } else if (sourceType === "Enterprise") {
    // Enterprise rulesets require GHEC + special scopes; out of scope here.
    return null
  } else {
    url = `https://api.github.com/repos/${owner}/${repo}/rulesets/${rulesetId}`
  }
  const res = await fetch(url, { headers: buildHeaders(token), cache: "no-store" })
  if (res.status === 404 || res.status === 403) return null
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    throw new Error(`GitHub rulesets/${rulesetId} fetch failed: ${res.status}`)
  }
  const json = (await res.json()) as {
    id?: number
    name?: string
    enforcement?: string
    bypass_actors?: Array<{ actor_type?: string }>
  }
  const bypassActorsVisible = Array.isArray(json.bypass_actors)
  const actors = bypassActorsVisible ? (json.bypass_actors as Array<{ actor_type?: string }>) : []
  const types = Array.from(
    new Set(
      actors
        .map((a) => a.actor_type)
        .filter((t): t is string => typeof t === "string"),
    ),
  )
  const enforcementRaw = json.enforcement
  const enforcement: RulesetDetails["enforcement"] =
    enforcementRaw === "active" || enforcementRaw === "evaluate" || enforcementRaw === "disabled"
      ? enforcementRaw
      : "disabled"
  return {
    id: typeof json.id === "number" ? json.id : rulesetId,
    name: typeof json.name === "string" ? json.name : `ruleset-${rulesetId}`,
    enforcement,
    bypassActorsVisible,
    bypassActorsCount: actors.length,
    bypassActorTypes: types,
  }
}

export async function assessRulesetSignals(
  owner: string,
  repo: string,
  branch: string,
  token: string | null,
): Promise<RulesetSignals | null> {
  const rules = await fetchRulesForBranch(owner, repo, branch, token)
  if (rules === null || rules.length === 0) return null

  // Cache ruleset details across rules in the same scan (each rule entry
  // references a ruleset_id; multiple rules from the same ruleset are common).
  const detailsCache = new Map<number, RulesetDetails | null>()
  const fetchCached = async (entry: RuleEntry) => {
    if (detailsCache.has(entry.ruleset_id)) {
      return detailsCache.get(entry.ruleset_id) ?? null
    }
    const details = await fetchRulesetDetails(
      owner,
      repo,
      entry.ruleset_id,
      entry.ruleset_source_type,
      entry.ruleset_source,
      token,
    )
    detailsCache.set(entry.ruleset_id, details)
    return details
  }

  let prRequired = false
  let statusChecksRequired = false
  let signedCommitsRequired = false
  let sawAnyActive = false
  let sawVisibleBypass = false
  let anyVisibleBypassNonEmpty = false
  const bypassFindings: RulesetBypassFinding[] = []

  for (const rule of rules) {
    const details = await fetchCached(rule)
    if (!details) continue
    if (details.enforcement !== "active") continue
    sawAnyActive = true

    if (rule.type === "pull_request") {
      prRequired = true
    }
    if (rule.type === "required_status_checks") {
      const params = rule.parameters as
        | { required_status_checks?: unknown[] }
        | undefined
      const checks = params?.required_status_checks
      if (Array.isArray(checks) && checks.length > 0) {
        statusChecksRequired = true
      }
    }
    if (rule.type === "required_signatures") {
      signedCommitsRequired = true
    }

    if (details.bypassActorsVisible) {
      sawVisibleBypass = true
      if (details.bypassActorsCount > 0) {
        anyVisibleBypassNonEmpty = true
        const types = details.bypassActorTypes
        const typesText = types.length > 0 ? types.join(", ") : "unspecified"
        bypassFindings.push({
          ruleId: "ruleset-bypass-actors",
          ruleName: "Branch protection rule allows bypass",
          severity: "low",
          rulesetName: details.name,
          ruleType: rule.type,
          branch,
          actorCount: details.bypassActorsCount,
          actorTypes: types,
          description: `Rule '${rule.type}' in ruleset '${details.name}' (branch '${branch}') can be bypassed by ${details.bypassActorsCount} actor(s): ${typesText}.`,
        })
      }
    }
  }

  if (!sawAnyActive) return null

  const noBypassActors: boolean | null = !sawVisibleBypass
    ? null
    : !anyVisibleBypassNonEmpty

  return {
    prRequired,
    statusChecksRequired,
    signedCommitsRequired,
    noBypassActors,
    bypassFindings,
  }
}
