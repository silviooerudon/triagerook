import type { DependencyFinding, DetectorHealth } from "./types"
import { GitHubRateLimitError, parseGitHubRateLimit } from "./scan"
import { normalizeSeverity } from "./severity"
import { buildGitHubHeaders } from "./github-fetch"

// Go module scanner.
//
// Parses go.mod (direct + indirect requires) and queries OSV's batch
// endpoint with ecosystem "Go". OSV indexes the same advisories Google
// uses for govulncheck, so coverage matches what a Go user expects.
//
// Why go.mod and not go.sum:
//   - go.mod is the declared module set (what the developer chose).
//   - go.sum is hash-only, doesn't carry version info OSV needs.
//   - The full transitive closure that govulncheck sees comes from
//     `go list -m all` at runtime, which we can't replicate from a
//     static fetch. Listing direct + `// indirect` lines from go.mod
//     gives us the best static approximation.
//
// Bias same as python-deps: report vulnerabilities found, mark the
// detector degraded (don't fail the whole scan) when OSV is unreachable.

type OsvVulnerability = {
  id: string
  summary?: string
  details?: string
  aliases?: string[]
  severity?: Array<{ type: string; score: string }>
  database_specific?: { severity?: string; cwe_ids?: string[] }
  affected?: Array<{
    package: { name: string; ecosystem: string }
    ranges?: Array<{
      type: string
      events: Array<{ introduced?: string; fixed?: string; last_affected?: string }>
    }>
    versions?: string[]
  }>
  references?: Array<{ type: string; url: string }>
}

type OsvBatchResponse = {
  results: Array<{ vulns?: Array<{ id: string }> }>
}

const OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
const OSV_VULN_URL = "https://api.osv.dev/v1/vulns"
const MAX_PACKAGES = 500

type ParsedDep = {
  name: string
  version: string
  source: "go.mod"
}

// Strip the Go-mod `v` prefix (`v1.2.3` → `1.2.3`) and the
// `+incompatible` suffix that appears on modules that haven't moved
// to semver-major versioning. OSV indexes the bare semver form on
// the Go ecosystem.
function normalizeGoVersion(raw: string): string {
  return raw.replace(/^v/, "").replace(/\+incompatible$/, "").trim()
}

// Parse a go.mod file. Handles both block form (`require ( ... )`) and
// single-line form (`require example.com/pkg v1.2.3`). Strips trailing
// comments and `// indirect` markers — both direct and indirect deps
// get scanned because a vuln in an indirect dep is still a vuln in
// your build.
export function parseGoMod(content: string): ParsedDep[] {
  const deps: ParsedDep[] = []
  const lines = content.split("\n")

  let inRequireBlock = false
  for (const raw of lines) {
    const line = raw.trim()
    if (!line || line.startsWith("//")) continue

    if (line.startsWith("require (")) {
      inRequireBlock = true
      continue
    }
    if (inRequireBlock && line === ")") {
      inRequireBlock = false
      continue
    }

    let body: string | null = null
    if (inRequireBlock) {
      body = line
    } else if (line.startsWith("require ")) {
      body = line.slice("require ".length).trim()
    }
    if (!body) continue

    // Drop inline comments — keep the `// indirect` distinction for
    // future use but we scan both direct and indirect.
    const commentIdx = body.indexOf("//")
    if (commentIdx >= 0) body = body.slice(0, commentIdx).trim()

    const parts = body.split(/\s+/)
    if (parts.length < 2) continue
    const [name, version] = parts
    if (!name || !version || !version.startsWith("v")) continue

    deps.push({
      name,
      version: normalizeGoVersion(version),
      source: "go.mod",
    })
  }

  return deps
}

async function fetchRepoFile(
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
    return null
  }
  return res.text()
}

function mapOsvSeverity(
  vuln: OsvVulnerability,
): { severity: DependencyFinding["severity"]; cvss: number | null } {
  const cvssStr = vuln.severity?.find((s) => s.type.startsWith("CVSS"))?.score
  const cvss = cvssStr ? extractCvssScore(cvssStr) : null
  const dbSev = vuln.database_specific?.severity
  let severity: DependencyFinding["severity"] = normalizeSeverity(dbSev)
  if (!dbSev && cvss !== null) {
    if (cvss >= 9) severity = "critical"
    else if (cvss >= 7) severity = "high"
    else if (cvss >= 4) severity = "medium"
    else severity = "low"
  }
  return { severity, cvss }
}

function extractCvssScore(cvssVector: string): number | null {
  const num = Number.parseFloat(cvssVector)
  if (Number.isFinite(num)) return num
  return null
}

function buildVulnerableRange(vuln: OsvVulnerability, pkgName: string): string {
  const affected = vuln.affected?.find(
    (a) => a.package.name.toLowerCase() === pkgName.toLowerCase(),
  )
  if (!affected?.ranges?.length) return "unknown"
  const parts: string[] = []
  for (const range of affected.ranges) {
    let introduced = ""
    let fixed = ""
    for (const event of range.events) {
      if (event.introduced) introduced = event.introduced
      if (event.fixed) fixed = event.fixed
    }
    if (introduced === "0" && fixed) parts.push(`< ${fixed}`)
    else if (introduced && fixed) parts.push(`>= ${introduced}, < ${fixed}`)
    else if (introduced) parts.push(`>= ${introduced}`)
    else if (fixed) parts.push(`< ${fixed}`)
  }
  return parts.length > 0 ? parts.join(" or ") : "unknown"
}

function findGhsa(vuln: OsvVulnerability): string | null {
  if (vuln.id.startsWith("GHSA-")) return vuln.id
  return vuln.aliases?.find((a) => a.startsWith("GHSA-")) ?? null
}

function findAdvisoryUrl(vuln: OsvVulnerability): string {
  const ghsa = findGhsa(vuln)
  if (ghsa) return `https://github.com/advisories/${ghsa}`
  // Go advisories often have a GO-YYYY-NNNN ID and a friendly page on
  // pkg.go.dev; OSV's own page is the universal fallback.
  if (vuln.id.startsWith("GO-")) {
    return `https://pkg.go.dev/vuln/${vuln.id}`
  }
  const ref = vuln.references?.find((r) => r.type === "ADVISORY")?.url
  if (ref) return ref
  return `https://osv.dev/vulnerability/${vuln.id}`
}

async function fetchOsvDetails(id: string): Promise<OsvVulnerability | null> {
  try {
    const res = await fetch(`${OSV_VULN_URL}/${id}`, { cache: "no-store" })
    if (!res.ok) return null
    return res.json()
  } catch {
    return null
  }
}

export type GoDepsScanResult = {
  findings: DependencyFinding[]
  degraded: DetectorHealth | null
  // Deduped+capped deps parsed from go.mod, exposed so the license scanner can
  // reuse them instead of re-fetching/re-parsing go.mod (lib/licenses-registry.ts).
  parsedDeps: ParsedDep[]
}

export async function scanGoDependencies(
  owner: string,
  repo: string,
  token: string | null,
): Promise<GoDepsScanResult> {
  const content = await fetchRepoFile(owner, repo, "go.mod", token)
  if (!content) return { findings: [], degraded: null, parsedDeps: [] }

  const parsed = parseGoMod(content)
  if (parsed.length === 0) return { findings: [], degraded: null, parsedDeps: [] }

  // De-dupe + cap before hitting OSV. OSV's batch endpoint accepts up
  // to ~1000 queries per call but our budget is tighter — keep the
  // top MAX_PACKAGES so a monorepo with a giant go.mod doesn't eat
  // the whole function timeout.
  const seen = new Set<string>()
  const unique = parsed
    .filter((d) => {
      const key = `${d.name}@${d.version}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
    .slice(0, MAX_PACKAGES)

  const batchBody = {
    queries: unique.map((d) => ({
      package: { name: d.name, ecosystem: "Go" },
      version: d.version,
    })),
  }

  let batchRes: Response
  try {
    batchRes = await fetch(OSV_BATCH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(batchBody),
      cache: "no-store",
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.warn("[go-deps] OSV batch fetch failed:", msg)
    return {
      findings: [],
      degraded: {
        detector: "osv",
        reason: `OSV.dev unreachable (${msg.slice(0, 80)}). Go vulnerability scan skipped.`,
      },
      parsedDeps: unique,
    }
  }
  if (!batchRes.ok) {
    return {
      findings: [],
      degraded: {
        detector: "osv",
        reason: `OSV.dev API returned ${batchRes.status}. Go vulnerability scan skipped.`,
      },
      parsedDeps: unique,
    }
  }
  const batchJson = (await batchRes.json()) as OsvBatchResponse

  const idToPackages = new Map<string, ParsedDep[]>()
  batchJson.results.forEach((result, idx) => {
    if (!result.vulns) return
    const pkg = unique[idx]
    for (const vuln of result.vulns) {
      if (!idToPackages.has(vuln.id)) idToPackages.set(vuln.id, [])
      idToPackages.get(vuln.id)!.push(pkg)
    }
  })

  if (idToPackages.size === 0) return { findings: [], degraded: null, parsedDeps: unique }

  const ids = Array.from(idToPackages.keys()).slice(0, 100)
  const details = await Promise.all(ids.map((id) => fetchOsvDetails(id)))

  const findings: DependencyFinding[] = []
  details.forEach((vuln, i) => {
    if (!vuln) return
    const pkgs = idToPackages.get(ids[i])!
    const { severity, cvss } = mapOsvSeverity(vuln)
    for (const pkg of pkgs) {
      findings.push({
        package: pkg.name,
        version: pkg.version,
        ecosystem: "Go",
        severity,
        title: vuln.summary ?? vuln.id,
        ghsa: findGhsa(vuln),
        vulnerable_versions: buildVulnerableRange(vuln, pkg.name),
        cvss_score: cvss,
        url: findAdvisoryUrl(vuln),
        source: pkg.source,
      })
    }
  })

  return { findings, degraded: null, parsedDeps: unique }
}
