import type { DependencyFinding, DetectorHealth } from "./types"
import { GitHubRateLimitError, parseGitHubRateLimit } from "./scan"
import { normalizeSeverity } from "./severity"
import { buildGitHubHeaders } from "./github-fetch"

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
  source: "requirements.txt" | "pyproject.toml" | "Pipfile"
}

function stripPep440Specifier(raw: string): string {
  // We only want a single concrete version for OSV. Accept formats like
  //   django>=3.2, <4.0   →  skip (range, unknown concrete)
  //   requests==2.31.0    →  2.31.0
  //   boto3>=1.26         →  skip (too broad)
  //   click~=8.1          →  skip
  const eqMatch = raw.match(/==\s*([0-9][A-Za-z0-9._+!-]*)/)
  if (eqMatch) return eqMatch[1]
  return ""
}

export function parseRequirementsTxt(content: string): ParsedDep[] {
  const deps: ParsedDep[] = []
  const lines = content.split("\n")
  for (let raw of lines) {
    raw = raw.trim()
    if (!raw || raw.startsWith("#") || raw.startsWith("-")) continue
    // Drop inline comments
    const hashIdx = raw.indexOf(" #")
    if (hashIdx > 0) raw = raw.slice(0, hashIdx).trim()
    // Drop env markers, hashes, extras
    raw = raw.split(";")[0].trim()
    raw = raw.split(" --hash=")[0].trim()
    const nameMatch = raw.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/)
    if (!nameMatch) continue
    const name = nameMatch[1].toLowerCase()
    const rest = raw.slice(nameMatch[0].length)
    const version = stripPep440Specifier(rest)
    if (!version) continue
    deps.push({ name, version, source: "requirements.txt" })
  }
  return deps
}

export function parsePyprojectToml(content: string): ParsedDep[] {
  // Minimal best-effort parser targeting PEP-621 and Poetry shapes. A full
  // TOML parser isn't worth shipping until we need more features.
  const deps: ParsedDep[] = []

  // PEP-621 dependencies = ["pkg==1.0.0", "other>=2.0", ...]
  const pep621Block = content.match(/dependencies\s*=\s*\[([\s\S]*?)\]/m)
  if (pep621Block) {
    const entries = pep621Block[1].match(/"([^"]+)"/g) ?? []
    for (const entry of entries) {
      const inner = entry.slice(1, -1).trim()
      const nameMatch = inner.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)/)
      if (!nameMatch) continue
      const version = stripPep440Specifier(inner.slice(nameMatch[0].length))
      if (!version) continue
      deps.push({
        name: nameMatch[1].toLowerCase(),
        version,
        source: "pyproject.toml",
      })
    }
  }

  // Poetry [tool.poetry.dependencies] section with key = "version"
  const poetryBlock = content.match(
    /\[tool\.poetry\.(?:dev-)?dependencies\]([\s\S]*?)(?=\n\[|$)/g,
  )
  if (poetryBlock) {
    for (const block of poetryBlock) {
      const lines = block.split("\n")
      for (const line of lines) {
        const kv = line.match(
          /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*["']([^"']+)["']/,
        )
        if (!kv) continue
        const name = kv[1].toLowerCase()
        if (name === "python") continue
        const versionSpec = kv[2]
        const eq = stripPep440Specifier(`==${versionSpec.replace(/^[\^~>=<!]+/, "")}`)
        if (!eq) continue
        deps.push({ name, version: eq, source: "pyproject.toml" })
      }
    }
  }

  return deps
}

export function parsePipfile(content: string): ParsedDep[] {
  const deps: ParsedDep[] = []
  const blocks = content.match(/\[(?:dev-)?packages\]([\s\S]*?)(?=\n\[|$)/g) ?? []
  for (const block of blocks) {
    const lines = block.split("\n")
    for (const line of lines) {
      const kv = line.match(
        /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*=\s*["']([^"']+)["']/,
      )
      if (!kv) continue
      const name = kv[1].toLowerCase()
      const spec = kv[2].trim()
      const version = stripPep440Specifier(
        spec.startsWith("==") ? spec : `==${spec.replace(/^[\^~>=<!*]+/, "")}`,
      )
      if (!version) continue
      deps.push({ name, version, source: "Pipfile" })
    }
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
  // Vectors look like "CVSS:3.1/AV:N/AC:L/..."; older ones are plain numbers
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

export type PythonDepsScanResult = {
  findings: DependencyFinding[]
  degraded: DetectorHealth | null
  // Deduped+capped deps parsed from requirements/pyproject/Pipfile, exposed so
  // the license scanner can reuse them instead of re-fetching/re-parsing
  // (lib/licenses-registry.ts). Each carries its own `source`.
  parsedDeps: ParsedDep[]
}

export async function scanPythonDependencies(
  owner: string,
  repo: string,
  token: string | null,
): Promise<PythonDepsScanResult> {
  const [req, pyproject, pipfile] = await Promise.all([
    fetchRepoFile(owner, repo, "requirements.txt", token),
    fetchRepoFile(owner, repo, "pyproject.toml", token),
    fetchRepoFile(owner, repo, "Pipfile", token),
  ])

  const parsed: ParsedDep[] = []
  if (req) parsed.push(...parseRequirementsTxt(req))
  if (pyproject) parsed.push(...parsePyprojectToml(pyproject))
  if (pipfile) parsed.push(...parsePipfile(pipfile))

  if (parsed.length === 0) return { findings: [], degraded: null, parsedDeps: [] }

  // De-dupe: (name, version) pair, prefer first encountered (requirements.txt
  // is most specific usually)
  const seen = new Set<string>()
  const unique = parsed
    .filter((d) => {
      const key = `${d.name}@${d.version}`
      if (seen.has(key)) return false
      seen.add(key)
      return true
    })
    .slice(0, MAX_PACKAGES)

  // 1. Query OSV in batch to know which packages have any vulns
  const batchBody = {
    queries: unique.map((d) => ({
      package: { name: d.name, ecosystem: "PyPI" },
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
    console.warn("[python-deps] OSV batch fetch failed:", msg)
    return {
      findings: [],
      degraded: {
        detector: "osv",
        reason: `OSV.dev unreachable (${msg.slice(0, 80)}). Python vulnerability scan skipped.`,
      },
      parsedDeps: unique,
    }
  }
  if (!batchRes.ok) {
    return {
      findings: [],
      degraded: {
        detector: "osv",
        reason: `OSV.dev API returned ${batchRes.status}. Python vulnerability scan skipped.`,
      },
      parsedDeps: unique,
    }
  }
  const batchJson = (await batchRes.json()) as OsvBatchResponse

  // 2. Collect unique vuln IDs to fetch full details (batch only returns IDs)
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

  // Cap details fetch at 100 to keep latency bounded
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
        ecosystem: "PyPI",
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
