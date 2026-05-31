import type { DependencyFinding, DetectorHealth, DependencyEcosystem } from "./types"
import { normalizeSeverity } from "./severity"

// Shared OSV.dev query core.
//
// python-deps / go-deps / ruby-deps each carry their own copy of this
// machinery (batch query → collect IDs → fetch details → map to
// DependencyFinding). Newer ecosystems (Maven/Gradle, Composer) reuse this
// module instead of cloning it a fourth and fifth time. The three original
// scanners are left as-is to avoid regressing working code — migrating them
// onto this helper is a safe follow-up.
//
// Bias matches the existing scanners: report vulnerabilities found, mark the
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
const MAX_DETAILS = 100

export type OsvParsedDep = {
  name: string
  version: string
  source: NonNullable<DependencyFinding["source"]>
}

export type OsvScanOutcome = {
  findings: DependencyFinding[]
  degraded: DetectorHealth | null
  // The full deduped dep list (NOT capped — the OSV cap is applied to the
  // query subset separately). Exposed so a license scanner can reuse it.
  deduped: OsvParsedDep[]
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

function defaultAdvisoryUrl(vuln: OsvVulnerability): string {
  const ghsa = findGhsa(vuln)
  if (ghsa) return `https://github.com/advisories/${ghsa}`
  const ref = vuln.references?.find((r) => r.type === "ADVISORY")?.url
  if (ref) return ref
  return `https://osv.dev/vulnerability/${vuln.id}`
}

async function fetchOsvDetails(
  id: string,
  fetchImpl: typeof fetch,
): Promise<OsvVulnerability | null> {
  try {
    const res = await fetchImpl(`${OSV_VULN_URL}/${id}`, { cache: "no-store" })
    if (!res.ok) return null
    return res.json()
  } catch {
    return null
  }
}

function dedupe(parsed: OsvParsedDep[]): OsvParsedDep[] {
  const seen = new Set<string>()
  return parsed.filter((d) => {
    const key = `${d.name}@${d.version}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

export type OsvScanConfig = {
  // OSV's ecosystem string for the batch query ("Maven", "Packagist", …).
  osvEcosystem: string
  // The TriageRook DependencyEcosystem stamped on each finding.
  displayEcosystem: DependencyEcosystem
  // Short label used in log lines + the degraded reason ("Java", "PHP").
  scanLabel: string
  // Optional per-ecosystem advisory URL builder (falls back to GHSA/OSV).
  advisoryUrl?: (vuln: OsvVulnerability) => string
  // Injectable fetch for tests.
  fetchImpl?: typeof fetch
}

// Run a full OSV scan over an already-parsed dependency list. Handles
// dedupe, the 500-package cap, the batch query, the bounded details fetch,
// and DependencyFinding construction. Returns `deduped` so callers that need
// the full list (e.g. license enrichment) don't re-parse.
export async function runOsvScan(
  parsed: OsvParsedDep[],
  config: OsvScanConfig,
): Promise<OsvScanOutcome> {
  const fetchImpl = config.fetchImpl ?? fetch
  const urlFor = config.advisoryUrl ?? defaultAdvisoryUrl

  if (parsed.length === 0) return { findings: [], degraded: null, deduped: [] }

  const deduped = dedupe(parsed)
  const unique = deduped.slice(0, MAX_PACKAGES)

  const batchBody = {
    queries: unique.map((d) => ({
      package: { name: d.name, ecosystem: config.osvEcosystem },
      version: d.version,
    })),
  }

  let batchRes: Response
  try {
    batchRes = await fetchImpl(OSV_BATCH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(batchBody),
      cache: "no-store",
    })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    console.warn(`[osv:${config.scanLabel}] OSV batch fetch failed:`, msg)
    return {
      findings: [],
      degraded: {
        detector: "osv",
        reason: `OSV.dev unreachable (${msg.slice(0, 80)}). ${config.scanLabel} vulnerability scan skipped.`,
      },
      deduped,
    }
  }
  if (!batchRes.ok) {
    return {
      findings: [],
      degraded: {
        detector: "osv",
        reason: `OSV.dev API returned ${batchRes.status}. ${config.scanLabel} vulnerability scan skipped.`,
      },
      deduped,
    }
  }
  const batchJson = (await batchRes.json()) as OsvBatchResponse

  const idToPackages = new Map<string, OsvParsedDep[]>()
  batchJson.results.forEach((result, idx) => {
    if (!result.vulns) return
    const pkg = unique[idx]
    for (const vuln of result.vulns) {
      if (!idToPackages.has(vuln.id)) idToPackages.set(vuln.id, [])
      idToPackages.get(vuln.id)!.push(pkg)
    }
  })

  if (idToPackages.size === 0) return { findings: [], degraded: null, deduped }

  const ids = Array.from(idToPackages.keys()).slice(0, MAX_DETAILS)
  const details = await Promise.all(ids.map((id) => fetchOsvDetails(id, fetchImpl)))

  const findings: DependencyFinding[] = []
  details.forEach((vuln, i) => {
    if (!vuln) return
    const pkgs = idToPackages.get(ids[i])!
    const { severity, cvss } = mapOsvSeverity(vuln)
    for (const pkg of pkgs) {
      findings.push({
        package: pkg.name,
        version: pkg.version,
        ecosystem: config.displayEcosystem,
        severity,
        title: vuln.summary ?? vuln.id,
        ghsa: findGhsa(vuln),
        vulnerable_versions: buildVulnerableRange(vuln, pkg.name),
        cvss_score: cvss,
        url: urlFor(vuln),
        source: pkg.source,
      })
    }
  })

  return { findings, degraded: null, deduped }
}
