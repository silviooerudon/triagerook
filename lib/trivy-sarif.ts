import type { DependencyFinding, DetectorHealth } from "./types"
import { normalizeSeverity } from "./severity"
import { GitHubRateLimitError, parseGitHubRateLimit } from "./scan"
import { buildGitHubHeaders } from "./github-fetch"

// Trivy SARIF ingestion (option D of the Docker-layer-CVE plan).
//
// A static fetch can't enumerate an image's OS-package CVEs — that needs the
// built image (Trivy/Grype pull the layers). Instead of standing up a scanning
// worker, we ingest the result the user already produces: they run Trivy in
// CI (`trivy image --format sarif --output trivy-results.sarif`) and commit the
// SARIF, and we fold its findings into the scan as "Container" dependencies.
// Zero scanning infra on our side; the user's CI does the (free, OSS) work.
//
// We deliberately surface these in their own ecosystem ("Container") rather
// than de-duping against our lockfile SCA: Trivy scans both OS and language
// packages, and a separate section keeps the provenance honest instead of
// guessing which finding is "the same".

type SarifRule = {
  id?: string
  name?: string
  shortDescription?: { text?: string }
  fullDescription?: { text?: string }
  helpUri?: string
  properties?: { "security-severity"?: string; tags?: string[] }
}

type SarifResult = {
  ruleId?: string
  level?: string
  message?: { text?: string }
}

type Sarif = {
  runs?: Array<{
    tool?: { driver?: { name?: string; rules?: SarifRule[] } }
    results?: SarifResult[]
  }>
}

const MAX_FINDINGS = 500

// Vulnerability identifiers Trivy emits as rule ids. Used to keep us off
// Trivy's *misconfiguration* SARIF output (which we don't want here — IaC is
// covered by our own detectors).
const VULN_ID = /^(?:CVE-|GHSA-|DLA-|DSA-|RUSTSEC-|GO-|PYSEC-|TEMP-|ELSA-|ALAS-|RHSA-)/i

function isVulnResult(ruleId: string | undefined, rule: SarifRule | undefined): boolean {
  if (ruleId && VULN_ID.test(ruleId)) return true
  const tags = rule?.properties?.tags
  return Array.isArray(tags) && tags.includes("vulnerability")
}

function field(text: string, label: string): string | null {
  const m = text.match(new RegExp(`${label}:\\s*(.+)`, "i"))
  return m ? m[1].trim() : null
}

function severityFrom(
  text: string,
  rule: SarifRule | undefined,
  level: string | undefined,
): { severity: DependencyFinding["severity"]; cvss: number | null } {
  // 1. Trivy writes "Severity: HIGH" into the message text.
  const sevText = field(text, "Severity")
  // 2. The rule carries a numeric CVSS in security-severity.
  const cvssRaw = rule?.properties?.["security-severity"]
  const cvss = cvssRaw ? Number.parseFloat(cvssRaw) : null

  if (sevText) return { severity: normalizeSeverity(sevText), cvss: Number.isFinite(cvss) ? cvss : null }
  if (cvss !== null && Number.isFinite(cvss)) {
    const severity =
      cvss >= 9 ? "critical" : cvss >= 7 ? "high" : cvss >= 4 ? "medium" : "low"
    return { severity, cvss }
  }
  // 3. Fall back to the SARIF level.
  const byLevel: Record<string, DependencyFinding["severity"]> = {
    error: "high",
    warning: "medium",
    note: "low",
  }
  return { severity: byLevel[level ?? ""] ?? "medium", cvss: null }
}

// Parse a Trivy SARIF document into Container DependencyFindings. Pure; returns
// [] for anything that isn't a parseable Trivy vulnerability report.
export function parseTrivySarif(content: string): DependencyFinding[] {
  let doc: Sarif
  try {
    doc = JSON.parse(content) as Sarif
  } catch {
    return []
  }
  if (!doc || !Array.isArray(doc.runs)) return []

  const findings: DependencyFinding[] = []
  for (const run of doc.runs) {
    const rulesById = new Map<string, SarifRule>()
    for (const r of run.tool?.driver?.rules ?? []) {
      if (r.id) rulesById.set(r.id, r)
    }
    for (const res of run.results ?? []) {
      if (findings.length >= MAX_FINDINGS) break
      const ruleId = res.ruleId
      const rule = ruleId ? rulesById.get(ruleId) : undefined
      if (!isVulnResult(ruleId, rule)) continue

      const text = res.message?.text ?? ""
      const pkg = field(text, "Package") ?? rule?.name ?? "unknown"
      const installed = field(text, "Installed Version") ?? ""
      const fixed = field(text, "Fixed Version")
      const { severity, cvss } = severityFrom(text, rule, res.level)
      const cve = ruleId ?? "unknown"

      findings.push({
        package: pkg,
        version: installed,
        ecosystem: "Container",
        severity,
        title: rule?.shortDescription?.text ?? `${cve} in ${pkg}`,
        ghsa: cve.startsWith("GHSA-") ? cve : null,
        vulnerable_versions: fixed ? `< ${fixed}` : "unknown",
        cvss_score: cvss,
        url: rule?.helpUri ?? `https://avd.aquasec.com/nvd/${cve.toLowerCase()}`,
        source: "trivy-sarif",
      })
    }
  }
  return findings
}

// Conventional locations a committed Trivy SARIF report may live at, in order.
const SARIF_PATHS = [
  "trivy-results.sarif",
  "trivy.sarif",
  ".triagerook/trivy.sarif",
  ".github/trivy-results.sarif",
]

export type FetchLike = (
  url: string,
  init: { headers: Record<string, string>; cache: "no-store" },
) => Promise<{ ok: boolean; status: number; text: () => Promise<string>; headers: { get: (k: string) => string | null } }>

export type ContainerScanResult = {
  findings: DependencyFinding[]
  degraded: DetectorHealth | null
}

// Fetch the first committed Trivy SARIF found and parse it. Absent file → empty
// (the common case; nothing to report). Present-but-unparseable → degraded, so
// a broken upload is surfaced rather than silently read as "image is clean".
export async function scanContainerVulns(
  owner: string,
  repo: string,
  token: string | null,
  fetchImpl: FetchLike = fetch as unknown as FetchLike,
): Promise<ContainerScanResult> {
  for (const path of SARIF_PATHS) {
    let res: Awaited<ReturnType<FetchLike>>
    try {
      res = await fetchImpl(
        `https://api.github.com/repos/${owner}/${repo}/contents/${path}`,
        { headers: buildGitHubHeaders(token, "application/vnd.github.v3.raw"), cache: "no-store" },
      )
    } catch {
      continue
    }
    if (res.status === 404) continue
    if (!res.ok) {
      const retry = parseGitHubRateLimit(res as unknown as Response)
      if (retry !== null) throw new GitHubRateLimitError(retry)
      continue
    }
    const content = await res.text()
    const findings = parseTrivySarif(content)
    if (findings.length === 0 && content.trim().length > 0) {
      // The file exists and is non-empty but yielded nothing — either a clean
      // image (fine) or a malformed/non-Trivy SARIF. Distinguish: valid JSON
      // with runs but no vuln results = clean; otherwise degraded.
      try {
        const doc = JSON.parse(content) as Sarif
        if (!Array.isArray(doc.runs)) {
          return {
            findings: [],
            degraded: {
              detector: "container-scan",
              reason: `Found ${path} but it isn't a valid SARIF document. Container CVE results skipped.`,
            },
          }
        }
      } catch {
        return {
          findings: [],
          degraded: {
            detector: "container-scan",
            reason: `Found ${path} but it isn't valid JSON. Container CVE results skipped.`,
          },
        }
      }
    }
    return { findings, degraded: null }
  }
  return { findings: [], degraded: null }
}
