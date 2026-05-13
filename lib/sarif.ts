import type { AnyFinding } from "./risk"

// SARIF 2.1.0 export. Reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
//
// Produced by /api/scans/[id]/sarif so users can:
//   - Download a static SARIF file and feed it to any SARIF-aware tool
//   - Upload it to GitHub Code Scanning so RepoGuard findings appear in
//     the repo's Security tab next to CodeQL/Dependabot
//
// Mapping decisions:
//   - tool.driver.name = "RepoGuard", informationUri points to the app.
//   - One result per finding. ruleId follows the same `<kind>/<id>`
//     namespace used by lib/suppressions.ts so suppressions and SARIF
//     output share vocabulary.
//   - Severity → level: critical/high → "error", medium/moderate →
//     "warning", low → "note". Findings flagged likelyTestFixture get
//     forced to "note" regardless of severity — the fixture multiplier
//     in risk.ts already discounts them; SARIF should too.
//   - Dependency findings have no line number; the physicalLocation
//     points at the manifest path and the region is omitted. When a
//     GHSA id is present, the ruleId is `dependency/<GHSA>` so the
//     same advisory across multiple versions deduplicates cleanly.
//   - Sensitive-file findings are file-level too (no region).
//   - run.properties carries owner/repo/scannedAt/riskScore as an
//     informational sidecar (most SARIF consumers ignore properties).

export const SARIF_VERSION = "2.1.0"
export const SARIF_SCHEMA =
  "https://json.schemastore.org/sarif-2.1.0.json"
export const REPOGUARD_TOOL_VERSION = "1.0.0"
export const REPOGUARD_INFO_URI = "https://repoguard-chi.vercel.app"

export type ScanForSarif = {
  owner: string
  repo: string
  scannedAt: string
  riskScore: number | null
  findings: AnyFinding[]
}

export type SarifLevel = "error" | "warning" | "note" | "none"

export type SarifLog = {
  $schema: string
  version: "2.1.0"
  runs: SarifRun[]
}

export type SarifRun = {
  tool: {
    driver: {
      name: string
      version: string
      informationUri: string
      rules: SarifRule[]
    }
  }
  results: SarifResult[]
  properties?: {
    owner: string
    repo: string
    scannedAt: string
    riskScore?: number
  }
}

export type SarifRule = {
  id: string
  name: string
  shortDescription: { text: string }
  fullDescription?: { text: string }
  defaultConfiguration?: { level: SarifLevel }
}

export type SarifResult = {
  ruleId: string
  level: SarifLevel
  message: { text: string }
  locations: SarifLocation[]
}

export type SarifLocation = {
  physicalLocation: {
    artifactLocation: { uri: string }
    region?: { startLine: number }
  }
}

type FindingShape = {
  ruleId: string
  ruleName: string
  ruleDescription: string
  level: SarifLevel
  message: string
  filePath: string
  lineNumber: number | null
}

function severityToLevel(
  severity: string | undefined | null,
  fixture: boolean,
): SarifLevel {
  if (fixture) return "note"
  switch (severity) {
    case "critical":
    case "high":
      return "error"
    case "medium":
    case "moderate":
      return "warning"
    case "low":
      return "note"
    default:
      return "none"
  }
}

function describeFinding(finding: AnyFinding): FindingShape | null {
  if (finding.kind === "secret") {
    const d = finding.data
    return {
      ruleId: `secret/${d.patternId}`,
      ruleName: d.patternName,
      ruleDescription: d.description,
      level: severityToLevel(d.severity, d.likelyTestFixture ?? false),
      message: `${d.patternName} matched in ${d.filePath}:${d.lineNumber}`,
      filePath: d.filePath,
      lineNumber: d.lineNumber,
    }
  }
  if (finding.kind === "code") {
    const d = finding.data
    return {
      ruleId: `code/${d.ruleId}`,
      ruleName: d.ruleName,
      ruleDescription: d.description,
      level: severityToLevel(d.severity, d.likelyTestFixture ?? false),
      message: `${d.ruleName} (${d.cwe ?? "no CWE"}) at ${d.filePath}:${d.lineNumber}`,
      filePath: d.filePath,
      lineNumber: d.lineNumber,
    }
  }
  if (finding.kind === "iac") {
    const d = finding.data
    return {
      ruleId: `iac/${d.ruleId}`,
      ruleName: d.ruleName,
      ruleDescription: d.description,
      level: severityToLevel(d.severity, false),
      message: `${d.ruleName} in ${d.filePath}${d.lineNumber ? `:${d.lineNumber}` : ""}`,
      filePath: d.filePath,
      lineNumber: d.lineNumber,
    }
  }
  if (finding.kind === "sensitive-file") {
    const d = finding.data
    return {
      ruleId: `sensitive-file/${d.kind}`,
      ruleName: d.name,
      ruleDescription: d.description,
      level: severityToLevel(d.severity, false),
      message: `Sensitive file present: ${d.filePath}`,
      filePath: d.filePath,
      lineNumber: null,
    }
  }
  if (finding.kind === "dependency") {
    const d = finding.data
    const ruleSuffix = d.ghsa ?? d.package
    return {
      ruleId: `dependency/${ruleSuffix}`,
      ruleName: d.title || `${d.package}@${d.version}`,
      ruleDescription: d.title,
      level: severityToLevel(d.severity, false),
      message: `${d.package}@${d.version} (${d.ghsa ?? "no GHSA"}) — ${d.title}`,
      filePath: d.source ?? "package.json",
      lineNumber: null,
    }
  }
  return null
}

function toSarifResult(shape: FindingShape): SarifResult {
  const physicalLocation: SarifLocation["physicalLocation"] = {
    artifactLocation: { uri: shape.filePath },
  }
  if (shape.lineNumber !== null && shape.lineNumber > 0) {
    physicalLocation.region = { startLine: shape.lineNumber }
  }
  return {
    ruleId: shape.ruleId,
    level: shape.level,
    message: { text: shape.message },
    locations: [{ physicalLocation }],
  }
}

function toSarifRule(shape: FindingShape): SarifRule {
  return {
    id: shape.ruleId,
    name: shape.ruleName,
    shortDescription: { text: shape.ruleName },
    fullDescription: shape.ruleDescription
      ? { text: shape.ruleDescription }
      : undefined,
    defaultConfiguration: { level: shape.level },
  }
}

export function scanToSarif(scan: ScanForSarif): SarifLog {
  const shapes: FindingShape[] = []
  for (const f of scan.findings) {
    const s = describeFinding(f)
    if (s) shapes.push(s)
  }

  const results = shapes.map(toSarifResult)

  const rulesByid = new Map<string, SarifRule>()
  for (const s of shapes) {
    if (!rulesByid.has(s.ruleId)) rulesByid.set(s.ruleId, toSarifRule(s))
  }
  const rules = Array.from(rulesByid.values())

  const properties: SarifRun["properties"] = {
    owner: scan.owner,
    repo: scan.repo,
    scannedAt: scan.scannedAt,
  }
  if (scan.riskScore !== null) properties.riskScore = scan.riskScore

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: "RepoGuard",
            version: REPOGUARD_TOOL_VERSION,
            informationUri: REPOGUARD_INFO_URI,
            rules,
          },
        },
        results,
        properties,
      },
    ],
  }
}
