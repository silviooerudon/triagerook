import type { AnyFinding, PrioritizedFinding, RiskBreakdown } from "./risk"

export type ScanSnapshot = {
  id: string
  scannedAt: string
  riskScore: number | null
  riskBreakdown: RiskBreakdown | null
  findings: PrioritizedFinding[]
}

export type ScanDiff = {
  from: { id: string; scannedAt: string; riskScore: number | null }
  to: { id: string; scannedAt: string; riskScore: number | null }
  scoreDelta: number | null
  newFindings: PrioritizedFinding[]
  resolvedFindings: PrioritizedFinding[]
  carriedFindings: PrioritizedFinding[]
}

/**
 * Stable identity for a finding across two scans. Two findings with the
 * same fingerprint are considered "the same issue" even if other fields
 * (severity, score, masked preview) shift. Strategy per kind:
 *
 *   • secret tree    – patternId + filePath + lineNumber
 *   • secret history – patternId + commitSha + filePath + lineNumber
 *   • code           – ruleId + filePath + lineNumber
 *   • iac            – ruleId + filePath + lineNumber
 *   • sensitive-file – kind + filePath
 *   • dependency     – package + (ghsa || version)
 *
 * Line numbers are deliberately included even though they're fragile to
 * unrelated edits above the finding. A shifted finding will show up as
 * "resolved" + "new" — the alternative (collapse to filePath only) loses
 * the ability to count two distinct issues on the same line, which is
 * worse for noise control.
 */
export function fingerprintFinding(f: AnyFinding | PrioritizedFinding): string {
  switch (f.kind) {
    case "secret": {
      const isHistory = f.data.source === "history"
      const commit = isHistory ? f.data.commitSha ?? "?" : "tree"
      return `secret|${commit}|${f.data.patternId}|${f.data.filePath}|${f.data.lineNumber}`
    }
    case "code":
      return `code|${f.data.ruleId}|${f.data.filePath}|${f.data.lineNumber}`
    case "iac":
      return `iac|${f.data.ruleId}|${f.data.filePath ?? "?"}|${f.data.lineNumber ?? "?"}`
    case "sensitive-file":
      return `sensitive-file|${f.data.kind}|${f.data.filePath}`
    case "dependency": {
      const ident = f.data.ghsa ?? f.data.version ?? "?"
      return `dependency|${f.data.package}|${ident}`
    }
  }
}

/**
 * Compares two scans of the same repository and returns the delta. The
 * caller is responsible for ensuring both snapshots reference the same
 * owner/repo; this function does not enforce that.
 *
 * Convention: `from` is the earlier scan, `to` is the later. The score
 * delta is `to - from` so positive numbers mean the repo got *worse*
 * (more risk accumulated) — the UI should show that in red.
 */
export function diffScans(from: ScanSnapshot, to: ScanSnapshot): ScanDiff {
  const fromFps = new Set(from.findings.map(fingerprintFinding))
  const toFps = new Set(to.findings.map(fingerprintFinding))

  const newFindings = to.findings.filter(
    (f) => !fromFps.has(fingerprintFinding(f)),
  )
  const resolvedFindings = from.findings.filter(
    (f) => !toFps.has(fingerprintFinding(f)),
  )
  const carriedFindings = to.findings.filter((f) =>
    fromFps.has(fingerprintFinding(f)),
  )

  const scoreDelta =
    from.riskScore !== null && to.riskScore !== null
      ? to.riskScore - from.riskScore
      : null

  return {
    from: { id: from.id, scannedAt: from.scannedAt, riskScore: from.riskScore },
    to: { id: to.id, scannedAt: to.scannedAt, riskScore: to.riskScore },
    scoreDelta,
    newFindings,
    resolvedFindings,
    carriedFindings,
  }
}
