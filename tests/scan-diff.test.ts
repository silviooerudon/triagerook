import { describe, it, expect } from "vitest"
import { fingerprintFinding, diffScans, type ScanSnapshot } from "@/lib/scan-diff"
import type { AnyFinding, PrioritizedFinding } from "@/lib/risk"

function secret(
  patternId: string,
  filePath: string,
  lineNumber: number,
  extra: { source?: "tree" | "history"; commitSha?: string; score?: number } = {},
): PrioritizedFinding {
  const finding: AnyFinding = {
    kind: "secret",
    data: {
      patternId,
      patternName: patternId,
      severity: "critical",
      description: "x",
      filePath,
      lineNumber,
      lineContent: "•••",
      likelyTestFixture: false,
      ...(extra.source ? { source: extra.source } : {}),
      ...(extra.commitSha ? { commitSha: extra.commitSha } : {}),
    },
  }
  return { ...finding, score: extra.score ?? 40 }
}

function dep(pkg: string, ghsa: string | null, version = "1.0.0"): PrioritizedFinding {
  const finding: AnyFinding = {
    kind: "dependency",
    data: {
      package: pkg,
      version,
      severity: "high",
      title: "bad",
      ghsa,
      vulnerable_versions: "<2",
      cvss_score: 7,
      url: "https://example.com",
    },
  }
  return { ...finding, score: 15 }
}

function snapshot(
  id: string,
  riskScore: number | null,
  findings: PrioritizedFinding[],
): ScanSnapshot {
  return {
    id,
    scannedAt: "2026-05-11T00:00:00Z",
    riskScore,
    riskBreakdown: null,
    findings,
  }
}

describe("fingerprintFinding", () => {
  it("treats tree and history secrets at the same line as distinct issues", () => {
    const tree = secret("github-pat", "src/a.ts", 10)
    const history = secret("github-pat", "src/a.ts", 10, {
      source: "history",
      commitSha: "abc123",
    })
    expect(fingerprintFinding(tree)).not.toBe(fingerprintFinding(history))
  })

  it("returns the same fingerprint for two identical secret findings", () => {
    const a = secret("github-pat", "src/a.ts", 10)
    const b = secret("github-pat", "src/a.ts", 10)
    expect(fingerprintFinding(a)).toBe(fingerprintFinding(b))
  })

  it("uses ghsa for dependencies when available, falls back to version", () => {
    const withGhsa = dep("lodash", "GHSA-foo")
    const sameWithGhsa = dep("lodash", "GHSA-foo", "9.9.9")
    expect(fingerprintFinding(withGhsa)).toBe(fingerprintFinding(sameWithGhsa))

    const noGhsa = dep("lodash", null, "4.17.20")
    const noGhsaSame = dep("lodash", null, "4.17.20")
    expect(fingerprintFinding(noGhsa)).toBe(fingerprintFinding(noGhsaSame))
    expect(fingerprintFinding(withGhsa)).not.toBe(fingerprintFinding(noGhsa))
  })
})

describe("diffScans", () => {
  it("classifies findings into new / resolved / carried", () => {
    const a = secret("github-pat", "src/a.ts", 10)
    const b = secret("aws-access-key", "src/b.ts", 20)
    const c = secret("openai-api-key", "src/c.ts", 30)

    const from = snapshot("s1", 80, [a, b])
    const to = snapshot("s2", 55, [a, c])

    const diff = diffScans(from, to)

    expect(diff.newFindings.map(fingerprintFinding)).toEqual([fingerprintFinding(c)])
    expect(diff.resolvedFindings.map(fingerprintFinding)).toEqual([
      fingerprintFinding(b),
    ])
    expect(diff.carriedFindings.map(fingerprintFinding)).toEqual([
      fingerprintFinding(a),
    ])
  })

  it("computes scoreDelta as to.score - from.score", () => {
    const from = snapshot("s1", 80, [])
    const to = snapshot("s2", 55, [])
    expect(diffScans(from, to).scoreDelta).toBe(-25)
  })

  it("returns null scoreDelta when either side is missing a score", () => {
    expect(diffScans(snapshot("s1", null, []), snapshot("s2", 50, [])).scoreDelta).toBeNull()
    expect(diffScans(snapshot("s1", 50, []), snapshot("s2", null, [])).scoreDelta).toBeNull()
  })

  it("returns empty arrays when both scans are empty", () => {
    const diff = diffScans(snapshot("s1", 0, []), snapshot("s2", 0, []))
    expect(diff.newFindings).toEqual([])
    expect(diff.resolvedFindings).toEqual([])
    expect(diff.carriedFindings).toEqual([])
  })

  it("treats a finding that moved file path as resolved + new", () => {
    const from = snapshot("s1", 40, [secret("github-pat", "src/a.ts", 10)])
    const to = snapshot("s2", 40, [secret("github-pat", "src/b.ts", 10)])
    const diff = diffScans(from, to)
    expect(diff.newFindings).toHaveLength(1)
    expect(diff.resolvedFindings).toHaveLength(1)
    expect(diff.carriedFindings).toHaveLength(0)
  })

  it("preserves both from and to metadata in the diff payload", () => {
    const from: ScanSnapshot = {
      id: "s1",
      scannedAt: "2026-05-01T00:00:00Z",
      riskScore: 50,
      riskBreakdown: null,
      findings: [],
    }
    const to: ScanSnapshot = {
      id: "s2",
      scannedAt: "2026-05-11T00:00:00Z",
      riskScore: 40,
      riskBreakdown: null,
      findings: [],
    }
    const diff = diffScans(from, to)
    expect(diff.from.id).toBe("s1")
    expect(diff.to.id).toBe("s2")
    expect(diff.from.scannedAt).toBe("2026-05-01T00:00:00Z")
    expect(diff.to.scannedAt).toBe("2026-05-11T00:00:00Z")
  })
})
