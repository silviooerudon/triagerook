import { describe, it, expect } from "vitest"
import {
  scoreFinding,
  prioritize,
  scoreRepo,
  SEVERITY_BASE_POINTS,
  TEST_FIXTURE_MULTIPLIER,
  HISTORY_SECRET_MULTIPLIER,
  TRANSITIVE_DEP_MULTIPLIER,
  REPO_SCORE_CAP,
  type AnyFinding,
} from "@/lib/risk"

function secret(
  severity: "critical" | "high" | "medium" | "low",
  extra: Partial<AnyFinding extends { kind: "secret"; data: infer D } ? D : never> = {},
): AnyFinding {
  return {
    kind: "secret",
    data: {
      patternId: "test",
      patternName: "Test",
      severity,
      description: "x",
      filePath: "a.ts",
      lineNumber: 1,
      lineContent: "•••",
      likelyTestFixture: false,
      ...extra,
    },
  }
}

function dep(severity: "critical" | "high" | "moderate" | "low", isTransitive = false): AnyFinding {
  return {
    kind: "dependency",
    data: {
      package: "foo",
      version: "1.0.0",
      severity,
      title: "bad",
      ghsa: null,
      vulnerable_versions: "<2",
      cvss_score: 7,
      url: "https://example.com",
      isTransitive,
    },
  }
}

describe("scoreFinding", () => {
  it("returns the base points for each severity", () => {
    expect(scoreFinding(secret("critical"))).toBe(SEVERITY_BASE_POINTS.critical)
    expect(scoreFinding(secret("high"))).toBe(SEVERITY_BASE_POINTS.high)
    expect(scoreFinding(secret("medium"))).toBe(SEVERITY_BASE_POINTS.medium)
    expect(scoreFinding(secret("low"))).toBe(SEVERITY_BASE_POINTS.low)
  })

  it("applies the test-fixture multiplier", () => {
    const f = secret("critical", { likelyTestFixture: true })
    expect(scoreFinding(f)).toBeCloseTo(
      SEVERITY_BASE_POINTS.critical * TEST_FIXTURE_MULTIPLIER,
    )
  })

  it("applies the history secret multiplier", () => {
    const f = secret("critical", { source: "history" })
    expect(scoreFinding(f)).toBeCloseTo(
      SEVERITY_BASE_POINTS.critical * HISTORY_SECRET_MULTIPLIER,
    )
  })

  it("applies the transitive-dep multiplier", () => {
    const direct = dep("high", false)
    const trans = dep("high", true)
    expect(scoreFinding(trans)).toBeCloseTo(
      scoreFinding(direct) * TRANSITIVE_DEP_MULTIPLIER,
    )
  })
})

describe("prioritize", () => {
  it("sorts findings by descending score", () => {
    const findings = [secret("low"), secret("critical"), secret("medium")]
    const out = prioritize(findings)
    expect(out.map((f) => f.data.severity)).toEqual(["critical", "medium", "low"])
  })

  it("attaches a score to each finding", () => {
    const out = prioritize([secret("high")])
    expect(out[0].score).toBe(SEVERITY_BASE_POINTS.high)
  })
})

describe("scoreRepo", () => {
  it("returns 0 score for empty findings", () => {
    const result = scoreRepo([])
    expect(result.score).toBe(0)
    expect(result.prioritized).toEqual([])
    expect(result.breakdown).toEqual({
      critical: 0, high: 0, medium: 0, low: 0, fixture: 0,
    })
  })

  it("caps the score at REPO_SCORE_CAP", () => {
    const many = Array.from({ length: 50 }, () => secret("critical"))
    const result = scoreRepo(many)
    expect(result.score).toBeLessThanOrEqual(REPO_SCORE_CAP)
  })

  it("accumulates per-severity score totals in breakdown", () => {
    const result = scoreRepo([secret("critical"), secret("high"), secret("high"), secret("low")])
    expect(result.breakdown.critical).toBe(SEVERITY_BASE_POINTS.critical)
    expect(result.breakdown.high).toBe(SEVERITY_BASE_POINTS.high * 2)
    expect(result.breakdown.low).toBe(SEVERITY_BASE_POINTS.low)
  })

  it("routes fixture findings into the fixture bucket, not the severity bucket", () => {
    const result = scoreRepo([secret("critical", { likelyTestFixture: true })])
    expect(result.breakdown.critical).toBe(0)
    expect(result.breakdown.fixture).toBeGreaterThan(0)
  })
})
