import { describe, it, expect } from "vitest"
import {
  scoreFinding,
  prioritize,
  scoreRepo,
  compressScore,
  SEVERITY_BASE_POINTS,
  TEST_FIXTURE_MULTIPLIER,
  HISTORY_SECRET_MULTIPLIER,
  TRANSITIVE_DEP_MULTIPLIER,
  REPO_SCORE_CAP,
  SCORE_LOG_MULTIPLIER,
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

  it("does NOT count fixture findings toward the score gauge", () => {
    // Regression for the dogfood pass: scanning repoguard/repoguard
    // returned score=43 CRITICAL even though every visible finding was
    // tagged "Test fixture". The breakdown.fixture bucket was leaking
    // into the score total. The tag promises the user "this doesn't
    // count" — the gauge must honour it.
    const fixturesOnly = Array.from({ length: 100 }, () =>
      secret("critical", { likelyTestFixture: true }),
    )
    const result = scoreRepo(fixturesOnly)
    expect(result.score).toBe(0)
    expect(result.breakdown.fixture).toBeGreaterThan(0)
  })

  it("mixes fixtures and real findings — only real findings count", () => {
    // One real high + a pile of fixture criticals → score reflects the
    // single high. The fixtures sit in the breakdown for transparency.
    const findings = [
      secret("high"),
      ...Array.from({ length: 50 }, () =>
        secret("critical", { likelyTestFixture: true }),
      ),
    ]
    const result = scoreRepo(findings)
    expect(result.score).toBe(compressScore(SEVERITY_BASE_POINTS.high))
    expect(result.breakdown.high).toBe(SEVERITY_BASE_POINTS.high)
    expect(result.breakdown.fixture).toBeGreaterThan(0)
  })
})

describe("compressScore — log-scale (no more saturation at 0)", () => {
  // Regression coverage for the 2026-05-14 dogfood saturation finding.
  // Before the log compression, any repo with > 2 criticals (≥ 80
  // points raw) saturated at penalty=100 and the gauge read "0/100
  // CRITICAL". After the change, large repos still get distinguishing
  // scores until the deduction sum is genuinely huge.
  it("returns 0 for zero raw total", () => {
    expect(compressScore(0)).toBe(0)
  })

  it("returns 0 for negative input (defensive)", () => {
    expect(compressScore(-5)).toBe(0)
  })

  it("is monotonically non-decreasing in raw total", () => {
    let prev = compressScore(0)
    for (const raw of [10, 25, 50, 100, 250, 500, 1000, 2500, 10000]) {
      const curr = compressScore(raw)
      expect(curr).toBeGreaterThanOrEqual(prev)
      prev = curr
    }
  })

  it("keeps small repos with a few findings well below the cap", () => {
    expect(compressScore(25)).toBeLessThan(50)
    expect(compressScore(100)).toBeLessThan(70)
  })

  it("distinguishes a mid-sized busy repo from a saturated mega-repo", () => {
    // Real numbers from the dogfood pass: nestjs ≈ 223, supabase ≈ 1670.
    // Before this change they both displayed identically. After, they
    // sit in different score bands.
    const nest = compressScore(223)
    const supabase = compressScore(1670)
    expect(nest).toBeLessThan(supabase)
    expect(supabase - nest).toBeGreaterThanOrEqual(15)
  })

  it("caps at REPO_SCORE_CAP for catastrophic deduction sums", () => {
    expect(compressScore(100_000)).toBe(REPO_SCORE_CAP)
  })

  it("uses SCORE_LOG_MULTIPLIER (sanity for future tuning)", () => {
    // raw=9 → log10(10)=1 → penalty == SCORE_LOG_MULTIPLIER
    expect(compressScore(9)).toBe(SCORE_LOG_MULTIPLIER)
  })

  it("scoreRepo plumbing — many criticals no longer all saturate", () => {
    // Before the log compression this returned the cap (100). After,
    // small differences in critical count produce distinguishable
    // scores.
    const five = scoreRepo(Array.from({ length: 5 }, () => secret("critical")))
    const fifty = scoreRepo(Array.from({ length: 50 }, () => secret("critical")))
    expect(five.score).toBeLessThan(fifty.score)
    expect(fifty.score).toBeLessThanOrEqual(REPO_SCORE_CAP)
  })
})
