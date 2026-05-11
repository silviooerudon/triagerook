import { describe, it, expect } from "vitest"
import {
  parseSuppressions,
  applySuppressions,
  findRuleIdForFinding,
} from "@/lib/suppressions"
import type { AnyFinding } from "@/lib/risk"

function secretFinding(filePath: string, patternId = "github-pat"): AnyFinding {
  return {
    kind: "secret",
    data: {
      patternId,
      patternName: patternId,
      severity: "critical",
      description: "x",
      filePath,
      lineNumber: 1,
      lineContent: "•••",
      likelyTestFixture: false,
    },
  }
}

describe("parseSuppressions", () => {
  it("parses a plain path glob", () => {
    const out = parseSuppressions("tests/**/*.ts")
    expect(out).toEqual([
      { pathGlob: "tests/**/*.ts", sourceLine: 1 },
    ])
  })

  it("ignores comments and blank lines", () => {
    const content = `
# this is a comment
tests/**/*.ts

src/**/*.spec.ts
`
    const out = parseSuppressions(content)
    expect(out.map((s) => s.pathGlob)).toEqual(["tests/**/*.ts", "src/**/*.spec.ts"])
  })

  it("parses [rule=...] modifier", () => {
    const out = parseSuppressions("tests/fixtures/** [rule=secret/*]")
    expect(out[0].ruleGlob).toBe("secret/*")
  })

  it("parses quoted [reason=...] with spaces", () => {
    const out = parseSuppressions(`docs/** [reason="known fixture, not real"]`)
    expect(out[0].reason).toBe("known fixture, not real")
  })

  it("parses ISO expires date and rejects garbage", () => {
    const out = parseSuppressions("tmp/** [expires=2099-12-31]\nfoo/** [expires=not-a-date]")
    expect(out[0].expires).toBe("2099-12-31")
    expect(out[1].expires).toBeUndefined()
  })
})

describe("findRuleIdForFinding", () => {
  it("namespaces secrets by patternId", () => {
    expect(findRuleIdForFinding(secretFinding("a.ts"))).toBe("secret/github-pat")
  })

  it("uses entropy/ prefix for entropy findings", () => {
    expect(
      findRuleIdForFinding(secretFinding("a.ts", "entropy-high-secret")),
    ).toBe("entropy/entropy-high-secret")
  })

  it("uses git-history/ namespace for history secrets", () => {
    const f: AnyFinding = secretFinding("a.ts")
    f.data.source = "history"
    expect(findRuleIdForFinding(f)).toBe("git-history/github-pat")
  })
})

describe("applySuppressions", () => {
  it("suppresses findings whose path matches a suppression", () => {
    const findings = [secretFinding("tests/fixtures/keys.ts"), secretFinding("src/server.ts")]
    const suppressions = parseSuppressions("tests/**")
    const result = applySuppressions(findings, suppressions)
    expect(result.kept.map((f) => f.data.filePath)).toEqual(["src/server.ts"])
    expect(result.suppressed).toHaveLength(1)
  })

  it("respects [rule=...] scope", () => {
    const findings = [
      secretFinding("tests/a.ts", "github-pat"),
      secretFinding("tests/a.ts", "aws-access-key"),
    ]
    const suppressions = parseSuppressions("tests/** [rule=secret/github-pat]")
    const result = applySuppressions(findings, suppressions)
    expect(result.kept).toHaveLength(1)
    expect(result.kept[0].data.patternId).toBe("aws-access-key")
  })

  it("flags expired suppressions but still suppresses the finding", () => {
    const findings = [secretFinding("tests/a.ts")]
    const suppressions = parseSuppressions("tests/** [expires=2000-01-01]")
    const result = applySuppressions(findings, suppressions, new Date("2026-01-01"))
    expect(result.suppressed).toHaveLength(1)
    expect(result.suppressed[0].expired).toBe(true)
    expect(result.expiredSuppressionsCount).toBe(1)
  })

  it("does not flag unexpired suppressions", () => {
    const findings = [secretFinding("tests/a.ts")]
    const suppressions = parseSuppressions("tests/** [expires=2099-12-31]")
    const result = applySuppressions(findings, suppressions, new Date("2026-01-01"))
    expect(result.suppressed[0].expired).toBe(false)
  })

  it("more specific rule wins over generic catch-all", () => {
    const findings = [secretFinding("src/a.ts", "github-pat")]
    const suppressions = parseSuppressions(`** [rule=secret/aws-access-key]\nsrc/a.ts [rule=secret/github-pat]`)
    const result = applySuppressions(findings, suppressions)
    expect(result.suppressed).toHaveLength(1)
  })

  it("dep suppression with pathGlob 'package.json' matches transitive deps recorded under package-lock.json", () => {
    const finding: AnyFinding = {
      kind: "dependency",
      data: {
        package: "postcss",
        version: "8.4.31",
        ecosystem: "npm",
        severity: "moderate",
        title: "postcss vuln",
        ghsa: "GHSA-qx2v-qp2m-jg93",
        vulnerable_versions: "<8.5.10",
        cvss_score: null,
        url: "",
        source: "package-lock.json",
        isTransitive: true,
      },
    }
    const suppressions = parseSuppressions("package.json [rule=dependency/postcss]")
    const result = applySuppressions([finding], suppressions)
    expect(result.suppressed).toHaveLength(1)
    expect(result.kept).toHaveLength(0)
  })

  it("dep suppression with pathGlob 'requirements.txt' matches deps in any python manifest", () => {
    const inPyproject: AnyFinding = {
      kind: "dependency",
      data: {
        package: "django",
        version: "4.2.1",
        ecosystem: "PyPI",
        severity: "high",
        title: "django vuln",
        ghsa: "GHSA-django",
        vulnerable_versions: "<4.2.7",
        cvss_score: null,
        url: "",
        source: "pyproject.toml",
      },
    }
    const inPipfile: AnyFinding = {
      ...inPyproject,
      data: { ...inPyproject.data, source: "Pipfile" },
    } as AnyFinding
    const suppressions = parseSuppressions("requirements.txt [rule=dependency/django]")
    const result = applySuppressions([inPyproject, inPipfile], suppressions)
    expect(result.suppressed).toHaveLength(2)
    expect(result.kept).toHaveLength(0)
  })

  it("dep suppression with exact source still matches (no regression for explicit lock-file scope)", () => {
    const finding: AnyFinding = {
      kind: "dependency",
      data: {
        package: "postcss",
        version: "8.4.31",
        ecosystem: "npm",
        severity: "moderate",
        title: "x",
        ghsa: null,
        vulnerable_versions: "<8.5.10",
        cvss_score: null,
        url: "",
        source: "package-lock.json",
      },
    }
    const suppressions = parseSuppressions("package-lock.json [rule=dependency/postcss]")
    const result = applySuppressions([finding], suppressions)
    expect(result.suppressed).toHaveLength(1)
  })
})
