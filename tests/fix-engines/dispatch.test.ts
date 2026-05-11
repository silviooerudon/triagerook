import { describe, it, expect } from "vitest"
import { findingSupportsFix, runFixEngine } from "@/lib/fix-engines"
import type { PrioritizedFinding } from "@/lib/risk"

function depFinding(): PrioritizedFinding {
  return {
    kind: "dependency",
    score: 5,
    data: {
      package: "postcss",
      version: "8.4.31",
      ecosystem: "npm",
      severity: "moderate",
      title: "postcss vuln",
      ghsa: "GHSA-test",
      vulnerable_versions: "<8.5.10",
      cvss_score: null,
      url: "https://example.com",
      source: "package.json",
    },
  }
}

function secretFinding(overrides: Partial<{ filePath: string; lineContent: string }> = {}): PrioritizedFinding {
  return {
    kind: "secret",
    score: 40,
    data: {
      patternId: "stripe-secret-key",
      patternName: "Stripe Secret Key",
      severity: "critical",
      description: "Stripe live secret",
      filePath: overrides.filePath ?? "lib/stripe.ts",
      lineNumber: 3,
      lineContent: overrides.lineContent ?? 'const stripeKey = "sk_live_abc"',
      likelyTestFixture: false,
    },
  }
}

function hardcodedCredsCodeFinding(): PrioritizedFinding {
  return {
    kind: "code",
    score: 40,
    data: {
      ruleId: "js-hardcoded-creds",
      ruleName: "Hardcoded credentials",
      severity: "critical",
      category: "hardcoded-creds",
      description: "Hardcoded credential",
      cwe: "CWE-798",
      filePath: "lib/api.ts",
      lineNumber: 1,
      lineContent: 'const apiKey = "secret-value-123"',
      likelyTestFixture: false,
    },
  }
}

describe("findingSupportsFix", () => {
  it("returns 'dep-bump' for npm dependency with parseable safe version", () => {
    expect(findingSupportsFix(depFinding())).toBe("dep-bump")
  })

  it("returns null for dependency without parseable safe version", () => {
    const f = depFinding()
    f.data = { ...f.data, vulnerable_versions: "unparseable" } as typeof f.data
    expect(findingSupportsFix(f)).toBe(null)
  })

  it("returns null for transitive dependency (cannot bump without lockfile work)", () => {
    const f = depFinding()
    f.data = { ...f.data, isTransitive: true } as typeof f.data
    expect(findingSupportsFix(f)).toBe(null)
  })

  it("returns null for dependency without a known manifest source", () => {
    const f = depFinding()
    f.data = { ...f.data, source: undefined } as typeof f.data
    expect(findingSupportsFix(f)).toBe(null)
  })

  it("returns 'secret-extract' for secret in JS/TS file with simple assignment", () => {
    expect(findingSupportsFix(secretFinding())).toBe("secret-extract")
  })

  it("returns null for secret in non-JS/TS file", () => {
    expect(findingSupportsFix(secretFinding({ filePath: "config/keys.yml" }))).toBe(null)
  })

  it("returns null for secret with line shape that is not a simple assignment", () => {
    expect(findingSupportsFix(secretFinding({ lineContent: 'callApi("sk_live_abc")' }))).toBe(null)
  })

  it("returns null for secret found in git history (file may not exist anymore)", () => {
    const f = secretFinding()
    f.data = { ...f.data, source: "history" } as typeof f.data
    expect(findingSupportsFix(f)).toBe(null)
  })

  it("returns 'secret-extract' for hardcoded-creds CodeFinding in JS/TS", () => {
    expect(findingSupportsFix(hardcodedCredsCodeFinding())).toBe("secret-extract")
  })

  it("returns null for likelyTestFixture findings (avoid noise PRs)", () => {
    const f = secretFinding()
    f.data = { ...f.data, likelyTestFixture: true } as typeof f.data
    expect(findingSupportsFix(f)).toBe(null)
  })

  it("returns null for iac findings (out of scope v1)", () => {
    const f: PrioritizedFinding = {
      kind: "iac",
      score: 5,
      data: {
        ruleId: "x",
        ruleName: "x",
        severity: "medium",
        category: "dockerfile",
        description: "x",
        filePath: "Dockerfile",
        lineNumber: 1,
        lineContent: "x",
        remediation: "x",
      },
    }
    expect(findingSupportsFix(f)).toBe(null)
  })

  it("returns null for sensitive-file findings (out of scope v1)", () => {
    const f: PrioritizedFinding = {
      kind: "sensitive-file",
      score: 40,
      data: {
        kind: "private-key",
        name: "Private key",
        severity: "critical",
        description: "x",
        filePath: "keys/id_rsa",
        remediation: "x",
      },
    }
    expect(findingSupportsFix(f)).toBe(null)
  })
})

describe("runFixEngine", () => {
  it("dispatches to dep-bump for dependency findings", () => {
    const result = runFixEngine({
      finding: depFinding(),
      fileContent: JSON.stringify({ dependencies: { postcss: "8.4.31" } }, null, 2),
      envExampleContent: null,
    })
    expect(result.kind).toBe("dep-bump")
    expect(result.patches[0].path).toBe("package.json")
    const patched = JSON.parse(result.patches[0].content)
    expect(patched.dependencies.postcss).toBe("8.5.10")
  })

  it("dispatches to secret-extract for secret findings", () => {
    const result = runFixEngine({
      finding: secretFinding(),
      fileContent: ["", "", 'const stripeKey = "sk_live_abc"'].join("\n"),
      envExampleContent: null,
    })
    expect(result.kind).toBe("secret-extract")
    const codePatch = result.patches.find((p) => p.path === "lib/stripe.ts")!
    expect(codePatch.content).toContain("process.env.STRIPE_KEY")
  })

  it("throws when finding is not supported", () => {
    const f: PrioritizedFinding = {
      kind: "iac",
      score: 5,
      data: {
        ruleId: "x",
        ruleName: "x",
        severity: "medium",
        category: "dockerfile",
        description: "x",
        filePath: "Dockerfile",
        lineNumber: 1,
        lineContent: "x",
        remediation: "x",
      },
    }
    expect(() =>
      runFixEngine({ finding: f, fileContent: "", envExampleContent: null })
    ).toThrow(/unsupported/i)
  })
})
