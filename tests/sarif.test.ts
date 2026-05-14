import { describe, it, expect } from "vitest"
import { scanToSarif, type ScanForSarif } from "@/lib/sarif"
import type { AnyFinding } from "@/lib/risk"

function baseScan(overrides: Partial<ScanForSarif> = {}): ScanForSarif {
  return {
    owner: "silviooerudon",
    repo: "rg-fix-test",
    scannedAt: "2026-05-12T20:00:00.000Z",
    riskScore: 36,
    findings: [],
    ...overrides,
  }
}

function secretFinding(overrides: Partial<{ filePath: string; lineNumber: number; patternId: string; severity: "critical" | "high" | "medium" | "low"; likelyTestFixture: boolean }> = {}): AnyFinding {
  return {
    kind: "secret",
    data: {
      patternId: overrides.patternId ?? "aws-access-key",
      patternName: "AWS Access Key ID",
      severity: overrides.severity ?? "critical",
      description: "AWS Access Key",
      filePath: overrides.filePath ?? "lib/secrets.ts",
      lineNumber: overrides.lineNumber ?? 12,
      lineContent: "•••",
      likelyTestFixture: overrides.likelyTestFixture ?? false,
    },
  }
}

describe("scanToSarif - envelope", () => {
  it("returns SARIF 2.1.0 with one run", () => {
    const out = scanToSarif(baseScan())
    expect(out.version).toBe("2.1.0")
    expect(out.$schema).toContain("sarif-2.1.0")
    expect(out.runs).toHaveLength(1)
  })

  it("populates tool.driver with RepoGuard metadata", () => {
    const out = scanToSarif(baseScan())
    const driver = out.runs[0].tool.driver
    expect(driver.name).toBe("RepoGuard")
    expect(driver.version).toBeTruthy()
    expect(driver.informationUri).toContain("repoguard")
  })

  it("uses the version from package.json (not a stale hardcoded string)", async () => {
    const pkg = await import("../package.json")
    const out = scanToSarif(baseScan())
    expect(out.runs[0].tool.driver.version).toBe(pkg.version)
  })

  it("attaches scan metadata to run.properties", () => {
    const out = scanToSarif(baseScan({ riskScore: 42 }))
    const props = out.runs[0].properties
    expect(props?.owner).toBe("silviooerudon")
    expect(props?.repo).toBe("rg-fix-test")
    expect(props?.scannedAt).toBe("2026-05-12T20:00:00.000Z")
    expect(props?.riskScore).toBe(42)
  })

  it("emits no results when findings is empty", () => {
    const out = scanToSarif(baseScan())
    expect(out.runs[0].results).toEqual([])
    expect(out.runs[0].tool.driver.rules).toEqual([])
  })
})

describe("scanToSarif - secret findings", () => {
  it("maps a critical secret to level=error with file+line location", () => {
    const out = scanToSarif(baseScan({ findings: [secretFinding()] }))
    const result = out.runs[0].results[0]
    expect(result.ruleId).toBe("secret/aws-access-key")
    expect(result.level).toBe("error")
    const loc = result.locations[0].physicalLocation
    expect(loc.artifactLocation.uri).toBe("lib/secrets.ts")
    expect(loc.region?.startLine).toBe(12)
  })

  it("downgrades fixture findings to level=note regardless of severity", () => {
    const out = scanToSarif(
      baseScan({ findings: [secretFinding({ likelyTestFixture: true, severity: "critical" })] }),
    )
    expect(out.runs[0].results[0].level).toBe("note")
  })

  it("dedupes the rules array (one rule per unique ruleId)", () => {
    const out = scanToSarif(
      baseScan({
        findings: [
          secretFinding({ filePath: "a.ts", lineNumber: 1 }),
          secretFinding({ filePath: "b.ts", lineNumber: 2 }),
        ],
      }),
    )
    expect(out.runs[0].tool.driver.rules).toHaveLength(1)
    expect(out.runs[0].tool.driver.rules[0].id).toBe("secret/aws-access-key")
    expect(out.runs[0].results).toHaveLength(2)
  })
})

describe("scanToSarif - severity mapping", () => {
  it("maps high to error", () => {
    const out = scanToSarif(baseScan({ findings: [secretFinding({ severity: "high" })] }))
    expect(out.runs[0].results[0].level).toBe("error")
  })
  it("maps medium to warning", () => {
    const out = scanToSarif(baseScan({ findings: [secretFinding({ severity: "medium" })] }))
    expect(out.runs[0].results[0].level).toBe("warning")
  })
  it("maps low to note", () => {
    const out = scanToSarif(baseScan({ findings: [secretFinding({ severity: "low" })] }))
    expect(out.runs[0].results[0].level).toBe("note")
  })
})

describe("scanToSarif - dependency findings", () => {
  it("locates a dependency finding at its manifest path with no line", () => {
    const dep: AnyFinding = {
      kind: "dependency",
      data: {
        package: "lodash",
        version: "4.17.20",
        ecosystem: "npm",
        severity: "high",
        title: "Command Injection in lodash",
        ghsa: null,
        vulnerable_versions: "<4.17.21",
        cvss_score: 7.2,
        url: "https://example.com",
        source: "package.json",
      },
    }
    const out = scanToSarif(baseScan({ findings: [dep] }))
    const r = out.runs[0].results[0]
    expect(r.ruleId).toBe("dependency/lodash")
    expect(r.level).toBe("error")
    const loc = r.locations[0].physicalLocation
    expect(loc.artifactLocation.uri).toBe("package.json")
    expect(loc.region).toBeUndefined()
  })

  it("uses ghsa-based ruleId when ghsa present (for dedupe across versions)", () => {
    const dep: AnyFinding = {
      kind: "dependency",
      data: {
        package: "postcss",
        version: "8.4.31",
        ecosystem: "npm",
        severity: "moderate",
        title: "x",
        ghsa: "GHSA-qx2v-qp2m-jg93",
        vulnerable_versions: "<8.5.10",
        cvss_score: null,
        url: "",
        source: "package-lock.json",
      },
    }
    const out = scanToSarif(baseScan({ findings: [dep] }))
    expect(out.runs[0].results[0].ruleId).toBe("dependency/GHSA-qx2v-qp2m-jg93")
  })
})

describe("scanToSarif - code findings", () => {
  it("locates a code finding at file:line with code/<ruleId>", () => {
    const code: AnyFinding = {
      kind: "code",
      data: {
        ruleId: "js-tls-verify-disabled",
        ruleName: "TLS verification disabled",
        severity: "high",
        category: "tls-verification",
        description: "x",
        cwe: "CWE-295",
        filePath: "src/api.ts",
        lineNumber: 42,
        lineContent: "x",
        likelyTestFixture: false,
      },
    }
    const out = scanToSarif(baseScan({ findings: [code] }))
    const r = out.runs[0].results[0]
    expect(r.ruleId).toBe("code/js-tls-verify-disabled")
    expect(r.level).toBe("error")
    expect(r.locations[0].physicalLocation.region?.startLine).toBe(42)
  })
})

describe("scanToSarif - sensitive-file findings", () => {
  it("uses sensitive-file/<kind> ruleId, no line in location", () => {
    const sf: AnyFinding = {
      kind: "sensitive-file",
      data: {
        kind: "private-key",
        name: "Private Key",
        severity: "critical",
        description: "x",
        filePath: "keys/id_rsa",
        remediation: "x",
      },
    }
    const out = scanToSarif(baseScan({ findings: [sf] }))
    expect(out.runs[0].results[0].ruleId).toBe("sensitive-file/private-key")
    expect(out.runs[0].results[0].locations[0].physicalLocation.region).toBeUndefined()
  })
})

describe("scanToSarif - helpUri injection", () => {
  it("populates helpUri on each rule entry when getHelpUri is provided", () => {
    const out = scanToSarif(
      baseScan({
        findings: [secretFinding({ patternId: "aws-access-key" })],
        getHelpUri: (id) =>
          id === "secret/aws-access-key"
            ? "https://example.com/docs/rules/secret.aws-access-key"
            : undefined,
      }),
    )
    expect(out.runs[0].tool.driver.rules[0].helpUri).toBe(
      "https://example.com/docs/rules/secret.aws-access-key",
    )
  })

  it("omits helpUri when getHelpUri returns undefined for an id", () => {
    const out = scanToSarif(
      baseScan({
        findings: [secretFinding({ patternId: "aws-access-key" })],
        getHelpUri: () => undefined,
      }),
    )
    expect(out.runs[0].tool.driver.rules[0].helpUri).toBeUndefined()
  })

  it("omits helpUri entirely when getHelpUri is not provided (client SARIF path)", () => {
    const out = scanToSarif(baseScan({ findings: [secretFinding()] }))
    expect(out.runs[0].tool.driver.rules[0].helpUri).toBeUndefined()
  })
})

describe("scanToSarif - iac findings", () => {
  it("locates an iac finding at file:line when both present", () => {
    const iac: AnyFinding = {
      kind: "iac",
      data: {
        ruleId: "iac-docker-root-user",
        ruleName: "Docker container runs as root",
        severity: "medium",
        category: "dockerfile",
        description: "x",
        filePath: "Dockerfile",
        lineNumber: 5,
        lineContent: "USER root",
        remediation: "x",
      },
    }
    const out = scanToSarif(baseScan({ findings: [iac] }))
    expect(out.runs[0].results[0].ruleId).toBe("iac/iac-docker-root-user")
    expect(out.runs[0].results[0].level).toBe("warning")
    expect(out.runs[0].results[0].locations[0].physicalLocation.region?.startLine).toBe(5)
  })

  it("omits region when iac finding has no line number", () => {
    const iac: AnyFinding = {
      kind: "iac",
      data: {
        ruleId: "iac-something",
        ruleName: "x",
        severity: "low",
        category: "github-actions",
        description: "x",
        filePath: ".github/workflows/ci.yml",
        lineNumber: null,
        lineContent: null,
        remediation: "x",
      },
    }
    const out = scanToSarif(baseScan({ findings: [iac] }))
    expect(out.runs[0].results[0].locations[0].physicalLocation.region).toBeUndefined()
  })
})
