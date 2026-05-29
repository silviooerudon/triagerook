import { describe, it, expect } from "vitest"
import { buildAttackGraph, blastRadiusForSecret } from "@/lib/attack-graph"
import type { AnyFinding } from "@/lib/risk"
import type { SecretFinding, IaCFinding } from "@/lib/types"

function secret(patternId: string, extra: Partial<SecretFinding> = {}): AnyFinding {
  return {
    kind: "secret",
    data: {
      patternId,
      patternName: patternId,
      severity: "critical",
      description: "",
      filePath: "config.ts",
      lineNumber: 3,
      lineContent: "***",
      likelyTestFixture: false,
      ...extra,
    },
  }
}

function iac(ruleId: string, likelyTestFixture = false): AnyFinding {
  const data: IaCFinding = {
    ruleId,
    ruleName: ruleId,
    severity: "high",
    category: "terraform",
    description: "",
    filePath: "main.tf",
    lineNumber: 1,
    lineContent: null,
    remediation: "",
    likelyTestFixture,
  }
  return { kind: "iac", data }
}

describe("blastRadiusForSecret", () => {
  it("maps providers to domains", () => {
    expect(blastRadiusForSecret("aws-access-key")?.domain).toBe("cloud")
    expect(blastRadiusForSecret("github-pat")?.domain).toBe("scm")
    expect(blastRadiusForSecret("stripe-live-secret")?.domain).toBe("payments")
    expect(blastRadiusForSecret("npm-access-token")?.domain).toBe("package-registry")
    expect(blastRadiusForSecret("openai-api-key")?.domain).toBe("ai")
  })

  it("returns null for unknown / non-credential patterns", () => {
    expect(blastRadiusForSecret("totally-unknown")).toBeNull()
  })
})

describe("buildAttackGraph", () => {
  it("produces a blast-radius path for a lone cloud credential", () => {
    const g = buildAttackGraph([secret("aws-access-key")])
    expect(g.paths.length).toBe(1)
    expect(g.paths[0].title).toContain("cloud")
    expect(g.nodes.some((n) => n.kind === "credential")).toBe(true)
  })

  it("chains a cloud credential with a public-resource finding into a critical path", () => {
    const g = buildAttackGraph([
      secret("aws-access-key"),
      iac("tf-s3-public-acl"),
    ])
    const chained = g.paths.find((p) => p.title.includes("cloud account"))
    expect(chained).toBeDefined()
    expect(chained!.severity).toBe("critical")
    expect(chained!.steps.join(" ")).toMatch(/Reachable resource exposed by/)
  })

  it("elevates a validated-live credential to critical", () => {
    const g = buildAttackGraph([secret("stripe-live-secret", { validation: "active" } as Partial<SecretFinding>)])
    expect(g.paths[0].severity).toBe("critical")
    expect(g.paths[0].liveCredential).toBe(true)
  })

  it("adds a supply-chain pivot for SCM tokens", () => {
    const g = buildAttackGraph([secret("github-pat")])
    expect(g.paths[0].steps.join(" ")).toMatch(/supply chain/i)
  })

  it("ignores test-fixture secrets", () => {
    const g = buildAttackGraph([secret("aws-access-key", { likelyTestFixture: true })])
    expect(g.paths).toHaveLength(0)
  })

  it("emits a standalone exposure path when there's a public resource but no credential", () => {
    const g = buildAttackGraph([iac("tf-s3-public-access-block-disabled")])
    expect(g.paths.some((p) => p.title.includes("Public cloud resource"))).toBe(true)
  })

  it("ignores test-fixture IaC findings when correlating", () => {
    // A wildcard-IAM finding in a test fixture must not chain a cloud key into
    // a critical path, nor produce a standalone exposure path.
    const chained = buildAttackGraph([
      secret("aws-access-key"),
      iac("tf-s3-public-acl", true),
    ])
    expect(chained.paths.some((p) => p.title.includes("cloud account"))).toBe(false)

    const standalone = buildAttackGraph([iac("iam-aws-wildcard-action", true)])
    expect(standalone.paths).toHaveLength(0)
  })

  it("returns an empty graph for a clean / non-correlating finding set", () => {
    const g = buildAttackGraph([secret("totally-unknown")])
    expect(g.paths).toHaveLength(0)
    expect(g.nodes).toHaveLength(0)
  })

  it("sorts paths with critical first", () => {
    const g = buildAttackGraph([
      secret("openai-api-key"), // ai, high-ish
      secret("aws-access-key"), // cloud
      iac("tf-s3-public-acl"), // makes aws critical
    ])
    expect(g.paths[0].severity).toBe("critical")
  })
})
