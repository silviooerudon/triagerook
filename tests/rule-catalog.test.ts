import { describe, it, expect } from "vitest"
import {
  findCatalogEntry,
  getRuleCatalog,
  resolveCatalogEntry,
  ruleIdToSlug,
  slugToRuleId,
} from "@/lib/rule-catalog"

describe("rule catalog", () => {
  it("aggregates rules across every detector layer", () => {
    const layers = new Set(getRuleCatalog().map((e) => e.layer))
    expect(layers.has("ast")).toBe(true)
    expect(layers.has("regex-code")).toBe(true)
    expect(layers.has("secret-regex")).toBe(true)
    expect(layers.has("sensitive-file")).toBe(true)
    expect(layers.has("iac-dockerfile")).toBe(true)
    expect(layers.has("iac-github-actions")).toBe(true)
  })

  it("contains a known AST rule", () => {
    const entry = findCatalogEntry("ast/sql-injection-template")
    expect(entry).toBeDefined()
    expect(entry?.layer).toBe("ast")
    expect(entry?.cwe).toBe("CWE-89")
    expect(entry?.severity).toBe("critical")
  })

  it("contains a known regex code rule (prefixed with code/)", () => {
    const entry = findCatalogEntry("code/js-tls-verify-disabled")
    expect(entry).toBeDefined()
    expect(entry?.layer).toBe("regex-code")
  })

  it("contains a known secret pattern (prefixed with secret/)", () => {
    const entry = findCatalogEntry("secret/aws-access-key")
    expect(entry).toBeDefined()
    expect(entry?.severity).toBe("critical")
  })

  it("contains a known sensitive-file rule (prefixed with sensitive-file/)", () => {
    const entry = findCatalogEntry("sensitive-file/private-key")
    expect(entry).toBeDefined()
    expect(entry?.remediation).toBeTruthy()
  })

  it("sorts critical before high before medium before low", () => {
    const catalog = getRuleCatalog()
    let lastSevRank = -1
    const sevRank = { critical: 0, high: 1, medium: 2, low: 3 } as const
    for (const e of catalog) {
      const rank = sevRank[e.severity]
      expect(rank).toBeGreaterThanOrEqual(lastSevRank)
      lastSevRank = rank
    }
  })

  it("returns undefined for an unknown rule id", () => {
    expect(findCatalogEntry("ast/does-not-exist")).toBeUndefined()
  })

  it("ruleIdToSlug + slugToRuleId round-trip every catalog entry", () => {
    for (const entry of getRuleCatalog()) {
      const slug = ruleIdToSlug(entry.id)
      expect(slug).not.toContain("/")
      expect(slugToRuleId(slug)).toBe(entry.id)
    }
  })

  it("memoises the catalog (same array reference across calls)", () => {
    expect(getRuleCatalog()).toBe(getRuleCatalog())
  })
})

describe("resolveCatalogEntry — SARIF id aliasing", () => {
  it("returns the entry directly when ids already match", () => {
    expect(resolveCatalogEntry("ast/sql-injection-template")?.layer).toBe("ast")
  })

  it("maps SARIF code/<id> to an AST entry when no regex rule with that id exists", () => {
    // SARIF emits `code/sql-injection-template` for AST findings (they
    // ride on the CodeFinding kind), but the catalog stores them under
    // `ast/`. The resolver bridges the two.
    const entry = resolveCatalogEntry("code/sql-injection-template")
    expect(entry).toBeDefined()
    expect(entry?.layer).toBe("ast")
    expect(entry?.id).toBe("ast/sql-injection-template")
  })

  it("keeps SARIF code/<id> pointing at the regex-code entry when one exists", () => {
    const entry = resolveCatalogEntry("code/js-tls-verify-disabled")
    expect(entry?.layer).toBe("regex-code")
  })

  it("maps SARIF iac/<id> to the dockerfile catalog entry when one exists", () => {
    const dockerfileRule = getRuleCatalog().find((e) => e.layer === "iac-dockerfile")
    expect(dockerfileRule).toBeDefined()
    if (!dockerfileRule) return
    const tail = dockerfileRule.id.replace(/^iac\/dockerfile\//, "")
    const entry = resolveCatalogEntry(`iac/${tail}`)
    expect(entry?.id).toBe(dockerfileRule.id)
  })

  it("returns undefined for dependency findings (no catalog page)", () => {
    expect(resolveCatalogEntry("dependency/lodash")).toBeUndefined()
    expect(resolveCatalogEntry("dependency/GHSA-x-y-z")).toBeUndefined()
  })

  it("returns undefined for unknown ids that don't match any aliasing rule", () => {
    expect(resolveCatalogEntry("nonsense/whatever")).toBeUndefined()
    expect(resolveCatalogEntry("code/does-not-exist")).toBeUndefined()
    expect(resolveCatalogEntry("plain-no-slash")).toBeUndefined()
  })
})
