import { describe, it, expect } from "vitest"
import {
  findCatalogEntry,
  getRuleCatalog,
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
