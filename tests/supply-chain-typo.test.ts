import { describe, it, expect } from "vitest"
import { __testMatchTyposquat } from "@/lib/supply-chain-typo"

const { damerauLevenshtein, sharesPrefix, parsePackageJsonDeps, parseRequirementsTxt } =
  __testMatchTyposquat

describe("damerauLevenshtein", () => {
  it("returns 0 for identical strings", () => {
    expect(damerauLevenshtein("lodash", "lodash", 2)).toBe(0)
  })

  it("returns 1 for a single substitution", () => {
    expect(damerauLevenshtein("lodash", "lodaah", 2)).toBe(1)
  })

  it("returns 1 for a transposition (Damerau)", () => {
    expect(damerauLevenshtein("lodash", "lodahs", 2)).toBe(1)
  })

  it("returns cap+1 when distance would exceed cap", () => {
    expect(damerauLevenshtein("a", "abcdefgh", 2)).toBe(3)
  })

  it("short-circuits on length-diff > cap", () => {
    expect(damerauLevenshtein("a", "abcdefgh", 1)).toBe(2)
  })
})

describe("sharesPrefix", () => {
  it("returns true when the first N chars match (transposition keeps prefix)", () => {
    expect(sharesPrefix("lodash", "lodahs", 3)).toBe(true)
  })

  it("returns false when prefixes diverge", () => {
    expect(sharesPrefix("lodash", "react", 3)).toBe(false)
    expect(sharesPrefix("lodash", "loadash", 3)).toBe(false)
  })

  it("returns false when a string is shorter than N", () => {
    expect(sharesPrefix("lo", "lodash", 3)).toBe(false)
  })
})

describe("parsePackageJsonDeps", () => {
  it("collects dependencies and devDependencies, skipping scoped packages", () => {
    const pkg = JSON.stringify({
      dependencies: { lodahs: "^1.0.0", react: "^19.0.0", "@scope/internal": "^1" },
      devDependencies: { vitest: "^4" },
    })
    const names = parsePackageJsonDeps(pkg)
    expect(names).toContain("lodahs")
    expect(names).toContain("react")
    expect(names).toContain("vitest")
    expect(names).not.toContain("@scope/internal")
  })

  it("returns empty for invalid JSON", () => {
    expect(parsePackageJsonDeps("not json")).toEqual([])
  })

  it("returns empty when no dep keys are present", () => {
    expect(parsePackageJsonDeps(JSON.stringify({ name: "x" }))).toEqual([])
  })
})

describe("parseRequirementsTxt", () => {
  it("strips version specifiers", () => {
    const names = parseRequirementsTxt("requsts==2.31.0\nflask>=2.0\n# comment\n")
    expect(names).toContain("requsts")
    expect(names).toContain("flask")
  })

  it("ignores blank lines, comments, and option lines", () => {
    const names = parseRequirementsTxt("\n# header\n  \n-e .\nrequests\n")
    expect(names).toEqual(["requests"])
  })
})
