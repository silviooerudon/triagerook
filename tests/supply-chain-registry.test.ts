import { describe, it, expect } from "vitest"
import {
  parsePackageJsonDeps,
  detectRegistrySignals,
  type FetchLike,
} from "@/lib/supply-chain-registry"

describe("parsePackageJsonDeps", () => {
  it("collects names from all dependency maps and skips non-registry specs", () => {
    const pkg = JSON.stringify({
      dependencies: { express: "^4.18.0", "@acme/internal": "1.0.0" },
      devDependencies: { vitest: "^1.0.0", local: "file:../local", wsp: "workspace:*" },
      optionalDependencies: { fsevents: "^2.0.0" },
      peerDependencies: { react: ">=18" },
    })
    const names = parsePackageJsonDeps(pkg).sort()
    expect(names).toEqual(
      ["@acme/internal", "express", "fsevents", "react", "vitest"].sort(),
    )
    expect(names).not.toContain("local")
    expect(names).not.toContain("wsp")
  })

  it("returns [] on malformed JSON", () => {
    expect(parsePackageJsonDeps("{bad")).toEqual([])
  })
})

// Fake registry: name → metadata payload, or 404 / error.
function makeFetch(reg: Record<string, unknown | "404" | "error">): FetchLike {
  return async (url: string) => {
    const name = decodeURIComponent(url.replace("https://registry.npmjs.org/", ""))
    const entry = reg[name]
    if (entry === undefined || entry === "404")
      return { ok: false, status: 404, json: async () => ({}) }
    if (entry === "error") return { ok: false, status: 500, json: async () => ({}) }
    return { ok: true, status: 200, json: async () => entry }
  }
}

const NOW = new Date("2026-05-31")
const files = (pkg: object) => new Map([["package.json", JSON.stringify(pkg)]])

describe("detectRegistrySignals", () => {
  it("flags an unpublished name as dependency confusion (HIGH)", async () => {
    const fetchImpl = makeFetch({ "@acme/internal-utils": "404" })
    const { findings } = await detectRegistrySignals(
      files({ dependencies: { "@acme/internal-utils": "1.0.0" } }),
      fetchImpl,
      NOW,
    )
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      categoryId: "dependency-confusion",
      severity: "HIGH",
      package: "@acme/internal-utils",
    })
  })

  it("flags a recently-created package (MEDIUM)", async () => {
    const fetchImpl = makeFetch({
      newpkg: { time: { created: "2026-05-20" }, maintainers: [{ name: "a" }] },
    })
    const { findings } = await detectRegistrySignals(
      files({ dependencies: { newpkg: "^1.0.0" } }),
      fetchImpl,
      NOW,
    )
    expect(findings.map((f) => f.categoryId)).toContain("recently-published")
  })

  it("does NOT flag an established, well-maintained package", async () => {
    const fetchImpl = makeFetch({
      express: {
        time: { created: "2010-01-01" },
        maintainers: [{ name: "dougwilson" }, { name: "wesleytodd" }],
        "dist-tags": { latest: "4.18.2" },
        versions: { "4.18.2": {} },
      },
    })
    const { findings } = await detectRegistrySignals(
      files({ dependencies: { express: "^4.18.2" } }),
      fetchImpl,
      NOW,
    )
    expect(findings).toHaveLength(0)
  })

  it("flags a deprecated package and a zero-maintainer package", async () => {
    const fetchImpl = makeFetch({
      old: {
        time: { created: "2015-01-01" },
        maintainers: [{ name: "x" }],
        "dist-tags": { latest: "1.0.0" },
        versions: { "1.0.0": { deprecated: "use foo instead" } },
      },
      orphan: { time: { created: "2015-01-01" }, maintainers: [] },
    })
    const { findings } = await detectRegistrySignals(
      files({ dependencies: { old: "1.0.0", orphan: "1.0.0" } }),
      fetchImpl,
      NOW,
    )
    const byPkg = Object.fromEntries(findings.map((f) => [f.package, f]))
    expect(byPkg.old).toMatchObject({ categoryId: "suspicious-maintainer", severity: "MEDIUM" })
    expect(byPkg.orphan).toMatchObject({ categoryId: "suspicious-maintainer", severity: "LOW" })
  })

  it("emits nothing on network error (unknown, not a finding)", async () => {
    const fetchImpl = makeFetch({ flaky: "error" })
    const { findings } = await detectRegistrySignals(
      files({ dependencies: { flaky: "1.0.0" } }),
      fetchImpl,
      NOW,
    )
    expect(findings).toHaveLength(0)
  })
})
