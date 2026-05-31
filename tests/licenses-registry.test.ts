import { describe, it, expect } from "vitest"
import { scanRegistryLicenses, type FetchLike } from "@/lib/licenses-registry"

// Build a fake fetch that serves GitHub manifest contents by path and deps.dev
// version metadata by (system, name) → licenses. Anything unknown is a 404.
function makeFetch(opts: {
  manifests?: Record<string, string>
  // key: `${system}/${name}` (name url-decoded), value: licenses array or "error"
  depsDev?: Record<string, string[] | "error" | "missing">
}): FetchLike {
  const manifests = opts.manifests ?? {}
  const depsDev = opts.depsDev ?? {}
  return async (url: string) => {
    const ok = (status: number, body: unknown) => ({
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
      text: async () => (typeof body === "string" ? body : JSON.stringify(body)),
      headers: { get: () => null },
    })

    const gh = url.match(/contents\/(.+)$/)
    if (gh) {
      const path = decodeURIComponent(gh[1])
      if (manifests[path] !== undefined) return ok(200, manifests[path])
      return ok(404, "")
    }

    const dd = url.match(/systems\/([^/]+)\/packages\/([^/]+)\/versions\//)
    if (dd) {
      const system = dd[1]
      const name = decodeURIComponent(dd[2])
      const entry = depsDev[`${system}/${name}`]
      if (entry === undefined) return ok(404, {})
      if (entry === "error") return ok(500, {})
      if (entry === "missing") return ok(200, { licenses: [] })
      return ok(200, { licenses: entry })
    }
    return ok(404, "")
  }
}

describe("scanRegistryLicenses", () => {
  it("flags a GPL Go module as strong copyleft", async () => {
    const fetchImpl = makeFetch({
      manifests: { "go.mod": "module x\n\nrequire (\n\tgithub.com/foo/bar v1.2.3\n)\n" },
      depsDev: { "go/github.com/foo/bar": ["GPL-3.0"] },
    })
    const { findings, degraded } = await scanRegistryLicenses("o", "r", null, fetchImpl)
    expect(degraded).toBeNull()
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      package: "github.com/foo/bar",
      ecosystem: "Go",
      risk: "copyleft-strong",
      severity: "high",
      source: "go.mod",
    })
  })

  it("does NOT flag a permissive (MIT) package", async () => {
    const fetchImpl = makeFetch({
      manifests: { "Gemfile.lock": "GEM\n  specs:\n    rails (7.0.0)\n\nPLATFORMS\n" },
      depsDev: { "rubygems/rails": ["MIT"] },
    })
    const { findings } = await scanRegistryLicenses("o", "r", null, fetchImpl)
    expect(findings).toHaveLength(0)
  })

  it("maps PyPI requirements + classifies AGPL", async () => {
    const fetchImpl = makeFetch({
      manifests: { "requirements.txt": "somepkg==1.0.0\nflask==2.0.0\n" },
      depsDev: {
        "pypi/somepkg": ["AGPL-3.0"],
        "pypi/flask": ["BSD-3-Clause"],
      },
    })
    const { findings } = await scanRegistryLicenses("o", "r", null, fetchImpl)
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      package: "somepkg",
      ecosystem: "PyPI",
      risk: "copyleft-strong",
    })
  })

  it("picks the riskiest of multiple detected licenses", async () => {
    const fetchImpl = makeFetch({
      manifests: { "go.mod": "require example.com/m v1.0.0\n" },
      depsDev: { "go/example.com/m": ["MIT", "LGPL-2.1"] },
    })
    const { findings } = await scanRegistryLicenses("o", "r", null, fetchImpl)
    expect(findings).toHaveLength(1)
    expect(findings[0].risk).toBe("copyleft-weak")
    expect(findings[0].license).toContain("LGPL-2.1")
  })

  it("treats empty deps.dev licenses as unknown (no missing-license noise)", async () => {
    const fetchImpl = makeFetch({
      manifests: { "go.mod": "require example.com/m v1.0.0\n" },
      depsDev: { "go/example.com/m": "missing" },
    })
    const { findings, degraded } = await scanRegistryLicenses("o", "r", null, fetchImpl)
    expect(findings).toHaveLength(0)
    expect(degraded).toBeNull()
  })

  it("degrades when deps.dev is down and nothing resolved", async () => {
    const fetchImpl = makeFetch({
      manifests: { "go.mod": "require example.com/m v1.0.0\n" },
      depsDev: { "go/example.com/m": "error" },
    })
    const { findings, degraded } = await scanRegistryLicenses("o", "r", null, fetchImpl)
    expect(findings).toHaveLength(0)
    expect(degraded?.detector).toBe("license-registry")
  })

  it("still degrades on a PARTIAL failure even when some licenses resolved", async () => {
    // Regression: a 500 for one package + a resolved copyleft for another must
    // not read as a comprehensive scan.
    const fetchImpl = makeFetch({
      manifests: {
        "go.mod": "require (\n\texample.com/ok v1.0.0\n\texample.com/bad v1.0.0\n)\n",
      },
      depsDev: { "go/example.com/ok": ["GPL-3.0"], "go/example.com/bad": "error" },
    })
    const { findings, degraded } = await scanRegistryLicenses("o", "r", null, fetchImpl)
    expect(findings).toHaveLength(1)
    expect(degraded?.detector).toBe("license-registry")
  })

  it("retries Go v2+ modules with the +incompatible suffix on 404", async () => {
    const seen: string[] = []
    const base = makeFetch({
      manifests: { "go.mod": "require example.com/m v2.3.4\n" },
      // only the +incompatible variant resolves
      depsDev: { "go/example.com/m": "error" },
    })
    const fetchImpl: FetchLike = async (url, init) => {
      if (url.includes("api.deps.dev")) {
        seen.push(url)
        if (/v2\.3\.4%2Bincompatible$/.test(url)) {
          return {
            ok: true, status: 200,
            json: async () => ({ licenses: ["GPL-3.0"] }),
            text: async () => "", headers: { get: () => null },
          }
        }
        // primary (no suffix) → 404
        return {
          ok: false, status: 404,
          json: async () => ({}), text: async () => "", headers: { get: () => null },
        }
      }
      return base(url, init)
    }
    const { findings } = await scanRegistryLicenses("o", "r", null, fetchImpl)
    expect(seen.some((u) => /v2\.3\.4%2Bincompatible$/.test(u))).toBe(true)
    expect(findings).toHaveLength(1)
    expect(findings[0].risk).toBe("copyleft-strong")
  })

  it("does NOT mark degraded when a Go v2+ +incompatible RETRY fails (benign 404)", async () => {
    // The primary 404 already means 'no data'; a best-effort retry failure must
    // not asymmetrically inflate the degraded marker for Go v2+ only.
    const base = makeFetch({ manifests: { "go.mod": "require example.com/m v2.0.0\n" } })
    const fetchImpl: FetchLike = async (url, init) => {
      if (url.includes("api.deps.dev")) {
        // primary AND +incompatible retry both fail (404 / 500)
        const status = /incompatible/.test(url) ? 500 : 404
        return {
          ok: false, status,
          json: async () => ({}), text: async () => "", headers: { get: () => null },
        }
      }
      return base(url, init)
    }
    const { findings, degraded } = await scanRegistryLicenses("o", "r", null, fetchImpl)
    expect(findings).toHaveLength(0)
    expect(degraded).toBeNull()
  })

  it("uses injected deps without fetching manifests", async () => {
    let manifestFetches = 0
    const fetchImpl: FetchLike = async (url) => {
      if (url.includes("contents/")) manifestFetches++
      if (url.includes("api.deps.dev")) {
        return {
          ok: true, status: 200,
          json: async () => ({ licenses: ["AGPL-3.0"] }),
          text: async () => "", headers: { get: () => null },
        }
      }
      return { ok: false, status: 404, json: async () => ({}), text: async () => "", headers: { get: () => null } }
    }
    const { findings } = await scanRegistryLicenses("o", "r", null, fetchImpl, [
      { name: "somepkg", version: "1.0.0", ecosystem: "PyPI", source: "requirements.txt" },
    ])
    expect(manifestFetches).toBe(0)
    expect(findings).toHaveLength(1)
    expect(findings[0].ecosystem).toBe("PyPI")
  })

  it("returns nothing when there are no PyPI/Go/Ruby manifests", async () => {
    const fetchImpl = makeFetch({ manifests: {} })
    const { findings, degraded } = await scanRegistryLicenses("o", "r", null, fetchImpl)
    expect(findings).toHaveLength(0)
    expect(degraded).toBeNull()
  })

  it("re-adds the v-prefix when querying deps.dev for Go", async () => {
    // parseGoMod strips the leading v; the deps.dev query must restore it.
    const seen: string[] = []
    const base = makeFetch({
      manifests: { "go.mod": "require example.com/m v1.0.0\n" },
      depsDev: { "go/example.com/m": ["MIT"] },
    })
    const fetchImpl: FetchLike = (url, init) => {
      if (url.includes("api.deps.dev")) seen.push(url)
      return base(url, init)
    }
    await scanRegistryLicenses("o", "r", null, fetchImpl)
    expect(seen.some((u) => /versions\/v1\.0\.0$/.test(u))).toBe(true)
  })
})
