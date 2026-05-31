import { describe, it, expect } from "vitest"
import { runOsvScan, type OsvParsedDep } from "@/lib/osv"

// A fake fetch serving OSV's batch + vuln-details endpoints.
function makeFetch(opts: {
  // key: `${name}@${version}` → vuln ids that the batch query returns
  batch: Record<string, string[]>
  // key: vuln id → details payload (or "error" for a non-ok response)
  details: Record<string, Record<string, unknown> | "error">
  batchStatus?: number
}): typeof fetch {
  return (async (url: string, init?: RequestInit) => {
    const ok = (status: number, body: unknown) => ({
      ok: status >= 200 && status < 300,
      status,
      json: async () => body,
      text: async () => JSON.stringify(body),
      headers: { get: () => null },
    })
    if (url.includes("querybatch")) {
      if (opts.batchStatus && opts.batchStatus >= 400) return ok(opts.batchStatus, {})
      const body = JSON.parse(String(init?.body)) as {
        queries: { package: { name: string }; version: string }[]
      }
      const results = body.queries.map((q) => {
        const ids = opts.batch[`${q.package.name}@${q.version}`] ?? []
        return ids.length ? { vulns: ids.map((id) => ({ id })) } : {}
      })
      return ok(200, { results })
    }
    const m = url.match(/vulns\/(.+)$/)
    if (m) {
      const entry = opts.details[decodeURIComponent(m[1])]
      if (!entry || entry === "error") return ok(500, {})
      return ok(200, entry)
    }
    return ok(404, {})
  }) as unknown as typeof fetch
}

const DEPS: OsvParsedDep[] = [
  { name: "org.apache.logging.log4j:log4j-core", version: "2.14.1", source: "pom.xml" },
  { name: "com.google.guava:guava", version: "30.0-jre", source: "pom.xml" },
]

describe("runOsvScan", () => {
  it("maps a vulnerable Maven package to a DependencyFinding", async () => {
    const fetchImpl = makeFetch({
      batch: { "org.apache.logging.log4j:log4j-core@2.14.1": ["GHSA-jfh8-c2jp-5v3q"] },
      details: {
        "GHSA-jfh8-c2jp-5v3q": {
          id: "GHSA-jfh8-c2jp-5v3q",
          summary: "Log4Shell RCE",
          severity: [{ type: "CVSS_V3", score: "10.0" }],
          affected: [
            {
              package: { name: "org.apache.logging.log4j:log4j-core", ecosystem: "Maven" },
              ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "2.15.0" }] }],
            },
          ],
        },
      },
    })
    const { findings, degraded, deduped } = await runOsvScan(DEPS, {
      osvEcosystem: "Maven",
      displayEcosystem: "Maven",
      scanLabel: "Java",
      fetchImpl,
    })
    expect(degraded).toBeNull()
    expect(deduped).toHaveLength(2)
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({
      package: "org.apache.logging.log4j:log4j-core",
      version: "2.14.1",
      ecosystem: "Maven",
      severity: "critical",
      ghsa: "GHSA-jfh8-c2jp-5v3q",
      vulnerable_versions: "< 2.15.0",
      source: "pom.xml",
    })
  })

  it("returns no findings (not degraded) when nothing is vulnerable", async () => {
    const fetchImpl = makeFetch({ batch: {}, details: {} })
    const { findings, degraded } = await runOsvScan(DEPS, {
      osvEcosystem: "Maven",
      displayEcosystem: "Maven",
      scanLabel: "Java",
      fetchImpl,
    })
    expect(findings).toHaveLength(0)
    expect(degraded).toBeNull()
  })

  it("degrades (not throws) when the batch endpoint errors", async () => {
    const fetchImpl = makeFetch({ batch: {}, details: {}, batchStatus: 503 })
    const { findings, degraded } = await runOsvScan(DEPS, {
      osvEcosystem: "Packagist",
      displayEcosystem: "Composer",
      scanLabel: "PHP",
      fetchImpl,
    })
    expect(findings).toHaveLength(0)
    expect(degraded?.detector).toBe("osv")
    expect(degraded?.reason).toContain("PHP")
  })

  it("dedupes (name, version) before querying", async () => {
    const dupes: OsvParsedDep[] = [
      { name: "a/b", version: "1.0.0", source: "composer.lock" },
      { name: "a/b", version: "1.0.0", source: "composer.lock" },
    ]
    const { deduped } = await runOsvScan(dupes, {
      osvEcosystem: "Packagist",
      displayEcosystem: "Composer",
      scanLabel: "PHP",
      fetchImpl: makeFetch({ batch: {}, details: {} }),
    })
    expect(deduped).toHaveLength(1)
  })
})
