import { describe, it, expect } from "vitest"
import { parseTrivySarif, scanContainerVulns, type FetchLike } from "@/lib/trivy-sarif"

function sarif(results: unknown[], rules: unknown[] = []) {
  return JSON.stringify({
    version: "2.1.0",
    runs: [{ tool: { driver: { name: "Trivy", rules } }, results }],
  })
}

describe("parseTrivySarif", () => {
  it("maps an OS-package vulnerability to a Container DependencyFinding", () => {
    const doc = sarif(
      [
        {
          ruleId: "CVE-2023-0464",
          level: "error",
          message: {
            text: "Package: openssl\nInstalled Version: 1.1.1k\nVulnerability CVE-2023-0464\nSeverity: HIGH\nFixed Version: 1.1.1t",
          },
        },
      ],
      [
        {
          id: "CVE-2023-0464",
          name: "OsPackageVulnerability",
          shortDescription: { text: "openssl: denial of service" },
          helpUri: "https://avd.aquasec.com/nvd/cve-2023-0464",
          properties: { "security-severity": "7.5", tags: ["vulnerability"] },
        },
      ],
    )
    const out = parseTrivySarif(doc)
    expect(out).toHaveLength(1)
    expect(out[0]).toMatchObject({
      package: "openssl",
      version: "1.1.1k",
      ecosystem: "Container",
      severity: "high",
      vulnerable_versions: "< 1.1.1t",
      cvss_score: 7.5,
      url: "https://avd.aquasec.com/nvd/cve-2023-0464",
      source: "trivy-sarif",
      title: "openssl: denial of service",
    })
  })

  it("derives severity from CVSS when no Severity line is present", () => {
    const doc = sarif(
      [{ ruleId: "CVE-2024-1", message: { text: "Package: zlib\nInstalled Version: 1.2" } }],
      [{ id: "CVE-2024-1", properties: { "security-severity": "9.8", tags: ["vulnerability"] } }],
    )
    expect(parseTrivySarif(doc)[0].severity).toBe("critical")
  })

  it("skips misconfiguration results (non-vulnerability rule ids/tags)", () => {
    const doc = sarif(
      [{ ruleId: "DS002", level: "warning", message: { text: "Image user should not be root" } }],
      [{ id: "DS002", properties: { tags: ["misconfiguration"] } }],
    )
    expect(parseTrivySarif(doc)).toEqual([])
  })

  it("returns [] on malformed JSON or non-SARIF", () => {
    expect(parseTrivySarif("{not json")).toEqual([])
    expect(parseTrivySarif(JSON.stringify({ foo: 1 }))).toEqual([])
  })

  it("falls back to SARIF level when neither Severity nor CVSS exist", () => {
    const doc = sarif([
      { ruleId: "CVE-2024-2", level: "error", message: { text: "Package: bash\nInstalled Version: 5.0" } },
    ])
    expect(parseTrivySarif(doc)[0].severity).toBe("high")
  })
})

// Fake GitHub Contents fetch: serve a SARIF for one path, 404 for the rest.
function makeFetch(files: Record<string, string>): FetchLike {
  return async (url: string) => {
    const m = url.match(/contents\/(.+)$/)
    const path = m ? decodeURIComponent(m[1]) : ""
    if (files[path] !== undefined) {
      return { ok: true, status: 200, text: async () => files[path], headers: { get: () => null } }
    }
    return { ok: false, status: 404, text: async () => "", headers: { get: () => null } }
  }
}

describe("scanContainerVulns", () => {
  const goodSarif = JSON.stringify({
    runs: [
      {
        tool: { driver: { name: "Trivy", rules: [{ id: "CVE-1", properties: { tags: ["vulnerability"] } }] } },
        results: [{ ruleId: "CVE-1", message: { text: "Package: libc\nInstalled Version: 2.31\nSeverity: CRITICAL" } }],
      },
    ],
  })

  it("ingests the first conventional SARIF path found", async () => {
    const { findings, degraded } = await scanContainerVulns(
      "o", "r", null, makeFetch({ "trivy-results.sarif": goodSarif }),
    )
    expect(degraded).toBeNull()
    expect(findings).toHaveLength(1)
    expect(findings[0]).toMatchObject({ package: "libc", severity: "critical", ecosystem: "Container" })
  })

  it("returns empty (not degraded) when no SARIF is committed", async () => {
    const { findings, degraded } = await scanContainerVulns("o", "r", null, makeFetch({}))
    expect(findings).toEqual([])
    expect(degraded).toBeNull()
  })

  it("degrades when the committed file isn't valid JSON", async () => {
    const { findings, degraded } = await scanContainerVulns(
      "o", "r", null, makeFetch({ "trivy.sarif": "<<not json>>" }),
    )
    expect(findings).toEqual([])
    expect(degraded?.detector).toBe("container-scan")
  })

  it("does not degrade on a valid-but-clean SARIF (no vulns)", async () => {
    const clean = JSON.stringify({ runs: [{ tool: { driver: { name: "Trivy" } }, results: [] }] })
    const { findings, degraded } = await scanContainerVulns(
      "o", "r", null, makeFetch({ "trivy-results.sarif": clean }),
    )
    expect(findings).toEqual([])
    expect(degraded).toBeNull()
  })
})
