import { describe, it, expect } from "vitest"
import { classifyLicense, scanNpmLicenses } from "@/lib/licenses"

describe("classifyLicense", () => {
  it("returns null for permissive licenses", () => {
    for (const lic of ["MIT", "ISC", "Apache-2.0", "BSD-3-Clause", "0BSD", "Unlicense", "CC0-1.0"]) {
      expect(classifyLicense(lic), lic).toBeNull()
    }
  })

  it("flags strong copyleft (GPL/AGPL)", () => {
    expect(classifyLicense("GPL-3.0")?.risk).toBe("copyleft-strong")
    expect(classifyLicense("GPL-2.0-only")?.risk).toBe("copyleft-strong")
    expect(classifyLicense("AGPL-3.0")?.risk).toBe("copyleft-strong")
    expect(classifyLicense("AGPL-3.0")?.severity).toBe("high")
  })

  it("flags weak copyleft (LGPL/MPL/EPL) as medium", () => {
    expect(classifyLicense("LGPL-3.0")?.risk).toBe("copyleft-weak")
    expect(classifyLicense("MPL-2.0")?.risk).toBe("copyleft-weak")
    expect(classifyLicense("EPL-2.0")?.risk).toBe("copyleft-weak")
    expect(classifyLicense("LGPL-3.0")?.severity).toBe("medium")
  })

  it("does NOT classify LGPL as strong GPL (negative lookbehind)", () => {
    expect(classifyLicense("LGPL-2.1")?.risk).toBe("copyleft-weak")
  })

  it("treats an absent/empty license as UNKNOWN (null), not 'missing'", () => {
    // classifyLicense owns the unknown-vs-missing distinction so the npm and
    // deps.dev paths can't diverge: absent/empty/whitespace metadata is not
    // evidence of "no license" and must produce no finding.
    expect(classifyLicense(null)).toBeNull()
    expect(classifyLicense(undefined)).toBeNull()
    expect(classifyLicense("")).toBeNull()
    expect(classifyLicense("   ")).toBeNull()
  })

  it("flags proprietary / UNLICENSED as non-standard", () => {
    expect(classifyLicense("UNLICENSED")?.risk).toBe("non-standard")
    expect(classifyLicense("SEE LICENSE IN LICENSE")?.risk).toBe("non-standard")
  })

  it("treats an OR expression with a permissive choice as acceptable", () => {
    expect(classifyLicense("(MIT OR GPL-3.0)")).toBeNull()
    expect(classifyLicense("Apache-2.0 OR LGPL-2.1")).toBeNull()
  })

  it("still flags an AND expression containing copyleft", () => {
    // AND means you must satisfy both — the copyleft obligation stands.
    expect(classifyLicense("MIT AND GPL-3.0")?.risk).toBe("copyleft-strong")
  })
})

function lockfile(packages: Record<string, unknown>): string {
  return JSON.stringify({ lockfileVersion: 3, packages })
}

describe("scanNpmLicenses", () => {
  it("flags a production GPL dependency from the lockfile", () => {
    const lock = lockfile({
      "": { name: "root" },
      "node_modules/gpl-lib": { version: "1.0.0", license: "GPL-3.0" },
      "node_modules/mit-lib": { version: "2.0.0", license: "MIT" },
    })
    const findings = scanNpmLicenses(lock)
    expect(findings).toHaveLength(1)
    expect(findings[0].package).toBe("gpl-lib")
    expect(findings[0].risk).toBe("copyleft-strong")
    expect(findings[0].ecosystem).toBe("npm")
    expect(findings[0].source).toBe("package-lock.json")
  })

  it("skips dev-only dependencies", () => {
    const lock = lockfile({
      "": { name: "root" },
      "node_modules/gpl-devtool": { version: "1.0.0", license: "GPL-3.0", dev: true },
    })
    expect(scanNpmLicenses(lock)).toHaveLength(0)
  })

  it("marks nested deps as transitive", () => {
    const lock = lockfile({
      "": { name: "root" },
      "node_modules/a/node_modules/agpl-lib": { version: "1.0.0", license: "AGPL-3.0" },
    })
    const [f] = scanNpmLicenses(lock)
    expect(f.isTransitive).toBe(true)
  })

  it("does NOT flag a dependency whose lockfile entry omits the license field", () => {
    // Regression: npm lockfiles routinely omit `license` even for MIT/BSD
    // packages (accepts, ansi-regex, normalize-path on OWASP/NodeGoat all
    // came back null → 346 false "missing" findings). Absent-in-lockfile is
    // unknown metadata, not "no license", so we skip it — consistent with the
    // deps.dev path treating an empty license list as unknown.
    const lock = lockfile({
      "": { name: "root" },
      "node_modules/no-license": { version: "1.0.0" },
    })
    expect(scanNpmLicenses(lock)).toHaveLength(0)
  })

  it("does NOT flag a dependency with an empty-string license field", () => {
    // normalizeLockfileLicense returns "" (not null) for `license: ""`; the
    // unknown-handling must live in classifyLicense so this is skipped too.
    const lock = lockfile({
      "": { name: "root" },
      "node_modules/empty-lic": { version: "1.0.0", license: "" },
    })
    expect(scanNpmLicenses(lock)).toHaveLength(0)
  })

  it("still flags an explicitly proprietary (UNLICENSED) dependency", () => {
    const lock = lockfile({
      "": { name: "root" },
      "node_modules/closed": { version: "1.0.0", license: "UNLICENSED" },
    })
    expect(scanNpmLicenses(lock)[0]?.risk).toBe("non-standard")
  })

  it("normalises an array license field", () => {
    const lock = lockfile({
      "": { name: "root" },
      "node_modules/old-lib": { version: "1.0.0", license: ["MIT", "GPL-3.0"] },
    })
    // ["MIT","GPL-3.0"] joins to "MIT OR GPL-3.0" → permissive escape → no finding
    expect(scanNpmLicenses(lock)).toHaveLength(0)
  })

  it("normalises an object license field ({ type })", () => {
    const lock = lockfile({
      "": { name: "root" },
      "node_modules/obj-lib": { version: "1.0.0", license: { type: "GPL-2.0" } },
    })
    expect(scanNpmLicenses(lock)[0]?.risk).toBe("copyleft-strong")
  })

  it("dedupes the same package@version appearing twice", () => {
    const lock = lockfile({
      "": { name: "root" },
      "node_modules/gpl-lib": { version: "1.0.0", license: "GPL-3.0" },
      "node_modules/x/node_modules/gpl-lib": { version: "1.0.0", license: "GPL-3.0" },
    })
    expect(scanNpmLicenses(lock)).toHaveLength(1)
  })

  it("returns [] for malformed JSON or missing packages map", () => {
    expect(scanNpmLicenses("not json")).toHaveLength(0)
    expect(scanNpmLicenses(JSON.stringify({ lockfileVersion: 1 }))).toHaveLength(0)
  })
})
