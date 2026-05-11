import { describe, it, expect } from "vitest"
import { applyDepBump, deriveSafeVersion } from "@/lib/fix-engines/dep-bump"
import type { DependencyFinding } from "@/lib/types"

function npmFinding(overrides: Partial<DependencyFinding> = {}): DependencyFinding {
  return {
    package: "postcss",
    version: "8.4.31",
    ecosystem: "npm",
    severity: "moderate",
    title: "postcss vuln",
    ghsa: "GHSA-qx2v-qp2m-jg93",
    vulnerable_versions: "<8.5.10",
    cvss_score: null,
    url: "https://example.com",
    source: "package.json",
    ...overrides,
  }
}

function pyFinding(overrides: Partial<DependencyFinding> = {}): DependencyFinding {
  return {
    package: "django",
    version: "4.2.1",
    ecosystem: "PyPI",
    severity: "high",
    title: "django vuln",
    ghsa: "GHSA-test",
    vulnerable_versions: "<4.2.7",
    cvss_score: null,
    url: "https://example.com",
    source: "requirements.txt",
    ...overrides,
  }
}

describe("deriveSafeVersion", () => {
  it("returns the upper bound for '<X.Y.Z'", () => {
    expect(deriveSafeVersion("<8.5.10")).toBe("8.5.10")
  })

  it("returns the upper bound for '< X.Y.Z' with whitespace", () => {
    expect(deriveSafeVersion("< 8.5.10")).toBe("8.5.10")
  })

  it("returns the upper bound after a '<' clause in a compound range", () => {
    expect(deriveSafeVersion(">=1.0.0 <2.0.0")).toBe("2.0.0")
  })

  it("returns null when range cannot be parsed", () => {
    expect(deriveSafeVersion("anything goes")).toBe(null)
  })

  it("returns null for empty string", () => {
    expect(deriveSafeVersion("")).toBe(null)
  })
})

describe("applyDepBump - npm package.json", () => {
  it("bumps a package present in dependencies", () => {
    const manifest = JSON.stringify(
      {
        name: "demo",
        version: "1.0.0",
        dependencies: { postcss: "8.4.31", react: "19.2.6" },
      },
      null,
      2
    )

    const result = applyDepBump({
      finding: npmFinding(),
      manifestContent: manifest,
      manifestPath: "package.json",
    })

    expect(result.newVersion).toBe("8.5.10")
    expect(result.patches).toHaveLength(1)
    expect(result.patches[0].path).toBe("package.json")
    const patched = JSON.parse(result.patches[0].content)
    expect(patched.dependencies.postcss).toBe("8.5.10")
    expect(patched.dependencies.react).toBe("19.2.6")
  })

  it("bumps a package present in devDependencies", () => {
    const manifest = JSON.stringify(
      {
        name: "demo",
        devDependencies: { postcss: "8.4.31" },
      },
      null,
      2
    )

    const result = applyDepBump({
      finding: npmFinding(),
      manifestContent: manifest,
      manifestPath: "package.json",
    })

    const patched = JSON.parse(result.patches[0].content)
    expect(patched.devDependencies.postcss).toBe("8.5.10")
  })

  it("preserves caret prefix when present in original", () => {
    const manifest = JSON.stringify(
      {
        dependencies: { postcss: "^8.4.31" },
      },
      null,
      2
    )

    const result = applyDepBump({
      finding: npmFinding(),
      manifestContent: manifest,
      manifestPath: "package.json",
    })

    const patched = JSON.parse(result.patches[0].content)
    expect(patched.dependencies.postcss).toBe("^8.5.10")
  })

  it("throws when package is not in any dependency block", () => {
    const manifest = JSON.stringify({ dependencies: { lodash: "4.17.21" } }, null, 2)

    expect(() =>
      applyDepBump({
        finding: npmFinding(),
        manifestContent: manifest,
        manifestPath: "package.json",
      })
    ).toThrow(/postcss/)
  })

  it("throws when vulnerable_versions cannot be parsed", () => {
    const manifest = JSON.stringify({ dependencies: { postcss: "8.4.31" } }, null, 2)

    expect(() =>
      applyDepBump({
        finding: npmFinding({ vulnerable_versions: "weird-range" }),
        manifestContent: manifest,
        manifestPath: "package.json",
      })
    ).toThrow(/safe version/i)
  })
})

describe("applyDepBump - python requirements.txt", () => {
  it("bumps pkg==X to safe version", () => {
    const manifest = "django==4.2.1\nrequests==2.28.0\n"

    const result = applyDepBump({
      finding: pyFinding(),
      manifestContent: manifest,
      manifestPath: "requirements.txt",
    })

    expect(result.newVersion).toBe("4.2.7")
    expect(result.patches[0].content).toBe("django==4.2.7\nrequests==2.28.0\n")
  })

  it("is case-insensitive on package name", () => {
    const manifest = "Django==4.2.1\n"

    const result = applyDepBump({
      finding: pyFinding(),
      manifestContent: manifest,
      manifestPath: "requirements.txt",
    })

    expect(result.patches[0].content).toBe("Django==4.2.7\n")
  })

  it("throws when package is not present in requirements.txt", () => {
    const manifest = "flask==2.0.0\n"

    expect(() =>
      applyDepBump({
        finding: pyFinding(),
        manifestContent: manifest,
        manifestPath: "requirements.txt",
      })
    ).toThrow(/django/i)
  })
})
