import { describe, it, expect } from "vitest"
import {
  scanPriorityTier,
  prioritizeFilesForScan,
} from "@/lib/scan-priority"

describe("scanPriorityTier", () => {
  it("classifies common source dirs as tier 1", () => {
    expect(scanPriorityTier("src/auth/login.ts")).toBe(1)
    expect(scanPriorityTier("lib/risk.ts")).toBe(1)
    expect(scanPriorityTier("app/dashboard/page.tsx")).toBe(1)
    expect(scanPriorityTier("api/users/[id].ts")).toBe(1)
    expect(scanPriorityTier("services/payment.ts")).toBe(1)
    expect(scanPriorityTier("packages/auth/src/index.ts")).toBe(1)
  })

  it("classifies root-level files as tier 2", () => {
    expect(scanPriorityTier("Dockerfile")).toBe(2)
    expect(scanPriorityTier("package.json")).toBe(2)
    expect(scanPriorityTier("next.config.ts")).toBe(2)
    expect(scanPriorityTier(".env.example")).toBe(2)
  })

  it("classifies GitHub Actions workflows as tier 2", () => {
    expect(scanPriorityTier(".github/workflows/ci.yml")).toBe(2)
    expect(scanPriorityTier(".github/actions/setup/action.yml")).toBe(2)
  })

  it("classifies unknown mid-path files as tier 3", () => {
    expect(scanPriorityTier("scripts/deploy.sh")).toBe(3)
    expect(scanPriorityTier("docker/Dockerfile.dev")).toBe(3)
    expect(scanPriorityTier("misc/foo.ts")).toBe(3)
  })

  it("classifies test / fixture / example / docs as tier 4 (low priority)", () => {
    expect(scanPriorityTier("test/foo.ts")).toBe(4)
    expect(scanPriorityTier("tests/integration/auth.test.ts")).toBe(4)
    expect(scanPriorityTier("__tests__/util.spec.ts")).toBe(4)
    expect(scanPriorityTier("specs/auth.spec.ts")).toBe(4)
    expect(scanPriorityTier("fixtures/sample.json")).toBe(4)
    expect(scanPriorityTier("examples/quickstart.ts")).toBe(4)
    expect(scanPriorityTier("e2e/login.cy.ts")).toBe(4)
    expect(scanPriorityTier("cypress/integration/foo.ts")).toBe(4)
    expect(scanPriorityTier("docs/api.md")).toBe(4)
    expect(scanPriorityTier("foo.test.ts")).toBe(4)
    expect(scanPriorityTier("foo.spec.js")).toBe(4)
    expect(scanPriorityTier("foo_test.go")).toBe(4)
    expect(scanPriorityTier("foo_spec.rb")).toBe(4)
  })

  it("treats a test file nested inside a source dir as tier 4 (not tier 1)", () => {
    // A test should stay deprioritised even when its path includes a
    // tier-1 prefix. Otherwise `src/auth/__tests__/login.test.ts`
    // would compete with real source files for budget.
    expect(scanPriorityTier("src/auth/__tests__/login.test.ts")).toBe(4)
    expect(scanPriorityTier("lib/foo/test/helper.ts")).toBe(4)
  })

  it("is case-insensitive for path components", () => {
    expect(scanPriorityTier("SRC/Auth.ts")).toBe(1)
    expect(scanPriorityTier("Tests/Auth.test.ts")).toBe(4)
  })
})

describe("prioritizeFilesForScan", () => {
  it("orders tier 1 files before tier 4 files", () => {
    const input = [
      { path: "tests/auth.test.ts" },
      { path: "src/auth.ts" },
      { path: "examples/demo.ts" },
      { path: "lib/risk.ts" },
    ]
    const sorted = prioritizeFilesForScan(input).map((f) => f.path)
    expect(sorted.indexOf("src/auth.ts")).toBeLessThan(sorted.indexOf("tests/auth.test.ts"))
    expect(sorted.indexOf("lib/risk.ts")).toBeLessThan(sorted.indexOf("examples/demo.ts"))
  })

  it("preserves the original order within a tier (stable sort)", () => {
    const input = [
      { path: "src/a.ts" },
      { path: "src/b.ts" },
      { path: "src/c.ts" },
    ]
    const sorted = prioritizeFilesForScan(input).map((f) => f.path)
    expect(sorted).toEqual(["src/a.ts", "src/b.ts", "src/c.ts"])
  })

  it("returns a new array; does not mutate the input", () => {
    const input = [{ path: "tests/x.ts" }, { path: "src/y.ts" }]
    const inputBefore = [...input]
    const out = prioritizeFilesForScan(input)
    expect(input).toEqual(inputBefore)
    expect(out).not.toBe(input)
  })

  it("returns every input file (no drops)", () => {
    const input = Array.from({ length: 50 }, (_, i) => ({ path: `src/file${i}.ts` }))
    const out = prioritizeFilesForScan(input)
    expect(out.length).toBe(input.length)
    expect(new Set(out.map((f) => f.path))).toEqual(new Set(input.map((f) => f.path)))
  })

  it("places tier 2 root files between tier 1 source and tier 3/4", () => {
    const input = [
      { path: "tests/x.test.ts" },           // 4
      { path: "scripts/deploy.sh" },          // 3
      { path: "package.json" },               // 2
      { path: "src/foo.ts" },                 // 1
    ]
    const order = prioritizeFilesForScan(input).map((f) => f.path)
    expect(order).toEqual([
      "src/foo.ts",
      "package.json",
      "scripts/deploy.sh",
      "tests/x.test.ts",
    ])
  })

  it("realistic monorepo budget scenario — tests fall off the end", () => {
    // Simulate 1500 files where ~800 are source, ~200 are root/config,
    // ~500 are tests. After prioritization, the first 1000 should
    // contain all source + all config + 0 tests.
    const sources = Array.from({ length: 800 }, (_, i) => ({
      path: `src/module${i}/index.ts`,
    }))
    const tests = Array.from({ length: 500 }, (_, i) => ({
      path: `tests/test${i}.test.ts`,
    }))
    const configs = Array.from({ length: 200 }, (_, i) => ({
      path: i === 0 ? "package.json" : `.github/workflows/job${i}.yml`,
    }))
    const all = [...tests, ...configs, ...sources]
    const sorted = prioritizeFilesForScan(all)
    const firstThousand = sorted.slice(0, 1000)
    const testsInFirstThousand = firstThousand.filter((f) =>
      f.path.startsWith("tests/"),
    ).length
    expect(testsInFirstThousand).toBe(0)
    expect(firstThousand.length).toBe(1000)
  })
})
