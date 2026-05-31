import { describe, it, expect } from "vitest"
import {
  scoreFinding,
  isPublicRouteFile,
  SEVERITY_BASE_POINTS,
  DEV_DEP_MULTIPLIER,
  PUBLIC_ROUTE_MULTIPLIER,
  type AnyFinding,
} from "@/lib/risk"
import type { DependencyFinding, CodeFinding } from "@/lib/types"

function dep(over: Partial<DependencyFinding>): AnyFinding {
  return {
    kind: "dependency",
    data: {
      package: "x",
      version: "1.0.0",
      severity: "high",
      title: "t",
      ghsa: null,
      vulnerable_versions: "<1",
      cvss_score: null,
      url: "u",
      ...over,
    },
  }
}

function code(over: Partial<CodeFinding>): AnyFinding {
  return {
    kind: "code",
    data: {
      ruleId: "r",
      ruleName: "n",
      severity: "high",
      category: "sqli",
      description: "d",
      cwe: null,
      filePath: "src/util.ts",
      lineNumber: 1,
      lineContent: "x",
      likelyTestFixture: false,
      ...over,
    },
  }
}

describe("isPublicRouteFile", () => {
  it("matches route/controller/handler dirs and framework conventions", () => {
    expect(isPublicRouteFile("src/routes/users.ts")).toBe(true)
    expect(isPublicRouteFile("app/controllers/orders_controller.rb")).toBe(true)
    expect(isPublicRouteFile("pages/api/login.ts")).toBe(true)
    expect(isPublicRouteFile("app/api/users/route.ts")).toBe(true)
    expect(isPublicRouteFile("src/users.controller.ts")).toBe(true)
  })
  it("does not match internal/util files", () => {
    expect(isPublicRouteFile("src/util.ts")).toBe(false)
    expect(isPublicRouteFile("lib/helpers/format.js")).toBe(false)
  })
})

describe("scoreFinding — prod vs dev dependency", () => {
  it("discounts a dev dependency vuln", () => {
    const prod = scoreFinding(dep({ isDev: false }))
    const devv = scoreFinding(dep({ isDev: true }))
    expect(prod).toBe(SEVERITY_BASE_POINTS.high)
    expect(devv).toBe(SEVERITY_BASE_POINTS.high * DEV_DEP_MULTIPLIER)
    expect(devv).toBeLessThan(prod)
  })

  it("stacks transitive + dev discounts", () => {
    const both = scoreFinding(dep({ isDev: true, isTransitive: true }))
    expect(both).toBe(SEVERITY_BASE_POINTS.high * 0.5 * DEV_DEP_MULTIPLIER)
  })
})

describe("scoreFinding — public route boost", () => {
  it("boosts a code finding in an exposed route file", () => {
    const internal = scoreFinding(code({ filePath: "src/util.ts" }))
    const route = scoreFinding(code({ filePath: "src/routes/auth.ts" }))
    expect(internal).toBe(SEVERITY_BASE_POINTS.high)
    expect(route).toBe(SEVERITY_BASE_POINTS.high * PUBLIC_ROUTE_MULTIPLIER)
    expect(route).toBeGreaterThan(internal)
  })
})
