import { describe, it, expect } from "vitest"
import { findingSupportsFix, runFixEngine } from "@/lib/fix-engines"
import { dockerfileBumpSupported } from "@/lib/fix-engines/dockerfile-baseimage"
import type { IaCFinding } from "@/lib/types"
import type { AnyFinding } from "@/lib/risk"

function iac(over: Partial<IaCFinding>): AnyFinding {
  return {
    kind: "iac",
    data: {
      ruleId: "dockerfile-base-image-eol",
      ruleName: "End-of-life base image",
      severity: "high",
      category: "dockerfile",
      description: "d",
      filePath: "Dockerfile",
      lineNumber: 1,
      lineContent: "FROM node:16-alpine",
      remediation: "r",
      ...over,
    },
  }
}

describe("dockerfileBumpSupported", () => {
  it("supports numeric-leading tags on known images, rejects codenames/centos", () => {
    expect(dockerfileBumpSupported("FROM node:16-alpine")).toBe(true)
    expect(dockerfileBumpSupported("FROM python:3.7-slim")).toBe(true)
    expect(dockerfileBumpSupported("FROM debian:stretch")).toBe(false)
    expect(dockerfileBumpSupported("FROM centos:7")).toBe(false)
    expect(dockerfileBumpSupported("FROM node")).toBe(false)
  })
})

describe("dockerfile-baseimage-bump engine", () => {
  it("is offered for the EOL finding and bumps the tag preserving the variant", () => {
    const f = iac({ lineContent: "FROM node:16-alpine" })
    expect(findingSupportsFix(f)).toBe("dockerfile-baseimage-bump")
    const r = runFixEngine({
      finding: f,
      fileContent: "FROM node:16-alpine\nRUN echo hi\n",
      envExampleContent: null,
    })
    expect(r.kind).toBe("dockerfile-baseimage-bump")
    expect(r.patches[0].content).toContain("FROM node:22-alpine")
    expect(r.patches[0].content).not.toContain("node:16")
  })

  it("bumps python preserving the .minor and -slim suffix", () => {
    const r = runFixEngine({
      finding: iac({ lineContent: "FROM python:3.7-slim", lineNumber: 1 }),
      fileContent: "FROM python:3.7-slim\n",
      envExampleContent: null,
    })
    expect(r.patches[0].content.trim()).toBe("FROM python:3.12-slim")
  })

  it("relocates via lineContent when the line number drifted", () => {
    const r = runFixEngine({
      finding: iac({ lineContent: "FROM node:16", lineNumber: 99 }),
      fileContent: "# header\nFROM node:16\n",
      envExampleContent: null,
    })
    expect(r.patches[0].content).toContain("FROM node:22")
  })

  it("is not offered for a test-fixture finding", () => {
    expect(findingSupportsFix(iac({ likelyTestFixture: true }))).toBeNull()
  })
})

describe("gha-permissions-fix engine", () => {
  const ghaFinding = (over: Partial<IaCFinding> = {}): AnyFinding =>
    iac({
      ruleId: "gha-permissions-write-all",
      ruleName: "Workflow grants write-all permissions",
      category: "github-actions",
      filePath: ".github/workflows/ci.yml",
      lineNumber: 2,
      lineContent: "permissions: write-all",
      ...over,
    })

  it("replaces write-all with least-privilege contents: read, preserving indent", () => {
    const f = ghaFinding()
    expect(findingSupportsFix(f)).toBe("gha-permissions-fix")
    const r = runFixEngine({
      finding: f,
      fileContent: "on: push\npermissions: write-all\njobs: {}\n",
      envExampleContent: null,
    })
    expect(r.patches[0].content).toContain("permissions:\n  contents: read")
    expect(r.patches[0].content).not.toContain("write-all")
  })

  it("preserves job-level indentation", () => {
    const r = runFixEngine({
      finding: ghaFinding({ lineNumber: 2 }),
      fileContent: "jobs:\n    permissions: write-all\n",
      envExampleContent: null,
    })
    expect(r.patches[0].content).toContain("    permissions:\n      contents: read")
  })
})
