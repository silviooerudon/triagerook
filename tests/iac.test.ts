import { describe, it, expect } from "vitest"
import {
  isActionsWorkflowPath,
  isDockerfilePath,
  scanDockerfile,
  scanGithubActions,
} from "@/lib/iac"

describe("isDockerfilePath", () => {
  it("matches root Dockerfile", () => {
    expect(isDockerfilePath("Dockerfile")).toBe(true)
    expect(isDockerfilePath("docker/Dockerfile")).toBe(true)
    expect(isDockerfilePath("Dockerfile.prod")).toBe(true)
    expect(isDockerfilePath("app.dockerfile")).toBe(true)
  })

  it("rejects non-Dockerfile paths", () => {
    expect(isDockerfilePath("docker-compose.yml")).toBe(false)
    expect(isDockerfilePath("README.md")).toBe(false)
    expect(isDockerfilePath("src/server.ts")).toBe(false)
  })
})

describe("isActionsWorkflowPath", () => {
  it("matches workflow YAML in .github/workflows/", () => {
    expect(isActionsWorkflowPath(".github/workflows/ci.yml")).toBe(true)
    expect(isActionsWorkflowPath(".github/workflows/release.yaml")).toBe(true)
  })

  it("rejects paths outside .github/workflows or wrong extensions", () => {
    expect(isActionsWorkflowPath(".github/ci.yml")).toBe(false)
    expect(isActionsWorkflowPath("workflows/ci.yml")).toBe(false)
    expect(isActionsWorkflowPath(".github/workflows/ci.txt")).toBe(false)
    expect(isActionsWorkflowPath(".github/workflows/nested/ci.yml")).toBe(false)
  })
})

describe("scanDockerfile", () => {
  it("flags missing USER directive", () => {
    const dockerfile = `FROM node:20\nWORKDIR /app\nCOPY . .\nCMD ["node", "server.js"]`
    const findings = scanDockerfile(dockerfile, "Dockerfile")
    expect(findings.some((f) => f.ruleId === "dockerfile-user-root")).toBe(true)
  })

  it("does NOT flag missing-USER when a non-root USER is present", () => {
    const dockerfile = `FROM node:20\nUSER node\nCMD ["node", "server.js"]`
    const findings = scanDockerfile(dockerfile, "Dockerfile")
    expect(findings.some((f) => f.ruleId === "dockerfile-user-root")).toBe(false)
  })

  it("flags explicit USER root", () => {
    const dockerfile = `FROM node:20\nUSER root\nCMD ["node", "server.js"]`
    const findings = scanDockerfile(dockerfile, "Dockerfile")
    expect(findings.some((f) => f.ruleId === "dockerfile-user-root-explicit")).toBe(true)
  })

  it("flags secrets baked into ENV", () => {
    const dockerfile = `FROM node:20\nENV API_KEY=hardcoded123\nUSER node`
    const findings = scanDockerfile(dockerfile, "Dockerfile")
    expect(findings.some((f) => f.ruleId === "dockerfile-secret-in-env")).toBe(true)
  })

  it("flags ADD with remote URL", () => {
    const dockerfile = `FROM node:20\nADD https://example.com/installer.sh /tmp/\nUSER node`
    const findings = scanDockerfile(dockerfile, "Dockerfile")
    expect(findings.some((f) => f.ruleId === "dockerfile-add-url")).toBe(true)
  })

  it("each finding carries category, severity, and filePath", () => {
    const dockerfile = `FROM node:20\nUSER root`
    const findings = scanDockerfile(dockerfile, "Dockerfile.prod")
    expect(findings.length).toBeGreaterThan(0)
    for (const f of findings) {
      expect(f.category).toBe("dockerfile")
      expect(f.severity).toMatch(/critical|high|medium|low/)
      expect(f.filePath).toBe("Dockerfile.prod")
      expect(f.remediation.length).toBeGreaterThan(0)
    }
  })
})

describe("scanGithubActions", () => {
  it("flags pull_request_target checking out PR head ref", () => {
    const workflow = `
on:
  pull_request_target:
    branches: [main]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
`
    const findings = scanGithubActions(workflow, ".github/workflows/ci.yml")
    expect(findings.some((f) => f.ruleId === "gha-pull-request-target-checkout-head")).toBe(true)
  })

  it("does NOT flag plain pull_request trigger with head checkout", () => {
    const workflow = `
on:
  pull_request:
    branches: [main]
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
`
    const findings = scanGithubActions(workflow, ".github/workflows/ci.yml")
    expect(findings.some((f) => f.ruleId === "gha-pull-request-target-checkout-head")).toBe(false)
  })
})
