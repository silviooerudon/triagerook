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

  it("flags a hardcoded secret literal in workflow env", () => {
    const wf = "env:\n  API_KEY: sk-live-abcdef123456\n  AWS_SECRET_ACCESS_KEY: 'wJalrXUtnFEMI'\n"
    const ids = scanGithubActions(wf, ".github/workflows/ci.yml").map((f) => f.ruleId)
    expect(ids.filter((id) => id === "gha-hardcoded-secret-env").length).toBe(2)
  })

  it("does NOT flag a secret sourced from ${{ secrets.* }} or empty/indirection", () => {
    const wf =
      "env:\n  API_KEY: \${{ secrets.API_KEY }}\n  TOKEN: \"\"\n  CLIENT_SECRET: $CLIENT_SECRET\n  NODE_ENV: production\n"
    const ids = scanGithubActions(wf, ".github/workflows/ci.yml").map((f) => f.ruleId)
    expect(ids).not.toContain("gha-hardcoded-secret-env")
  })

  it("does NOT flag secret-named CONFIG keys or numeric/boolean values", () => {
    const wf = [
      "env:",
      "  TOKEN_EXPIRY: 3600",
      "  PASSWORD_MIN_LENGTH: 8",
      "  API_KEY_HEADER: X-Api-Key",
      "  SECRET_NAME: my-k8s-secret", // k8s reference, not the value
      "  AWS_ACCESS_KEY_ID: AKIAEXAMPLE", // the ID isn't the secret
      "  SECRET_ROTATION_ENABLED: true",
      "  API_TOKEN_TTL: 300",
    ].join("\n")
    const ids = scanGithubActions(wf, ".github/workflows/ci.yml").map((f) => f.ruleId)
    expect(ids).not.toContain("gha-hardcoded-secret-env")
  })

  it("still flags real hardcoded secrets (incl. SECRET_KEY) despite the config guard", () => {
    const wf =
      "env:\n  DB_PASSWORD: p@ssw0rd123\n  SECRET_KEY: 8f3b9c2a1e7d4f6b\n  JWT_SECRET: 'hunter2hunter2'\n"
    const ids = scanGithubActions(wf, ".github/workflows/ci.yml").map((f) => f.ruleId)
    expect(ids.filter((id) => id === "gha-hardcoded-secret-env").length).toBe(3)
  })
})
