import { describe, it, expect } from "vitest"
import { scanHelmValues, isHelmValuesPath } from "@/lib/iac-helm"

const ids = (content: string, path = "values.yaml") =>
  scanHelmValues(content, path).map((f) => f.ruleId)

describe("isHelmValuesPath", () => {
  it("matches values files anywhere in the tree", () => {
    expect(isHelmValuesPath("values.yaml")).toBe(true)
    expect(isHelmValuesPath("charts/app/values.yaml")).toBe(true)
    expect(isHelmValuesPath("deploy/values-prod.yaml")).toBe(true)
    expect(isHelmValuesPath("values.staging.yml")).toBe(true)
  })
  it("does not match non-values yaml", () => {
    expect(isHelmValuesPath("config.yaml")).toBe(false)
    expect(isHelmValuesPath("templates/deployment.yaml")).toBe(false)
    expect(isHelmValuesPath("myvalues.yaml")).toBe(false)
  })
})

describe("scanHelmValues", () => {
  it("flags privileged, run-as-root, host namespaces, priv-esc", () => {
    expect(ids("securityContext:\n  privileged: true")).toContain("helm-privileged")
    expect(ids("securityContext:\n  runAsNonRoot: false")).toContain("helm-run-as-root")
    expect(ids("securityContext:\n  runAsUser: 0")).toContain("helm-run-as-root")
    expect(ids("pod:\n  hostNetwork: true")).toContain("helm-host-namespace")
    expect(ids("pod:\n  hostPID: true")).toContain("helm-host-namespace")
    expect(ids("securityContext:\n  allowPrivilegeEscalation: true")).toContain(
      "helm-allow-privilege-escalation",
    )
  })

  it("flags a mutable/empty image tag", () => {
    expect(ids("image:\n  repository: nginx\n  tag: latest")).toContain("helm-image-latest-tag")
    expect(ids('image:\n  tag: ""')).toContain("helm-image-latest-tag")
  })

  it("does NOT flag secure defaults", () => {
    const secure =
      "securityContext:\n  privileged: false\n  runAsNonRoot: true\n  runAsUser: 1000\n  allowPrivilegeEscalation: false\nimage:\n  tag: \"1.27.1\"\npod:\n  hostNetwork: false"
    expect(scanHelmValues(secure, "values.yaml")).toEqual([])
  })

  it("carries the helm category and a line number", () => {
    const out = scanHelmValues("a: 1\nprivileged: true", "values.yaml")
    expect(out[0]).toMatchObject({ category: "helm", lineNumber: 2 })
  })
})
