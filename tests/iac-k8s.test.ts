import { describe, it, expect } from "vitest"
import {
  looksLikeKubernetesManifest,
  scanKubernetes,
  K8S_RULES,
} from "@/lib/iac-k8s"

const POD_HEADER = `apiVersion: v1\nkind: Pod\nmetadata:\n  name: demo\nspec:\n  containers:\n    - name: app\n      image: nginx:1.27`

describe("looksLikeKubernetesManifest", () => {
  it("accepts a manifest with apiVersion + kind", () => {
    expect(looksLikeKubernetesManifest(POD_HEADER)).toBe(true)
  })

  it("rejects arbitrary YAML", () => {
    expect(looksLikeKubernetesManifest("foo: bar\nbaz: 1")).toBe(false)
    expect(looksLikeKubernetesManifest("name: build\non: push")).toBe(false)
  })
})

describe("scanKubernetes — guards", () => {
  it("returns nothing for non-manifest YAML even if it has scary words", () => {
    const yaml = `name: ci\nprivileged: true\nhostNetwork: true`
    expect(scanKubernetes(yaml, "ci.yml")).toHaveLength(0)
  })
})

describe("scanKubernetes — securityContext rules", () => {
  it("flags a privileged container", () => {
    const m = `${POD_HEADER}\n      securityContext:\n        privileged: true`
    expect(scanKubernetes(m, "pod.yaml").some((f) => f.ruleId === "k8s-privileged-container")).toBe(true)
  })

  it("flags host namespaces", () => {
    const m = `${POD_HEADER}\n  hostNetwork: true\n  hostPID: true`
    const ids = scanKubernetes(m, "pod.yaml").map((f) => f.ruleId)
    expect(ids.filter((id) => id === "k8s-host-namespace")).toHaveLength(2)
  })

  it("flags allowPrivilegeEscalation: true", () => {
    const m = `${POD_HEADER}\n      securityContext:\n        allowPrivilegeEscalation: true`
    expect(
      scanKubernetes(m, "pod.yaml").some((f) => f.ruleId === "k8s-allow-privilege-escalation"),
    ).toBe(true)
  })

  it("flags runAsUser: 0 and runAsNonRoot: false", () => {
    const m1 = `${POD_HEADER}\n      securityContext:\n        runAsUser: 0`
    const m2 = `${POD_HEADER}\n      securityContext:\n        runAsNonRoot: false`
    expect(scanKubernetes(m1, "pod.yaml").some((f) => f.ruleId === "k8s-run-as-root")).toBe(true)
    expect(scanKubernetes(m2, "pod.yaml").some((f) => f.ruleId === "k8s-run-as-root")).toBe(true)
  })

  it("does not flag a hardened securityContext", () => {
    const m = `${POD_HEADER}\n      securityContext:\n        runAsNonRoot: true\n        runAsUser: 10001\n        allowPrivilegeEscalation: false\n        privileged: false`
    expect(scanKubernetes(m, "pod.yaml")).toHaveLength(0)
  })
})

describe("scanKubernetes — image tags", () => {
  it("flags :latest", () => {
    const m = `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - image: nginx:latest`
    expect(scanKubernetes(m, "pod.yaml").some((f) => f.ruleId === "k8s-image-latest")).toBe(true)
  })

  it("flags an untagged image", () => {
    const m = `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - image: nginx`
    expect(scanKubernetes(m, "pod.yaml").some((f) => f.ruleId === "k8s-image-latest")).toBe(true)
  })

  it("does not flag a version-tagged image", () => {
    const m = `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - image: nginx:1.27.1`
    expect(scanKubernetes(m, "pod.yaml").some((f) => f.ruleId === "k8s-image-latest")).toBe(false)
  })

  it("does not flag a digest-pinned image", () => {
    const m = `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - image: nginx@sha256:${"a".repeat(64)}`
    expect(scanKubernetes(m, "pod.yaml").some((f) => f.ruleId === "k8s-image-latest")).toBe(false)
  })

  it("does not mistake a registry port for a missing tag", () => {
    const m = `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - image: registry.local:5000/app:2.1.0`
    expect(scanKubernetes(m, "pod.yaml").some((f) => f.ruleId === "k8s-image-latest")).toBe(false)
  })
})

describe("scanKubernetes — capabilities", () => {
  it("flags a dangerous capability in block form", () => {
    const m = `${POD_HEADER}\n      securityContext:\n        capabilities:\n          add:\n            - SYS_ADMIN\n            - NET_BIND_SERVICE`
    const caps = scanKubernetes(m, "pod.yaml").filter((f) => f.ruleId === "k8s-dangerous-capabilities")
    expect(caps).toHaveLength(1)
  })

  it("flags a dangerous capability in inline form", () => {
    const m = `${POD_HEADER}\n      securityContext:\n        capabilities:\n          add: ["NET_ADMIN", "CHOWN"]`
    expect(
      scanKubernetes(m, "pod.yaml").some((f) => f.ruleId === "k8s-dangerous-capabilities"),
    ).toBe(true)
  })

  it("does NOT flag capabilities under drop:", () => {
    const m = `${POD_HEADER}\n      securityContext:\n        capabilities:\n          drop:\n            - ALL`
    expect(
      scanKubernetes(m, "pod.yaml").some((f) => f.ruleId === "k8s-dangerous-capabilities"),
    ).toBe(false)
  })

  it("does not flag a benign added capability", () => {
    const m = `${POD_HEADER}\n      securityContext:\n        capabilities:\n          add:\n            - NET_BIND_SERVICE`
    expect(
      scanKubernetes(m, "pod.yaml").some((f) => f.ruleId === "k8s-dangerous-capabilities"),
    ).toBe(false)
  })
})

describe("scanKubernetes — Helm templating", () => {
  it("skips templated lines", () => {
    const m = `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: app\n      image: {{ .Values.image }}\n      securityContext:\n        privileged: {{ .Values.privileged }}`
    // image and privileged are both templated → no findings
    expect(scanKubernetes(m, "templates/pod.yaml")).toHaveLength(0)
  })

  it("still flags literal misconfig on non-templated lines in a chart", () => {
    const m = `apiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - name: app\n      image: {{ .Values.image }}\n      securityContext:\n        privileged: true`
    expect(scanKubernetes(m, "templates/pod.yaml").some((f) => f.ruleId === "k8s-privileged-container")).toBe(true)
  })
})

describe("scanKubernetes — multi-doc + finding shape", () => {
  it("scans across --- document separators", () => {
    const m = `apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n---\napiVersion: v1\nkind: Pod\nspec:\n  containers:\n    - securityContext:\n        privileged: true`
    expect(scanKubernetes(m, "all.yaml").some((f) => f.ruleId === "k8s-privileged-container")).toBe(true)
  })

  it("emits well-formed findings and every rule carries remediation", () => {
    const m = `${POD_HEADER}\n      securityContext:\n        privileged: true`
    const [f] = scanKubernetes(m, "pod.yaml").filter((x) => x.ruleId === "k8s-privileged-container")
    expect(f.category).toBe("kubernetes")
    expect(f.filePath).toBe("pod.yaml")
    expect(f.lineNumber).toBeGreaterThan(0)
    for (const rule of K8S_RULES) {
      expect(rule.remediation.trim().length).toBeGreaterThan(0)
      expect(rule.id.startsWith("k8s-")).toBe(true)
    }
  })
})
