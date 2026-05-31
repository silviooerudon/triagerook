import type { IaCFinding, Severity } from "./types"

// Helm chart misconfiguration detector — scans values.yaml (and values-*.yaml /
// values.*.yaml) for insecure defaults.
//
// Why this is a *dedicated* scanner and not the Kubernetes one: a Helm
// values.yaml is NOT a rendered K8s manifest (no top-level apiVersion + kind),
// so lib/iac-k8s.ts self-guards out of it and never sees these settings. Yet a
// chart's values are exactly where insecure defaults live — `privileged: true`,
// `runAsNonRoot: false`, `hostNetwork: true`, a `:latest` image tag — and they
// silently flow into every rendered workload. This closes that gap.
//
// Line-based like the other IaC scanners. Hardcoded secrets in values.yaml are
// intentionally NOT handled here (the secret/entropy detectors already scan
// .yaml, so this would double-report).

export type HelmRule = {
  id: string
  name: string
  severity: Severity
  description: string
  remediation: string
  test: (line: string) => boolean
}

export const HELM_RULES: HelmRule[] = [
  {
    id: "helm-privileged",
    name: "Helm values enable privileged containers",
    severity: "high",
    description:
      "`privileged: true` in chart values renders a container with full host access — it can escape to the node. This is rarely required outside of node-level agents.",
    remediation: "Set `privileged: false` and grant only the specific Linux capabilities the workload needs.",
    test: (l) => /^\s*privileged\s*:\s*true\b/i.test(l),
  },
  {
    id: "helm-run-as-root",
    name: "Helm values run the container as root",
    severity: "medium",
    description:
      "`runAsNonRoot: false` (or `runAsUser: 0`) lets the workload run as UID 0. Any container-escape or mounted-volume bug then becomes root on the node.",
    remediation: "Set `runAsNonRoot: true` and a non-zero `runAsUser`.",
    test: (l) => /^\s*runAsNonRoot\s*:\s*false\b/i.test(l) || /^\s*runAsUser\s*:\s*0\b/.test(l),
  },
  {
    id: "helm-host-namespace",
    name: "Helm values share a host namespace",
    severity: "high",
    description:
      "`hostNetwork` / `hostPID` / `hostIPC: true` place the pod in the node's network, process, or IPC namespace — breaking pod isolation and exposing other workloads on the node.",
    remediation: "Remove the host-namespace flag unless the chart is a node-level agent that genuinely requires it.",
    test: (l) => /^\s*host(?:Network|PID|IPC)\s*:\s*true\b/i.test(l),
  },
  {
    id: "helm-allow-privilege-escalation",
    name: "Helm values allow privilege escalation",
    severity: "medium",
    description:
      "`allowPrivilegeEscalation: true` lets a process gain more privileges than its parent (e.g. via setuid binaries), undermining a dropped-capability security context.",
    remediation: "Set `allowPrivilegeEscalation: false` in the chart's securityContext values.",
    test: (l) => /^\s*allowPrivilegeEscalation\s*:\s*true\b/i.test(l),
  },
  {
    id: "helm-image-latest-tag",
    name: "Helm values pin an image to a mutable tag",
    severity: "low",
    description:
      "An image `tag: latest` (or an empty tag) makes deployments non-reproducible and silently pulls new, unreviewed image contents — including newly introduced vulnerabilities.",
    remediation: "Pin `tag` to a specific version, ideally a digest (`tag: \"1.2.3\"` / `digest: sha256:...`).",
    test: (l) => /^\s*tag\s*:\s*["']?latest["']?\s*$/i.test(l) || /^\s*tag\s*:\s*(?:""|'')\s*$/.test(l),
  },
]

/** Returns true for chart values files (values.yaml, values-prod.yaml, …). */
export function isHelmValuesPath(path: string): boolean {
  const base = path.split("/").pop() ?? path
  return /^values(?:[.-][\w.-]+)?\.ya?ml$/i.test(base)
}

export function scanHelmValues(content: string, filePath: string): IaCFinding[] {
  const findings: IaCFinding[] = []
  const lines = content.split("\n")
  for (const rule of HELM_RULES) {
    for (let i = 0; i < lines.length; i++) {
      if (rule.test(lines[i])) {
        findings.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          category: "helm",
          description: rule.description,
          filePath,
          lineNumber: i + 1,
          lineContent: lines[i].trim().slice(0, 200) || null,
          remediation: rule.remediation,
        })
      }
    }
  }
  return findings
}
