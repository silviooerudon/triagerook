import type { IaCFinding, Severity } from "./types"

// Kubernetes manifest misconfiguration detector.
//
// Like the other IaC scanners (lib/iac.ts, lib/iac-terraform.ts) this reads
// YAML text directly instead of parsing it. Pulling in a full YAML parser
// would add weight, and the patterns we care about are high-confidence line
// shapes. The two rules that need structure (image tags / dangerous
// capabilities) track just enough context locally.
//
// Manifests are identified by content (apiVersion: + kind:) rather than by
// path, since k8s YAML can live anywhere in a repo. GitHub Actions workflows
// also have a kind-less shape and are dispatched before this in scan.ts, so
// there's no overlap.
//
// Helm: lines containing Go template markers ({{ ... }}) are skipped — a
// templated value is unknowable at scan time and would only produce noise.
// Charts with literal misconfigurations on non-templated lines are still
// covered. Pure-template files (every interesting line templated) simply
// yield nothing, which is the intended MVP behaviour.

export type KubernetesRule = {
  id: string
  name: string
  severity: Severity
  description: string
  remediation: string
  scan: (lines: string[], filePath: string) => IaCFinding[]
}

function makeFinding(
  rule: Pick<KubernetesRule, "id" | "name" | "severity" | "description" | "remediation">,
  filePath: string,
  lineIndex: number,
  lineContent: string,
): IaCFinding {
  return {
    ruleId: rule.id,
    ruleName: rule.name,
    severity: rule.severity,
    category: "kubernetes",
    description: rule.description,
    filePath,
    lineNumber: lineIndex + 1,
    lineContent: lineContent.trim().slice(0, 200) || null,
    remediation: rule.remediation,
  }
}

// Helm template marker — a line we cannot reason about.
function isTemplated(line: string): boolean {
  return /\{\{/.test(line)
}

// Per-line scanner helper: emit one finding per non-templated line matching `test`.
function lineRule(
  rule: Omit<KubernetesRule, "scan"> & { test: (line: string) => boolean },
): KubernetesRule {
  const { test, ...meta } = rule
  return {
    ...meta,
    scan: (lines, filePath) => {
      const findings: IaCFinding[] = []
      for (let i = 0; i < lines.length; i++) {
        if (isTemplated(lines[i])) continue
        if (test(lines[i])) findings.push(makeFinding(meta, filePath, i, lines[i]))
      }
      return findings
    },
  }
}

// Linux capabilities that grant near-root power inside a container.
const DANGEROUS_CAPS = /\b(?:ALL|SYS_ADMIN|NET_ADMIN|SYS_PTRACE|SYS_MODULE|NET_RAW|DAC_OVERRIDE|SETUID|SETGID)\b/

const CAP_RULE_META = {
  id: "k8s-dangerous-capabilities",
  name: "Dangerous Linux capability added",
  severity: "high" as const,
  description:
    "Adding capabilities like `ALL`, `SYS_ADMIN`, `NET_ADMIN`, or `SYS_PTRACE` via `securityContext.capabilities.add` hands the container powerful kernel privileges that are frequently abused for container escape.",
  remediation:
    "Drop all capabilities (`capabilities: { drop: [\"ALL\"] }`) and add back only the specific, minimal ones the workload requires.",
}

export const K8S_RULES: KubernetesRule[] = [
  lineRule({
    id: "k8s-privileged-container",
    name: "Privileged container",
    severity: "high",
    description:
      "`privileged: true` disables almost all container isolation — the process gets nearly all host capabilities and can access host devices. A compromise of the container is effectively a compromise of the node.",
    remediation:
      "Remove `privileged: true`. Grant only the specific capabilities the workload needs via `securityContext.capabilities.add`.",
    test: (l) => /^\s*privileged:\s*true\b/i.test(l),
  }),
  lineRule({
    id: "k8s-host-namespace",
    name: "Pod shares a host namespace",
    severity: "high",
    description:
      "`hostNetwork`, `hostPID`, or `hostIPC` set to true breaks the namespace boundary between the pod and the node — the container can see host network interfaces, processes, or IPC, widening the blast radius of any compromise.",
    remediation:
      "Remove the host namespace flag. Workloads almost never need direct host network/PID/IPC access.",
    test: (l) => /^\s*host(?:Network|PID|IPC):\s*true\b/i.test(l),
  }),
  lineRule({
    id: "k8s-allow-privilege-escalation",
    name: "allowPrivilegeEscalation enabled",
    severity: "medium",
    description:
      "`allowPrivilegeEscalation: true` lets a process gain more privileges than its parent (e.g. via setuid binaries). Combined with a vulnerable binary this is a path to root inside the container.",
    remediation:
      "Set `allowPrivilegeEscalation: false` in the container's securityContext.",
    test: (l) => /^\s*allowPrivilegeEscalation:\s*true\b/i.test(l),
  }),
  lineRule({
    id: "k8s-run-as-root",
    name: "Container runs as root",
    severity: "high",
    description:
      "`runAsUser: 0` (or `runAsNonRoot: false`) runs the container as UID 0. Any container-escape or mounted-volume bug then operates with root on the host kernel.",
    remediation:
      "Set `runAsNonRoot: true` and a non-zero `runAsUser` (e.g. 10001) in the securityContext.",
    test: (l) =>
      /^\s*runAsUser:\s*0\b/.test(l) || /^\s*runAsNonRoot:\s*false\b/i.test(l),
  }),
  {
    id: "k8s-image-latest",
    name: "Container image uses a mutable tag",
    severity: "low",
    description:
      "An image pinned to `:latest` (or with no tag at all) is non-reproducible: the same manifest can pull different code over time, and a compromised upstream tag silently enters the cluster.",
    remediation:
      "Pin images to an immutable digest (`image: repo/app@sha256:...`) or at least a specific version tag.",
    scan: (lines, filePath) => {
      const findings: IaCFinding[] = []
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        if (isTemplated(line)) continue
        const m = line.match(/^\s*-?\s*image:\s*["']?([^"'\s]+)["']?\s*$/i)
        if (!m) continue
        const ref = m[1]
        if (ref.includes("@sha256:")) continue // digest-pinned, good
        // Strip an optional registry host (which may contain ':port') by
        // looking only at the segment after the last '/'.
        const lastSeg = ref.slice(ref.lastIndexOf("/") + 1)
        const hasTag = lastSeg.includes(":")
        const isLatest = /:latest$/i.test(lastSeg)
        if (!hasTag || isLatest) {
          findings.push(
            makeFinding(
              {
                id: "k8s-image-latest",
                name: "Container image uses a mutable tag",
                severity: "low",
                description:
                  "An image pinned to `:latest` (or with no tag at all) is non-reproducible: the same manifest can pull different code over time, and a compromised upstream tag silently enters the cluster.",
                remediation:
                  "Pin images to an immutable digest (`image: repo/app@sha256:...`) or at least a specific version tag.",
              },
              filePath,
              i,
              line,
            ),
          )
        }
      }
      return findings
    },
  },
  {
    id: "k8s-dangerous-capabilities",
    name: "Dangerous Linux capability added",
    severity: "high",
    description:
      "Adding capabilities like `ALL`, `SYS_ADMIN`, `NET_ADMIN`, or `SYS_PTRACE` via `securityContext.capabilities.add` hands the container powerful kernel privileges that are frequently abused for container escape.",
    remediation:
      "Drop all capabilities (`capabilities: { drop: [\"ALL\"] }`) and add back only the specific, minimal ones the workload requires.",
    // Needs context: only flag capabilities listed under an `add:` block (or
    // inline `add: [...]`), not under `drop:`. Track the indent of the active
    // `add:` and flag dangerous caps on more-indented list items below it.
    scan: (lines, filePath) => {
      const findings: IaCFinding[] = []
      let addIndent = -1 // indent of the active `add:` block, or -1
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        if (isTemplated(line)) continue

        // Inline form: add: ["SYS_ADMIN", "NET_ADMIN"]
        const inline = line.match(/^\s*add:\s*\[(.+)\]/i)
        if (inline) {
          if (DANGEROUS_CAPS.test(inline[1])) {
            findings.push(
              makeFinding(CAP_RULE_META, filePath, i, line),
            )
          }
          continue
        }

        const addBlock = line.match(/^(\s*)add:\s*$/i)
        if (addBlock) {
          addIndent = addBlock[1].length
          continue
        }

        if (addIndent !== -1) {
          const indent = line.match(/^(\s*)/)?.[1].length ?? 0
          const isListItem = /^\s*-\s+\S/.test(line)
          // A non-list line at or below the add: indent closes the block.
          if (!isListItem && line.trim() !== "" && indent <= addIndent) {
            addIndent = -1
          } else if (isListItem && indent > addIndent && DANGEROUS_CAPS.test(line)) {
            findings.push(makeFinding(CAP_RULE_META, filePath, i, line))
          }
        }
      }
      return findings
    },
  },
]

export function scanKubernetes(content: string, filePath: string): IaCFinding[] {
  if (!looksLikeKubernetesManifest(content)) return []
  const lines = content.split("\n")
  const findings: IaCFinding[] = []
  for (const rule of K8S_RULES) {
    findings.push(...rule.scan(lines, filePath))
  }
  return findings
}

/**
 * Heuristic: a Kubernetes manifest has both a top-level `apiVersion:` and a
 * top-level `kind:`. We accept any document in the file (multi-doc YAML uses
 * `---` separators) so a `kind:` anywhere counts.
 */
export function looksLikeKubernetesManifest(content: string): boolean {
  return /^apiVersion:\s*\S/m.test(content) && /^kind:\s*\S/m.test(content)
}
