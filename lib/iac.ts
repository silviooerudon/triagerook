import type { IaCFinding, Severity } from "./types"

export type DockerRule = {
  id: string
  name: string
  severity: Severity
  description: string
  remediation: string
  /** Returns matched line index (0-based), or null if no match. */
  check: (lines: string[]) => number | null
}

export const DOCKER_RULES: DockerRule[] = [
  {
    id: "dockerfile-user-root",
    name: "Container runs as root",
    severity: "medium",
    description:
      "No USER directive found, so the container's entrypoint runs as UID 0. Any container escape or mounted-volume bug becomes root-equivalent on the host kernel.",
    remediation:
      "Add a non-root USER (e.g. `USER 10001` or `USER node`) after installing packages.",
    check: (lines) => {
      const hasUser = lines.some((l) => /^\s*USER\s+\S/i.test(l) && !/^\s*USER\s+(root|0)\s*$/i.test(l))
      if (hasUser) return null
      // Point at the FROM line as the place the reviewer should look
      const fromIdx = lines.findIndex((l) => /^\s*FROM\s/i.test(l))
      return fromIdx >= 0 ? fromIdx : 0
    },
  },
  {
    id: "dockerfile-user-root-explicit",
    name: "Container explicitly runs as root",
    severity: "medium",
    description:
      "USER is set to root (UID 0). Drop privileges with USER <non-root> after any root-only steps (apt install, etc.).",
    remediation: "Replace with `USER 10001` (or `USER node` / `USER nobody`).",
    check: (lines) => lines.findIndex((l) => /^\s*USER\s+(root|0)\s*$/i.test(l)),
  },
  {
    id: "dockerfile-latest-tag",
    name: "Base image pinned to :latest",
    severity: "low",
    description:
      "Using :latest (or no tag) means builds are non-reproducible and new vulnerabilities silently enter the image.",
    remediation:
      "Pin to a specific version or, ideally, a SHA digest (`FROM node:20.11.1-alpine@sha256:...`).",
    check: (lines) =>
      lines.findIndex(
        (l) => /^\s*FROM\s+\S+(?::latest)?\s*$/i.test(l) && !/@sha256:[a-f0-9]{64}/.test(l) && (!/:\S+/.test(l.replace(/\s+AS\s+\S+.*$/i, "")) || /:latest/i.test(l)),
      ),
  },
  {
    id: "dockerfile-add-url",
    name: "ADD from remote URL",
    severity: "medium",
    description:
      "ADD with an HTTP(S) URL executes without verifying integrity and leaves the downloaded content unpinned. Prefer RUN curl/wget with explicit checksum verification.",
    remediation:
      "Use RUN with a pinned hash (`curl -fsSL <url> | sha256sum -c <(echo <hash>  -)`).",
    check: (lines) => lines.findIndex((l) => /^\s*ADD\s+https?:\/\//i.test(l)),
  },
  {
    id: "dockerfile-secret-in-env",
    name: "Secret baked into ENV layer",
    severity: "high",
    description:
      "Values like API_KEY, TOKEN, PASSWORD, SECRET passed via ENV are stored in the image layer history and readable by anyone who pulls the image.",
    remediation:
      "Pass via runtime env or use BuildKit secrets (`RUN --mount=type=secret,id=foo cat /run/secrets/foo`).",
    check: (lines) =>
      lines.findIndex(
        (l) =>
          /^\s*ENV\s+.*\b(?:API_KEY|TOKEN|SECRET|PASSWORD|PASSWD|AUTH|PRIVATE_KEY|ACCESS_KEY|CLIENT_SECRET)\b\s*[:=\s]/i.test(
            l,
          ),
      ),
  },
  {
    id: "dockerfile-curl-pipe-sh",
    name: "RUN pipes remote script to shell",
    severity: "high",
    description:
      "curl|bash during image build downloads unverified code and executes it. Common malware-insertion vector.",
    remediation:
      "Download, verify checksum, then execute: `curl -fsSLO <url> && echo '<sha>' file | sha256sum -c - && sh file`.",
    check: (lines) =>
      lines.findIndex(
        (l) =>
          /^\s*RUN\s/.test(l) && /\b(?:curl|wget)\b[^|\n]*\|\s*(?:ba)?sh\b/.test(l),
      ),
  },
  {
    id: "dockerfile-chmod-777",
    name: "World-writable files created",
    severity: "low",
    description:
      "chmod 777 grants read/write/execute to any user in the container. Usually a symptom of misunderstanding Unix permissions rather than a real requirement.",
    remediation:
      "Use 755 for dirs/executables, 644 for files, and prefer the correct owner via --chown.",
    check: (lines) =>
      lines.findIndex(
        (l) => /^\s*RUN\s/.test(l) && /\bchmod\s+(?:-R\s+)?(?:a\+rwx|777)\b/.test(l),
      ),
  },
  {
    id: "dockerfile-apt-noconfirm-no-pin",
    name: "apt install without version pinning",
    severity: "low",
    description:
      "apt-get install without specific versions makes builds non-reproducible and can pick up vulnerable packages silently between builds.",
    remediation: "Pin package versions (`apt-get install -y pkg=1.2.3`) or rely on a Docker layer cache bust per release.",
    check: (lines) =>
      lines.findIndex(
        (l) =>
          /^\s*RUN\s/.test(l) &&
          /\bapt(?:-get)?\s+install\b/.test(l) &&
          !/=\S+/.test(l),
      ),
  },
]

export function scanDockerfile(
  content: string,
  filePath: string,
): IaCFinding[] {
  const lines = content.split("\n")
  const findings: IaCFinding[] = []
  for (const rule of DOCKER_RULES) {
    const idx = rule.check(lines)
    if (idx === null) continue
    findings.push({
      ruleId: rule.id,
      ruleName: rule.name,
      severity: rule.severity,
      category: "dockerfile",
      description: rule.description,
      filePath,
      lineNumber: idx + 1,
      lineContent:
        (lines[idx] ?? "").trim().slice(0, 200) || null,
      remediation: rule.remediation,
    })
  }
  return findings
}

/**
 * Very small YAML-ish reader tuned for GitHub Actions files. A full YAML
 * parser (js-yaml) would be safer but adds 100KB+ to the bundle; since we
 * only need to spot a handful of patterns we scan text directly.
 */
export type ActionsRule = {
  id: string
  name: string
  severity: Severity
  description: string
  remediation: string
  scan: (content: string, filePath: string) => IaCFinding[]
}

export const ACTIONS_RULES: ActionsRule[] = [
  {
    id: "gha-pull-request-target-checkout-head",
    name: "pull_request_target checks out untrusted PR code",
    severity: "critical",
    description:
      "pull_request_target runs with repository secrets available. Checking out the PR head (github.event.pull_request.head.sha / head.ref / github.head_ref) under this trigger executes attacker-controlled code with write access and exposes all secrets — the root cause of the GhostAction / s1ngularity wave of breaches.",
    remediation:
      "Either switch to `pull_request` (no secrets exposed), or keep `pull_request_target` but checkout the base branch ref only and never run code from the PR.",
    scan: (content, filePath) => {
      if (!/on:[\s\S]*?pull_request_target/i.test(content)) return []
      const dangerousRefRegex =
        /ref:\s*(?:\$\{\{\s*)?(?:github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref)/i
      const checkoutRegex = /uses:\s*actions\/checkout@/i
      const lines = content.split("\n")
      const findings: IaCFinding[] = []
      let insideCheckout = false
      let lastCheckoutLine = 0
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        if (checkoutRegex.test(line)) {
          insideCheckout = true
          lastCheckoutLine = i
          continue
        }
        if (insideCheckout) {
          if (/^\s*-\s*(?:uses|name|run):/.test(line)) {
            insideCheckout = false
            continue
          }
          if (dangerousRefRegex.test(line)) {
            findings.push({
              ruleId: "gha-pull-request-target-checkout-head",
              ruleName: "pull_request_target checks out untrusted PR code",
              severity: "critical",
              category: "github-actions",
              description:
                "pull_request_target runs with repository secrets available. Checking out the PR head (github.event.pull_request.head.sha / head.ref / github.head_ref) under this trigger executes attacker-controlled code with write access and exposes all secrets — the root cause of the GhostAction / s1ngularity wave of breaches.",
              filePath,
              lineNumber: i + 1,
              lineContent: line.trim().slice(0, 200),
              remediation:
                "Either switch to `pull_request` (no secrets exposed), or keep `pull_request_target` but checkout the base branch ref only and never run code from the PR.",
            })
            insideCheckout = false
          }
        }
      }
      // If we saw pull_request_target + unpinned checkout but no explicit ref,
      // the default already checks out the base — that's safer, don't warn.
      void lastCheckoutLine
      return findings
    },
  },
  {
    id: "gha-unpinned-action",
    name: "Third-party action not pinned to a commit SHA",
    severity: "medium",
    description:
      "`uses: someone/action@main` (or @master / @v1) fetches whatever the maintainer's branch points at today. A compromised maintainer can replace the code without notice. Pin to a full 40-char commit SHA.",
    remediation:
      "Replace the tag/branch with the full SHA. Tools like `pinact` can automate this across a repo.",
    scan: (content, filePath) => {
      const findings: IaCFinding[] = []
      const lines = content.split("\n")
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        const m = line.match(
          /^\s*-?\s*uses:\s*([a-z0-9][a-z0-9._-]*\/[a-z0-9][a-z0-9._-]*(?:\/[a-z0-9][a-z0-9._-]*)?)@(\S+)/i,
        )
        if (!m) continue
        const [, name, ref] = m
        // First-party GitHub/Microsoft actions in the public repo are
        // lower risk; still flag them but at low severity? We'll keep them
        // at medium for uniformity but skip a couple known-safe orgs.
        if (/^(actions|github|docker)\//i.test(name)) continue
        // Full SHA check: 40 hex chars
        if (/^[a-f0-9]{40}$/.test(ref)) continue
        findings.push({
          ruleId: "gha-unpinned-action",
          ruleName: "Third-party action not pinned to a commit SHA",
          severity: "medium",
          category: "github-actions",
          description:
            "`uses: someone/action@main` (or @master / @v1) fetches whatever the maintainer's branch points at today. A compromised maintainer can replace the code without notice. Pin to a full 40-char commit SHA.",
          filePath,
          lineNumber: i + 1,
          lineContent: line.trim().slice(0, 200),
          remediation:
            "Replace the tag/branch with the full SHA. Tools like `pinact` can automate this across a repo.",
        })
      }
      return findings
    },
  },
  {
    id: "gha-script-injection",
    name: "Shell step interpolates GitHub event data",
    severity: "high",
    description:
      "`run:` steps that embed ${{ github.event.* }} values (issue titles, PR bodies, commit messages) expand before the shell parses them — anything an attacker can put in the field becomes shell code.",
    remediation:
      "Pass the value via env: then reference it as \"$FIELD\" inside the script, which runs through normal shell quoting.",
    scan: (content, filePath) => {
      const findings: IaCFinding[] = []
      const lines = content.split("\n")
      const danger =
        /\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review)\.(?:title|body|head\.ref)\s*\}\}|\$\{\{\s*github\.head_ref\s*\}\}/
      let inRun = false
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        if (/^\s*-?\s*run:\s*\|/.test(line) || /^\s*run:\s*\|/.test(line)) {
          inRun = true
          continue
        }
        if (inRun && /^\s*-\s*(?:uses|name|run):/.test(line)) inRun = false
        if (
          (inRun || /^\s*-?\s*run:\s*\S/.test(line)) &&
          danger.test(line)
        ) {
          findings.push({
            ruleId: "gha-script-injection",
            ruleName: "Shell step interpolates GitHub event data",
            severity: "high",
            category: "github-actions",
            description:
              "`run:` steps that embed ${{ github.event.* }} values (issue titles, PR bodies, commit messages) expand before the shell parses them — anything an attacker can put in the field becomes shell code.",
            filePath,
            lineNumber: i + 1,
            lineContent: line.trim().slice(0, 200),
            remediation:
              "Pass the value via env: then reference it as \"$FIELD\" inside the script, which runs through normal shell quoting.",
          })
        }
      }
      return findings
    },
  },
  {
    id: "gha-permissions-write-all",
    name: "Workflow grants write-all permissions",
    severity: "medium",
    description:
      "`permissions: write-all` (or the older default where no `permissions:` block is set) gives GITHUB_TOKEN full repo write access for every step, including any compromised action.",
    remediation:
      "Add an explicit `permissions:` block at the top of the workflow with only the scopes the jobs actually need (e.g. `contents: read`).",
    scan: (content, filePath) => {
      const findings: IaCFinding[] = []
      const lines = content.split("\n")
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        if (/^\s*permissions:\s*write-all\s*$/.test(line)) {
          findings.push({
            ruleId: "gha-permissions-write-all",
            ruleName: "Workflow grants write-all permissions",
            severity: "medium",
            category: "github-actions",
            description:
              "`permissions: write-all` (or the older default where no `permissions:` block is set) gives GITHUB_TOKEN full repo write access for every step, including any compromised action.",
            filePath,
            lineNumber: i + 1,
            lineContent: line.trim(),
            remediation:
              "Add an explicit `permissions:` block at the top of the workflow with only the scopes the jobs actually need (e.g. `contents: read`).",
          })
        }
      }
      return findings
    },
  },
]

export function scanGithubActions(
  content: string,
  filePath: string,
): IaCFinding[] {
  const findings: IaCFinding[] = []
  for (const rule of ACTIONS_RULES) {
    findings.push(...rule.scan(content, filePath))
  }
  return findings
}

/** Returns true when a given tree path looks like a GitHub Actions workflow. */
export function isActionsWorkflowPath(path: string): boolean {
  return /^\.github\/workflows\/[^/]+\.ya?ml$/i.test(path)
}

export function isDockerfilePath(path: string): boolean {
  const base = path.split("/").pop() ?? ""
  return /^Dockerfile(\.[A-Za-z0-9._-]+)?$/i.test(base) || /\.dockerfile$/i.test(base)
}
