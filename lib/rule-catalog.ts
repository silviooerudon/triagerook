import type { Severity } from "./types"
import { listAstRules } from "./ast/runner"
import { CODE_RULES } from "./code-vulns"
import { SECRET_PATTERNS } from "./secret-patterns"
import { FILE_RULES } from "./sensitive-files"
import { DOCKER_RULES, ACTIONS_RULES } from "./iac"
import { K8S_RULES } from "./iac-k8s"
import { HELM_RULES } from "./iac-helm"
import { TERRAFORM_RULES } from "./iac-terraform"
import { CLOUDFORMATION_RULES } from "./iac-cloudformation"
import { IAM_POLICY_RULES } from "./iam-policy"
import { FRAMEWORK_RULES } from "./framework-rules"
import { BIZ_LOGIC_RULES } from "./biz-logic"
import { AI_INSECURE_RULES } from "./ai-insecure"

// Side-effect import so the AST rule modules register themselves into
// the runner before we enumerate them. Without this, listAstRules()
// returns an empty array.
import "./ast"

// Detector layer this rule belongs to. Drives the badge color and the
// "How it's detected" sentence on the rule detail page.
export type DetectorLayer =
  | "ast"
  | "regex-code"
  | "secret-regex"
  | "sensitive-file"
  | "iac-dockerfile"
  | "iac-github-actions"
  | "iac-terraform"
  | "iac-cloudformation"
  | "iac-kubernetes"
  | "iac-helm"
  | "iac-iam"
  | "framework"
  | "business-logic"
  | "ai-generated"

export type CatalogEntry = {
  id: string
  layer: DetectorLayer
  name: string
  severity: Severity
  category: string
  cwe: string | null
  description: string
  // Optional remediation guidance — only some detectors carry this. The
  // rule detail page falls back to the description for layers that
  // weren't authored with a separate remediation field.
  remediation?: string
  // Programming languages this rule applies to (when relevant). For
  // secret patterns and sensitive-file rules this is "any" because the
  // detector is language-agnostic.
  languages?: readonly string[]
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
}

// Single aggregation function so the rule index page and the per-rule
// detail page never drift. Memoised at module scope because the source
// rule arrays are themselves module-scope constants — recomputing on
// every request would be wasteful for a page that is effectively static.
let cached: CatalogEntry[] | null = null

export function getRuleCatalog(): readonly CatalogEntry[] {
  if (cached) return cached
  const out: CatalogEntry[] = []

  for (const rule of listAstRules()) {
    out.push({
      id: rule.id,
      layer: "ast",
      name: rule.name,
      severity: rule.severity,
      category: rule.category,
      cwe: rule.cwe,
      description: rule.description,
      languages: rule.languages,
    })
  }

  for (const rule of CODE_RULES) {
    out.push({
      id: `code/${rule.id}`,
      layer: "regex-code",
      name: rule.name,
      severity: rule.severity,
      category: rule.category,
      cwe: rule.cwe,
      description: rule.description,
      languages: rule.languages,
    })
  }

  for (const rule of FRAMEWORK_RULES) {
    out.push({
      // SARIF emits these as `code/<id>` (they're CodeFindings), so the
      // catalog id matches for a direct resolve.
      id: `code/${rule.id}`,
      layer: "framework",
      name: rule.name,
      severity: rule.severity,
      category: `framework:${rule.framework}`,
      cwe: rule.cwe,
      description: rule.description,
      languages: rule.languages,
    })
  }

  for (const rule of BIZ_LOGIC_RULES) {
    out.push({
      // Emitted as CodeFindings → SARIF id `code/<id>`, so the catalog id matches.
      id: `code/${rule.id}`,
      layer: "business-logic",
      name: rule.name,
      severity: rule.severity,
      category: rule.category,
      cwe: rule.cwe,
      description: rule.description,
      languages: rule.languages,
    })
  }

  for (const rule of AI_INSECURE_RULES) {
    out.push({
      id: `code/${rule.id}`,
      layer: "ai-generated",
      name: rule.name,
      severity: rule.severity,
      category: rule.category,
      cwe: rule.cwe,
      description: rule.description,
      languages: rule.languages,
    })
  }

  for (const rule of SECRET_PATTERNS) {
    out.push({
      id: `secret/${rule.id}`,
      layer: "secret-regex",
      name: rule.name,
      severity: rule.severity,
      category: "secret",
      cwe: "CWE-798",
      description: rule.description,
    })
  }

  for (const rule of FILE_RULES) {
    out.push({
      id: `sensitive-file/${rule.kind}`,
      layer: "sensitive-file",
      name: rule.name,
      severity: rule.severity,
      category: "sensitive-file",
      cwe: null,
      description: rule.description,
      remediation: rule.remediation,
    })
  }

  for (const rule of DOCKER_RULES) {
    out.push({
      id: `iac/dockerfile/${rule.id}`,
      layer: "iac-dockerfile",
      name: rule.name,
      severity: rule.severity,
      category: "iac-dockerfile",
      cwe: null,
      description: rule.description,
      remediation: rule.remediation,
    })
  }

  // Emitted by scanDockerBaseImages (outside the single-index DOCKER_RULES
  // model), so it's listed here explicitly. Severity is dynamic per how long
  // past EOL the image is; we advertise the worst case.
  out.push({
    id: `iac/dockerfile/dockerfile-base-image-eol`,
    layer: "iac-dockerfile",
    name: "End-of-life base image",
    severity: "high",
    category: "iac-dockerfile",
    cwe: "CWE-1104",
    description:
      "A base image past its end-of-life no longer receives security updates, so unpatched OS/runtime CVEs accumulate in every layer built on it.",
    remediation:
      "Upgrade to a currently-supported release of the base image and rebuild; pin to a digest once on a supported tag.",
  })

  for (const rule of ACTIONS_RULES) {
    out.push({
      id: `iac/actions/${rule.id}`,
      layer: "iac-github-actions",
      name: rule.name,
      severity: rule.severity,
      category: "iac-actions",
      cwe: null,
      description: rule.description,
      remediation: rule.remediation,
    })
  }

  for (const rule of TERRAFORM_RULES) {
    out.push({
      id: `iac/terraform/${rule.id}`,
      layer: "iac-terraform",
      name: rule.name,
      severity: rule.severity,
      category: "iac-terraform",
      cwe: null,
      description: rule.description,
      remediation: rule.remediation,
    })
  }

  for (const rule of CLOUDFORMATION_RULES) {
    out.push({
      id: `iac/cloudformation/${rule.id}`,
      layer: "iac-cloudformation",
      name: rule.name,
      severity: rule.severity,
      category: "iac-cloudformation",
      cwe: null,
      description: rule.description,
      remediation: rule.remediation,
    })
  }

  for (const rule of K8S_RULES) {
    out.push({
      id: `iac/kubernetes/${rule.id}`,
      layer: "iac-kubernetes",
      name: rule.name,
      severity: rule.severity,
      category: "iac-kubernetes",
      cwe: null,
      description: rule.description,
      remediation: rule.remediation,
    })
  }

  for (const rule of HELM_RULES) {
    out.push({
      id: `iac/helm/${rule.id}`,
      layer: "iac-helm",
      name: rule.name,
      severity: rule.severity,
      category: "iac-helm",
      cwe: null,
      description: rule.description,
      remediation: rule.remediation,
    })
  }

  for (const rule of IAM_POLICY_RULES) {
    out.push({
      id: `iac/iam/${rule.id}`,
      layer: "iac-iam",
      name: rule.name,
      severity: rule.severity,
      category: "iac-iam",
      cwe: null,
      description: rule.description,
      remediation: rule.remediation,
    })
  }

  out.sort((a, b) => {
    const sev = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
    if (sev !== 0) return sev
    if (a.layer !== b.layer) return a.layer.localeCompare(b.layer)
    return a.id.localeCompare(b.id)
  })

  cached = out
  return out
}

export function findCatalogEntry(id: string): CatalogEntry | undefined {
  return getRuleCatalog().find((e) => e.id === id)
}

// SARIF emits rule ids using the runtime finding kind (always `code/<id>`
// for both AST and regex code rules, always `iac/<id>` without
// dockerfile/actions discrimination). The catalog uses more specific
// prefixes. This resolver bridges the two so a SARIF helpUri pointing at
// `/docs/rules/code.sql-injection-template` still lands on the matching
// rule page (which lives at `ast/sql-injection-template` in the catalog).
//
// Returns the canonical catalog entry, or undefined when no rule matches
// (e.g. dependency findings have no catalog page since the rules are
// dynamically sourced from npm-audit / OSV).
export function resolveCatalogEntry(id: string): CatalogEntry | undefined {
  const direct = findCatalogEntry(id)
  if (direct) return direct

  const slashAt = id.indexOf("/")
  if (slashAt < 0) return undefined
  const prefix = id.slice(0, slashAt)
  const rest = id.slice(slashAt + 1)

  if (prefix === "code") {
    return findCatalogEntry(`ast/${rest}`)
  }
  if (prefix === "iac") {
    return findCatalogEntry(`iac/dockerfile/${rest}`)
      ?? findCatalogEntry(`iac/actions/${rest}`)
      ?? findCatalogEntry(`iac/terraform/${rest}`)
      ?? findCatalogEntry(`iac/kubernetes/${rest}`)
      ?? findCatalogEntry(`iac/iam/${rest}`)
  }
  return undefined
}

// Encode a rule id into a URL-safe slug for the [ruleId] dynamic route.
// Rule ids contain '/' (e.g. "ast/sql-injection-template") which would
// otherwise break Next's path parsing. We swap '/' for '.' so the URL
// stays readable (`/docs/rules/ast.sql-injection-template`) — '.' is
// not used inside any of our rule names, so the round-trip is lossless.
const SLUG_SEPARATOR = "."

export function ruleIdToSlug(id: string): string {
  return id.replaceAll("/", SLUG_SEPARATOR)
}

export function slugToRuleId(slug: string): string {
  return slug.replaceAll(SLUG_SEPARATOR, "/")
}

// Layer display metadata for the index page. Kept separate from the
// catalog so this file remains pure data; UI strings live with the UI.
export const LAYER_LABELS: Record<DetectorLayer, string> = {
  ast: "AST",
  "regex-code": "Code regex",
  "secret-regex": "Secret pattern",
  "sensitive-file": "Sensitive file",
  "iac-dockerfile": "Dockerfile",
  "iac-github-actions": "GitHub Actions",
  "iac-terraform": "Terraform",
  "iac-cloudformation": "CloudFormation",
  "iac-kubernetes": "Kubernetes",
  "iac-helm": "Helm",
  "iac-iam": "Cloud IAM",
  framework: "Framework-aware",
  "business-logic": "Business logic",
  "ai-generated": "AI-generated code",
}
