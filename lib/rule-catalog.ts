import type { Severity } from "./types"
import { listAstRules } from "./ast/runner"
import { CODE_RULES } from "./code-vulns"
import { SECRET_PATTERNS } from "./secret-patterns"
import { FILE_RULES } from "./sensitive-files"
import { DOCKER_RULES, ACTIONS_RULES } from "./iac"

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
}
