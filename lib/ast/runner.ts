import type { SourceFile } from "ts-morph"
import type { CodeFinding, CodeVulnCategory, Severity } from "@/lib/types"
import { parseAst, type SupportedLanguage } from "./parser"

// Each rule walks the SourceFile and emits zero or more hits. Rules are
// pure functions over the AST — no I/O, no module resolution, no global
// state — so the runner can fan them out across files in parallel later
// without locking concerns.
export type AstRule = {
  id: string
  name: string
  severity: Severity
  category: CodeVulnCategory
  cwe: string
  description: string
  languages: SupportedLanguage[]
  detect: (sourceFile: SourceFile, language: SupportedLanguage) => AstRuleHit[]
}

export type AstRuleHit = {
  lineNumber: number
  // The raw source line at lineNumber. Rules should not include secret
  // values here; if the matched expression touches a credential, mask
  // before returning (see code-vulns.ts maskLineForDisplay() for the
  // pattern).
  lineContent: string
}

// Registry. Each rule self-registers by being added here so adding a
// rule is one import + one push, no string indirection.
const RULES: AstRule[] = []

export function registerAstRule(rule: AstRule): void {
  RULES.push(rule)
}

// Cap on the display line so DB / API responses don't carry 4000-char
// minified one-liners.
function clampLineContent(line: string): string {
  const trimmed = line.trim()
  return trimmed.length > 200 ? trimmed.slice(0, 200) + "…" : trimmed
}

export function runAstRules(
  filePath: string,
  content: string,
  likelyTestFixture: boolean
): CodeFinding[] {
  const parsed = parseAst(filePath, content)
  if (parsed.kind !== "ok") return []

  const findings: CodeFinding[] = []
  for (const rule of RULES) {
    if (!rule.languages.includes(parsed.language)) continue
    let hits: AstRuleHit[]
    try {
      hits = rule.detect(parsed.sourceFile, parsed.language)
    } catch (err) {
      // Rules can throw on pathological AST shapes (e.g. ts-morph
      // failing to resolve a type query). Swallow per-rule so one bad
      // rule doesn't kill the whole scan — log so the bug is visible
      // in Vercel runtime logs.
      console.warn(`[ast/${rule.id}] threw on ${filePath}:`, err)
      continue
    }
    for (const hit of hits) {
      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        category: rule.category,
        description: rule.description,
        cwe: rule.cwe,
        filePath,
        lineNumber: hit.lineNumber,
        lineContent: clampLineContent(hit.lineContent),
        likelyTestFixture,
      })
    }
  }
  return findings
}

// Test-only: empties the registry so a test can install a single rule
// and assert in isolation.
export function _resetAstRulesForTests(): AstRule[] {
  const previous = [...RULES]
  RULES.length = 0
  return previous
}

export function _restoreAstRulesForTests(rules: AstRule[]): void {
  RULES.length = 0
  RULES.push(...rules)
}
