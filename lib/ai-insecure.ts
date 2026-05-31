import type { CodeFinding, CodeVulnCategory, Severity } from "./types"
import { isLikelyScannerSelfReference } from "./scanner-self-reference"

// AI-generated insecure-code detector.
//
// LLM coding assistants produce code that *runs* but carries tell-tale
// shortcuts that ship to production: placeholder credentials left in literals,
// "in a real application you'd validate this" disclaimers next to the missing
// validation, TODO-auth markers, and swallowed exceptions that hide failures.
// None of these is caught by the classic CWE-sink detectors — the signal is the
// scaffolding itself.
//
// Unlike the code-vuln / business-logic layers, this scanner DOES read comment
// lines (the disclaimers and TODO markers are the whole point). Severities are
// deliberately low/medium so these hygiene tells don't drown out real
// vulnerabilities — they're "this code wasn't finished/hardened" signals.

type Language = "js" | "python" | "any"

export type AiInsecureRule = {
  id: string
  name: string
  severity: Severity
  category: Extract<CodeVulnCategory, "ai-generated">
  cwe: string | null
  description: string
  languages: Language[]
  regex: RegExp
  /** When true, the matched line is masked before display (may embed a literal). */
  mask?: boolean
}

export const AI_INSECURE_RULES: AiInsecureRule[] = [
  {
    id: "ai-placeholder-credential",
    name: "Placeholder credential left in code",
    severity: "high",
    category: "ai-generated",
    cwe: "CWE-798",
    description:
      "A credential literal is a generated placeholder (your-api-key, INSERT_API_KEY_HERE, <your-secret>, change-me, sk-xxxx…). AI assistants emit these so the snippet 'works', and they ship unchanged — either as a broken default in production or, worse, replaced inline with a real secret that then gets committed. Move it to an environment variable and fail fast when it's unset.",
    languages: ["js", "python"],
    mask: true,
    // Word-like tokens are \b-anchored so they match a whole placeholder, not a
    // substring of a longer identifier (the change_me / x{12,} FP class —
    // `placeholderKeyboard`, `your_tokenizer`, `replaceThisNode` must NOT match).
    // A trailing `s?` keeps plural placeholders (`your-secrets`, `placeholder_keys`)
    // matching without re-admitting `...keyboard`/`...secretary`. The `sk-x{6,}`
    // token is deliberately NOT trailing-\b-anchored: real OpenAI placeholders are
    // `sk-xxxx<more chars>` (no boundary after the x-run).
    regex:
      /(?:\byour[_-]?(?:api[_-]?key|secret|token|password|client[_-]?secret)s?\b|\bapi[_-]?key[_-]?here\b|\binsert[_-]?(?:your[_-]?)?(?:api[_-]?)?key[_-]?here\b|\breplace[_-]?(?:this|with[_-]?your[_-]?\w+)\b|\bchange[-_]?me\b|<your[_-][a-z0-9_]+>|\bsk-x{6,}|\bplaceholder[_-]?(?:api[_-]?)?(?:key|secret|token)s?\b)/i,
  },
  {
    id: "ai-todo-security",
    name: "Security control deferred with a TODO/FIXME",
    severity: "medium",
    category: "ai-generated",
    cwe: "CWE-710",
    description:
      "A TODO/FIXME/HACK comment defers a security control (auth, authorization, validation, sanitization, CSRF, encryption). AI-generated scaffolding routinely stubs these out and leaves the marker; the endpoint then ships without the control. Implement it or gate the code behind a feature flag until it exists.",
    languages: ["any"],
    regex:
      /\b(?:TODO|FIXME|XXX|HACK)\b[^\n]{0,50}?\b(?:auth(?:z|n|orization|enticat\w+)?|permission|access[\s-]?control|validate|validation|sanitiz\w+|sanitis\w+|csrf|escap\w+|encrypt\w+|verify\s+(?:the\s+)?(?:user|token|signature))\b/i,
  },
  {
    id: "ai-demo-disclaimer",
    name: "“Not production-ready” disclaimer left in code",
    severity: "low",
    category: "ai-generated",
    cwe: "CWE-1059",
    description:
      "A generated disclaimer (\"in a real application you would…\", \"for demonstration purposes only\", \"this is a simplified example\", \"don't do this in production\") signals the surrounding code was scaffolded, not hardened — frequently next to a missing check or an insecure shortcut. Review the adjacent code for the control the comment admits is absent.",
    languages: ["any"],
    regex:
      /(?:in\s+(?:a\s+)?(?:real|production)\s+(?:application|app|environment|system|world|scenario|setting|deployment)|for\s+(?:demonstration|demo|illustration|example|simplicity|brevity)\s+(?:purposes|only)|this\s+is\s+(?:just\s+)?(?:a\s+)?(?:simplified|simple|basic|naive|minimal)\s+(?:example|implementation|version|approach)|(?:not|never)\s+(?:suitable|intended|meant|recommended)\s+for\s+production|do\s*n['o]?t\s+(?:do\s+)?this\s+in\s+production)/i,
  },
  {
    id: "ai-bare-except-pass",
    name: "Swallowed exception (bare except: pass)",
    severity: "medium",
    category: "ai-generated",
    cwe: "CWE-703",
    description:
      "A bare `except:`/`except Exception:` that only `pass`es hides every error — including auth failures, integrity-check failures, and security-relevant exceptions — letting the code continue in an unexpected state. Catch the specific exception and handle (or re-raise) it.",
    languages: ["python"],
    // Allow a trailing comment after `pass` (e.g. `except: pass  # ignore`).
    regex: /^\s*except\b[^\n:]*:\s*pass\s*(?:#.*)?$/,
  },
  {
    id: "ai-empty-catch",
    name: "Empty catch block swallows errors",
    severity: "low",
    category: "ai-generated",
    cwe: "CWE-703",
    description:
      "An empty `catch {}` discards the error, masking failures (including security-relevant ones) and making incidents undebuggable. At minimum log the error; handle or rethrow it where it matters.",
    languages: ["js"],
    regex: /\bcatch\s*(?:\([^)]*\))?\s*\{\s*\}/,
  },
]

const JS_EXTENSIONS = new Set(["js", "jsx", "ts", "tsx", "mjs", "cjs"])
const PY_EXTENSIONS = new Set(["py", "pyi"])
// `any`-language rules (comment tells) apply to source files broadly.
const TEXT_CODE_EXTENSIONS = new Set([
  "js", "jsx", "ts", "tsx", "mjs", "cjs", "py", "pyi", "java", "kt", "go",
  "rb", "php", "cs", "rs", "c", "cpp", "h", "hpp", "swift", "scala",
])

function detectLanguage(filePath: string): "js" | "python" | null {
  const lower = filePath.toLowerCase()
  const ext = lower.slice(lower.lastIndexOf(".") + 1)
  if (JS_EXTENSIONS.has(ext)) return "js"
  if (PY_EXTENSIONS.has(ext)) return "python"
  return null
}

function fileExtension(filePath: string): string {
  const lower = filePath.toLowerCase()
  return lower.slice(lower.lastIndexOf(".") + 1)
}

function ruleApplies(rule: AiInsecureRule, filePath: string): boolean {
  if (rule.languages.includes("any")) {
    return TEXT_CODE_EXTENSIONS.has(fileExtension(filePath))
  }
  const lang = detectLanguage(filePath)
  return lang !== null && rule.languages.includes(lang)
}

// This guard is intentionally specific to the AI-insecure layer: unlike the
// code-vuln / business-logic / framework detectors (which skip comment lines),
// this layer scans comments and prose, so its own `description:`/`name:` rule
// copy — and prose-property fields in any scanned config/schema — match the
// disclaimer/TODO regexes. The shared isLikelyScannerSelfReference deliberately
// does NOT cover prose markers (broadening it risks FPs in the comment-skipping
// layers — see .repoguardignore), so the prose guard lives here, where prose IS
// scanned. Skip matches that sit after a string-property marker.
const STRING_PROP_MARKER = /\b(?:description|name|reason|title|message|label|capability)\s*:\s*/i

function isProseDefinition(line: string, matchOffset: number): boolean {
  return STRING_PROP_MARKER.test(line.slice(0, matchOffset))
}

const QUOTED_LITERAL = /(["'`])([^"'`\n]{6,})\1/g

// High-confidence credential token shapes. Redacted even when UNQUOTED so a real
// secret co-located with a placeholder match (e.g. `API_KEY = sk_live_real  #
// change-me`) never survives into lineContent, which is persisted and returned.
// NOTE: this is a deliberately small subset of lib/secret-patterns.ts (the
// canonical "what a secret looks like" registry) covering the highest-volume
// leak shapes. If you add/retune a provider prefix there, mirror it here so
// redaction coverage doesn't drift behind detection coverage.
const SECRET_TOKEN =
  /\b(?:sk-[A-Za-z0-9_-]{12,}|sk_(?:live|test)_[A-Za-z0-9]{12,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|xox[baprs]-[0-9A-Za-z-]{10,})/g

function maskLine(line: string, matched?: string): string {
  let safe = line
    .trim()
    .replace(QUOTED_LITERAL, (_m, q) => `${q}***REDACTED***${q}`)
    .replace(SECRET_TOKEN, "***REDACTED***")
  // Redact the matched placeholder itself when it survived the above (e.g. an
  // unquoted `your-api-key`), so a mask:true finding never echoes the literal.
  if (matched && safe.includes(matched)) safe = safe.split(matched).join("***REDACTED***")
  return safe.length > 200 ? safe.slice(0, 200) + "…" : safe
}

/**
 * Scan a single file for AI-generated-insecure-code tells. Reads comment lines
 * too (the disclaimers/TODO markers are the signal).
 */
export function scanAiInsecure(
  content: string,
  filePath: string,
  likelyTestFixture: boolean,
): CodeFinding[] {
  const applicable = AI_INSECURE_RULES.filter((r) => ruleApplies(r, filePath))
  if (applicable.length === 0) return []

  const findings: CodeFinding[] = []
  const lines = content.split("\n")
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    for (const rule of applicable) {
      const m = rule.regex.exec(line)
      if (!m) continue
      if (isLikelyScannerSelfReference(line, m.index)) continue
      if (isProseDefinition(line, m.index)) continue
      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        category: rule.category,
        description: rule.description,
        cwe: rule.cwe,
        filePath,
        lineNumber: i + 1,
        lineContent: rule.mask ? maskLine(line, m[0]) : line.trim().slice(0, 200),
        likelyTestFixture,
      })
    }
  }
  return findings
}
