import type { CodeFinding, CodeVulnCategory, Severity } from "./types"
import { isLikelyScannerSelfReference } from "./scanner-self-reference"

// Business-logic / broken-access-control scanner.
//
// The OWASP #1 risk (Broken Access Control) and business-logic flaws (payment
// tampering, mass assignment, privilege escalation) don't look like a CWE-89
// SQL injection — there's no dangerous *sink*. The vulnerability is that a
// trusted decision (who owns this record, how much does it cost, what role does
// this user have) is driven directly by attacker-controlled input.
//
// These can't be proven with a regex — ownership/authorization checks may live
// a few lines away — so every rule is framed as "verify there's a check here",
// kept conservative, and tied to the CWE that names the class. They emit
// CodeFinding so they flow through risk/SARIF/UI exactly like the code-vuln and
// framework layers. Comment lines are skipped (these are runtime-behaviour
// rules, not comment tells — that's the AI-insecure layer's job).

type Language = "js" | "python"

export type BizLogicRule = {
  id: string
  name: string
  severity: Severity
  category: Extract<CodeVulnCategory, "access-control" | "business-logic">
  cwe: string | null
  description: string
  languages: Language[]
  regex: RegExp
  /** Optional FP filter: return true to suppress a match on this line. */
  suppress?: (line: string) => boolean
}

// Lines that pass request data into a logging / serialization / response sink
// rather than a real ORM-write or charge. `{ amount: req.body.amount }` inside a
// `logger.info(...)` is structured logging, not payment tampering.
const LOGGING_OR_SERIALIZE_CONTEXT =
  /\b(?:console|logger|log|winston|pino|bunyan)\b\s*\.|\.(?:debug|info|warn|warning|error|trace|log)\s*\(|\b(?:JSON\.stringify|res\.json|response\.json|ctx\.body\s*=)\b/

export const BIZ_LOGIC_RULES: BizLogicRule[] = [
  // ───────────────────────── Mass assignment ─────────────────────────
  {
    id: "mass-assignment-orm-js",
    name: "Mass assignment: ORM write fed the whole request body",
    severity: "high",
    category: "access-control",
    cwe: "CWE-915",
    description:
      "An ORM create/update is passed `req.body` (or `request.body`) directly, so a client can set any column — including ones it should never control (role, isAdmin, balance, ownerId). Whitelist the assignable fields explicitly (e.g. pick/`fields`/a DTO) instead of spreading the raw body.",
    languages: ["js"],
    regex:
      /\b(?:create|createMany|update|updateOne|updateMany|build|bulkCreate|insert|insertMany|findByIdAndUpdate|findOneAndUpdate|save)\s*\(\s*(?:req|request|ctx)\.body\b/,
  },
  {
    id: "mass-assignment-new-model-js",
    name: "Mass assignment: model constructed from the whole request body",
    severity: "high",
    category: "access-control",
    cwe: "CWE-915",
    description:
      "`new Model(req.body)` lets the client populate every field of the entity, including privileged ones. Construct the model from an explicit allowlist of fields.",
    languages: ["js"],
    regex: /\bnew\s+[A-Z]\w*\s*\(\s*(?:req|request|ctx)\.body\s*\)/,
  },
  {
    id: "mass-assignment-py",
    name: "Mass assignment: request data splatted into ORM write",
    severity: "high",
    category: "access-control",
    cwe: "CWE-915",
    description:
      "`Model.objects.create(**request.data)` (or `**request.POST` / `**request.json`) lets the client set any model field. Bind explicit fields, or use a serializer with a fixed `fields` allowlist (never `fields = '__all__'` on a model with privileged columns).",
    languages: ["python"],
    regex:
      /\.(?:create|update|filter|get_or_create|update_or_create)\s*\(\s*\*\*\s*(?:request\.(?:data|POST|GET|json)|self\.request\.data)\b/,
  },

  // ───────────────────── Privilege escalation via input ─────────────────────
  {
    id: "privilege-from-client-js",
    name: "Privilege escalation: role/admin flag assigned from request input",
    severity: "high",
    category: "access-control",
    cwe: "CWE-269",
    description:
      "A role/privilege attribute (role, isAdmin, permissions, accessLevel) is set from `req.body`/`req.query`/`req.params`. The client can then promote itself. Authorization attributes must be derived server-side from the authenticated session, never from the request payload.",
    languages: ["js"],
    regex:
      /\b(?:is_?[Aa]dmin|role|roles|isSuperuser|is_superuser|permissions?|accessLevel|access_level|isStaff|is_staff)\s*[:=]\s*(?:req|request|ctx)\.(?:body|query|params)\b/,
  },
  {
    id: "privilege-from-client-py",
    name: "Privilege escalation: privileged user flag assigned from request",
    severity: "high",
    category: "access-control",
    cwe: "CWE-269",
    description:
      "A privileged attribute (is_staff, is_superuser, is_admin, role) is assigned from `request.data`/`request.POST`. Authorization state must come from the authenticated user, not from client-supplied data.",
    languages: ["python"],
    regex:
      /\b(?:is_staff|is_superuser|is_admin|role|roles|permissions?)\s*=\s*request\.(?:data|POST|GET|json)\b/,
  },

  // ─────────────────── Payment / amount tampering ───────────────────
  {
    id: "payment-amount-from-client-js",
    name: "Payment tampering: charge amount taken from client input",
    severity: "high",
    category: "business-logic",
    cwe: "CWE-840",
    description:
      "A monetary field (amount, price, total, unit_amount, subtotal, discount) is taken directly from `req.body`/`req.query`. A client can then set its own price. Compute the amount server-side from trusted catalog/cart data before charging.",
    languages: ["js"],
    regex:
      /\b(?:amount|price|total|unit_amount|unitAmount|subtotal|discount|amount_cents|amountCents)\s*:\s*(?:req|request|ctx)\.(?:body|query|params)\b/,
    suppress: (line) => LOGGING_OR_SERIALIZE_CONTEXT.test(line),
  },
  {
    id: "payment-amount-from-client-py",
    name: "Payment tampering: charge amount taken from request",
    severity: "high",
    category: "business-logic",
    cwe: "CWE-840",
    description:
      "A monetary field (amount, price, total) is taken from `request.data`/`request.POST` and used to build a charge. Derive the amount server-side from trusted data, not from the request.",
    languages: ["python"],
    regex:
      /\b(?:amount|price|total|unit_amount|subtotal|discount)\s*=\s*request\.(?:data|POST|GET|json)\b/,
    suppress: (line) => LOGGING_OR_SERIALIZE_CONTEXT.test(line),
  },

  // ──────────────────── IDOR — direct object reference ────────────────────
  {
    id: "idor-direct-lookup-js",
    name: "Possible IDOR: record fetched by client id with no ownership scope",
    severity: "medium",
    category: "access-control",
    cwe: "CWE-639",
    description:
      "An entity is loaded by primary key taken straight from `req.params`/`req.query`/`req.body` (findById/findByPk/getById). If the handler doesn't then check the record belongs to the authenticated user, any user can read/modify another's data. Verify ownership, or scope the query by the session user id.",
    languages: ["js"],
    regex:
      /\.(?:findById|findByPk|getById|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove)\s*\(\s*(?:req|request|ctx)\.(?:params|query|body)\./,
  },
  {
    id: "idor-direct-lookup-py",
    name: "Possible IDOR: object fetched by client id with no ownership scope",
    severity: "medium",
    category: "access-control",
    cwe: "CWE-639",
    description:
      "An object is fetched by pk/id taken from `request` (`.objects.get(pk=request...)` / `get_object_or_404(..., pk=request...)`) with no owner filter. Scope the lookup by the authenticated user (`.filter(owner=request.user)`) or verify ownership after fetch.",
    languages: ["python"],
    regex:
      /(?:\.objects\.get\s*\(\s*(?:pk|id)\s*=\s*request\.(?:GET|POST|data)|get_object_or_404\s*\([^)]*\b(?:pk|id)\s*=\s*request\.(?:GET|POST|data))/,
  },
]

const JS_EXTENSIONS = new Set(["js", "jsx", "ts", "tsx", "mjs", "cjs"])
const PY_EXTENSIONS = new Set(["py", "pyi"])

function detectLanguage(filePath: string): Language | null {
  const lower = filePath.toLowerCase()
  const ext = lower.slice(lower.lastIndexOf(".") + 1)
  if (JS_EXTENSIONS.has(ext)) return "js"
  if (PY_EXTENSIONS.has(ext)) return "python"
  return null
}

/**
 * Scan a single file for business-logic / broken-access-control patterns.
 * Runs on the same content the secret/code scanners already fetched.
 */
export function scanBusinessLogic(
  content: string,
  filePath: string,
  likelyTestFixture: boolean,
): CodeFinding[] {
  const language = detectLanguage(filePath)
  if (!language) return []

  const applicable = BIZ_LOGIC_RULES.filter((r) => r.languages.includes(language))
  if (applicable.length === 0) return []

  const findings: CodeFinding[] = []
  const lines = content.split("\n")
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const trimmed = line.trimStart()
    // Skip comment lines (these are runtime-behaviour rules). Language-aware:
    // `#` is a comment in Python but an ES private class field in JS/TS
    // (`#role = req.body.role`), so only treat `#` as a comment for Python.
    const isComment =
      trimmed.startsWith("//") ||
      trimmed.startsWith("*") ||
      (language === "python" && trimmed.startsWith("#"))
    if (isComment) continue
    for (const rule of applicable) {
      const m = rule.regex.exec(line)
      if (!m) continue
      if (rule.suppress?.(line)) continue
      if (isLikelyScannerSelfReference(line, m.index)) continue
      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        category: rule.category,
        description: rule.description,
        cwe: rule.cwe,
        filePath,
        lineNumber: i + 1,
        lineContent: line.trim().slice(0, 200),
        likelyTestFixture,
      })
    }
  }
  return findings
}
