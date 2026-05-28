import type { CodeFinding, Severity } from "./types"
import type { Framework } from "./framework-detect"
import { isLikelyScannerSelfReference } from "./scanner-self-reference"

// Framework-aware SAST rules. Each rule fires only when (a) its framework is
// present in the repo (see lib/framework-detect.ts) and (b) the file is in a
// language the rule applies to. That context is what separates a real finding
// ("DEBUG = True in a Django settings module") from noise ("a variable named
// DEBUG in some random script").
//
// Rules are conservative single-line regexes, emitted as CodeFinding so they
// flow through risk/SARIF/UI exactly like the existing code-vuln layer.

type Language = "js" | "python" | "java" | "php" | "ruby" | "any"

export type FrameworkRule = {
  id: string
  name: string
  severity: Severity
  framework: Framework
  languages: Language[]
  cwe: string | null
  description: string
  regex: RegExp
}

export const FRAMEWORK_RULES: FrameworkRule[] = [
  // ───────────────────────── Django ─────────────────────────
  {
    id: "django-debug-true",
    name: "Django DEBUG enabled",
    severity: "high",
    framework: "django",
    languages: ["python"],
    cwe: "CWE-489",
    description:
      "`DEBUG = True` in Django serves detailed stack traces (with settings and local variables) to anyone who triggers an error, and disables several security protections. It must be False in production.",
    regex: /^\s*DEBUG\s*=\s*True\b/,
  },
  {
    id: "django-allowed-hosts-wildcard",
    name: "Django ALLOWED_HOSTS allows any host",
    severity: "medium",
    framework: "django",
    languages: ["python"],
    cwe: "CWE-16",
    description:
      "`ALLOWED_HOSTS = ['*']` disables Django's Host-header validation, enabling Host-header poisoning and cache-poisoning attacks.",
    regex: /^\s*ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']\s*\]/,
  },
  {
    id: "django-csrf-exempt",
    name: "Django CSRF protection disabled on a view",
    severity: "high",
    framework: "django",
    languages: ["python"],
    cwe: "CWE-352",
    description:
      "`@csrf_exempt` turns off CSRF protection for a view. A state-changing view without CSRF protection can be triggered cross-site on behalf of an authenticated user.",
    regex: /@csrf_exempt\b/,
  },
  // ───────────────────────── Flask ─────────────────────────
  {
    id: "flask-debug-run",
    name: "Flask app run with debug=True",
    severity: "high",
    framework: "flask",
    languages: ["python"],
    cwe: "CWE-489",
    description:
      "`app.run(debug=True)` enables the Werkzeug debugger, which exposes an interactive Python console to anyone who can trigger an exception — remote code execution if reachable.",
    regex: /\.run\s*\([^)]*\bdebug\s*=\s*True\b/,
  },
  // ───────────────────────── FastAPI ─────────────────────────
  {
    id: "fastapi-cors-wildcard-credentials",
    name: "FastAPI CORS allows any origin with credentials",
    severity: "high",
    framework: "fastapi",
    languages: ["python"],
    cwe: "CWE-942",
    description:
      "CORSMiddleware with `allow_origins=['*']` together with `allow_credentials=True` lets any site make credentialed cross-origin requests — the browser will not block it, defeating the same-origin policy.",
    regex: /allow_origins\s*=\s*\[\s*["']\*["']\s*\]/,
  },
  // ───────────────────────── Express ─────────────────────────
  {
    id: "express-cors-wildcard",
    name: "Express CORS enabled with default (wildcard) origin",
    severity: "medium",
    framework: "express",
    languages: ["js"],
    cwe: "CWE-942",
    description:
      "`app.use(cors())` with no options reflects/allows any origin. Configure an explicit `origin` allowlist instead of the permissive default.",
    regex: /\b(?:app|router)\.use\s*\(\s*cors\s*\(\s*\)\s*\)/,
  },
  // ───────────────────────── NestJS ─────────────────────────
  {
    id: "nestjs-enablecors-wildcard",
    name: "NestJS enableCors() with default (wildcard) origin",
    severity: "medium",
    framework: "nestjs",
    languages: ["js"],
    cwe: "CWE-942",
    description:
      "`app.enableCors()` with no options allows any origin. Pass an explicit `origin` option restricting it to known front-ends.",
    regex: /\.enableCors\s*\(\s*\)/,
  },
  // ───────────────────────── Spring ─────────────────────────
  {
    id: "spring-csrf-disabled",
    name: "Spring Security CSRF protection disabled",
    severity: "high",
    framework: "spring",
    languages: ["java"],
    cwe: "CWE-352",
    description:
      "`http.csrf().disable()` (or `csrf(csrf -> csrf.disable())`) turns off CSRF protection for the whole application. Only acceptable for stateless APIs that use no cookies for auth.",
    regex: /\.csrf\s*\([^)]*\)\s*\.disable\s*\(\s*\)|csrf\s*\(\s*[^)]*\.disable\s*\(\s*\)\s*\)/,
  },
  {
    id: "spring-cors-wildcard",
    name: "Spring @CrossOrigin allows any origin",
    severity: "medium",
    framework: "spring",
    languages: ["java"],
    cwe: "CWE-942",
    description:
      '`@CrossOrigin(origins = "*")` opens an endpoint to cross-origin requests from any site. Restrict to known origins.',
    regex: /@CrossOrigin\s*\(\s*origins\s*=\s*["']\*["']/,
  },
  {
    id: "spring-actuator-expose-all",
    name: "Spring Boot Actuator exposes all endpoints",
    severity: "high",
    framework: "spring",
    languages: ["any"],
    cwe: "CWE-200",
    description:
      "`management.endpoints.web.exposure.include=*` exposes every Actuator endpoint (env, heapdump, mappings, …) over HTTP, leaking configuration and enabling abuse if unauthenticated.",
    regex: /management\.endpoints\.web\.exposure\.include\s*[=:]\s*["']?\*/,
  },
  // ───────────────────────── Laravel ─────────────────────────
  {
    id: "laravel-app-debug-true",
    name: "Laravel app debug enabled in config",
    severity: "medium",
    framework: "laravel",
    languages: ["php"],
    cwe: "CWE-489",
    description:
      "`'debug' => true` in Laravel config renders Ignition error pages with full stack traces and environment data. Drive it from `APP_DEBUG` and keep it false in production.",
    regex: /["']debug["']\s*=>\s*true\b/,
  },
  // ───────────────────────── Rails ─────────────────────────
  {
    id: "rails-skip-csrf",
    name: "Rails CSRF token verification skipped",
    severity: "high",
    framework: "rails",
    languages: ["ruby"],
    cwe: "CWE-352",
    description:
      "`skip_before_action :verify_authenticity_token` disables Rails CSRF protection on a controller. State-changing actions then become triggerable cross-site.",
    regex: /skip_before_action\s+:verify_authenticity_token\b/,
  },
]

const EXT_LANGUAGE: Record<string, Language> = {
  js: "js", jsx: "js", ts: "js", tsx: "js", mjs: "js", cjs: "js",
  py: "python",
  java: "java", kt: "java",
  php: "php",
  rb: "ruby",
}

function fileLanguage(filePath: string): Language | null {
  const ext = filePath.toLowerCase().split(".").pop() ?? ""
  return EXT_LANGUAGE[ext] ?? null
}

// `any`-language rules read config files (properties/yaml/json), so they get a
// broad allowlist of extensions rather than a code-language match.
const CONFIG_EXTENSIONS = new Set([
  "properties", "yml", "yaml", "conf", "config", "env", "ini", "toml",
])

function ruleAppliesToFile(rule: FrameworkRule, filePath: string): boolean {
  if (rule.languages.includes("any")) {
    const ext = filePath.toLowerCase().split(".").pop() ?? ""
    return CONFIG_EXTENSIONS.has(ext)
  }
  const lang = fileLanguage(filePath)
  return lang !== null && rule.languages.includes(lang)
}

/**
 * Apply framework-gated rules to a file. A rule fires only when its framework
 * is in `frameworks` and the file matches the rule's language(s).
 */
export function scanFrameworkRules(
  content: string,
  filePath: string,
  frameworks: Set<Framework>,
  likelyTestFixture: boolean,
): CodeFinding[] {
  if (frameworks.size === 0) return []
  const applicable = FRAMEWORK_RULES.filter(
    (r) => frameworks.has(r.framework) && ruleAppliesToFile(r, filePath),
  )
  if (applicable.length === 0) return []

  const findings: CodeFinding[] = []
  const lines = content.split("\n")
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    for (const rule of applicable) {
      if (!rule.regex.test(line)) continue
      if (isLikelyScannerSelfReference(line, 0)) continue
      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        category: "framework",
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
