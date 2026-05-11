import type { CodeFinding, CodeVulnCategory, Severity } from "./types"

type Language = "js" | "python" | "any"

type CodeRule = {
  id: string
  name: string
  severity: Severity
  category: CodeVulnCategory
  cwe: string | null
  description: string
  languages: Language[]
  /** Regex applied line-by-line. Must have /g removed — we re-anchor per line. */
  regex: RegExp
  /** Optional filter to suppress false positives based on the captured line. */
  suppress?: (line: string) => boolean
}

/**
 * High-confidence code-vulnerability patterns. Intentionally conservative —
 * false positives erode trust faster than false negatives. Each rule ties to
 * a CWE to make output actionable and to integrate later with SARIF export.
 */
const CODE_RULES: CodeRule[] = [
  // ─────────────────────────  SSRF (Capital One lesson)  ─────────────────────
  {
    id: "js-ssrf-fetch-user-input",
    name: "SSRF: HTTP client called with user-controlled URL",
    severity: "critical",
    category: "ssrf",
    cwe: "CWE-918",
    description:
      "A request library is invoked with a URL derived from the HTTP request. Attackers can redirect the request to internal metadata endpoints (e.g. AWS 169.254.169.254) or internal services.",
    languages: ["js"],
    regex:
      /\b(?:fetch|axios(?:\.(?:get|post|put|delete|request))?|got|node-fetch|needle|request|superagent\.(?:get|post))\s*\(\s*[^)]*\b(?:req|request|ctx|context)\.(?:body|params|query|headers|url)\b/g,
  },
  {
    id: "py-ssrf-requests-user-input",
    name: "SSRF: requests library called with user-controlled URL",
    severity: "critical",
    category: "ssrf",
    cwe: "CWE-918",
    description:
      "A Python HTTP client is called with a URL derived from Flask/Django/FastAPI request data.",
    languages: ["python"],
    regex:
      /\b(?:requests|httpx|urllib3|aiohttp)\.(?:get|post|put|delete|request|head)\s*\([^)]*\b(?:request\.(?:args|form|json|GET|POST|data)|request\.query_params|params\.get)\b/g,
  },
  {
    id: "py-urllib-ssrf",
    name: "SSRF: urllib.request.urlopen with user input",
    severity: "critical",
    category: "ssrf",
    cwe: "CWE-918",
    description:
      "urllib.request.urlopen resolves arbitrary schemes (file://, ftp://) and is rarely the right primitive for user-supplied URLs.",
    languages: ["python"],
    regex:
      /\burllib\.request\.urlopen\s*\([^)]*\b(?:request\.(?:args|form|json|GET|POST|data)|params)\b/g,
  },

  // ─────────────────────────  SQL injection  ─────────────────────────────────
  {
    id: "js-sqli-string-concat",
    name: "SQL Injection: query built with + string concatenation",
    severity: "critical",
    category: "sqli",
    cwe: "CWE-89",
    description:
      "SQL string is concatenated with a variable. Use parameterized queries (?, $1) or a query builder instead.",
    languages: ["js"],
    regex:
      /\b(?:query|execute|exec|raw|run|prepare)\s*\(\s*["'`][^"'`]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b[^"'`]*["'`]\s*\+\s*\w/gi,
  },
  {
    id: "js-sqli-template-literal",
    name: "SQL Injection: template literal with interpolation",
    severity: "critical",
    category: "sqli",
    cwe: "CWE-89",
    description:
      "SQL is built via a template literal with ${var} interpolation, which is equivalent to string concatenation. Use parameter binding.",
    languages: ["js"],
    regex:
      /\b(?:query|execute|exec|raw|run|prepare)\s*\(\s*`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b[^`]*\$\{[^}]+\}/gi,
  },
  {
    id: "py-sqli-f-string",
    name: "SQL Injection: Python f-string/format interpolation in query",
    severity: "critical",
    category: "sqli",
    cwe: "CWE-89",
    description:
      "SQL query is built via f-string/format/% — both equivalent to string concatenation. Use parameterized queries (cursor.execute(sql, (x,))).",
    languages: ["python"],
    regex:
      /\.(?:execute|executemany|raw)\s*\(\s*f["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b[^"']*\{[^}]+\}|\.(?:execute|executemany|raw)\s*\(\s*["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^"']*["']\s*(?:%|\.format\b)/gi,
  },

  // ─────────────────────────  Command injection  ─────────────────────────────
  {
    id: "js-command-injection",
    name: "Command Injection: shell exec with user-controlled argument",
    severity: "critical",
    category: "command-injection",
    cwe: "CWE-78",
    description:
      "child_process.exec/execSync/spawn runs a shell command that includes untrusted input. Use execFile with an argv array instead.",
    languages: ["js"],
    regex:
      /\b(?:child_process\.)?(?:exec|execSync|spawn|spawnSync)\s*\(\s*[^)]*(?:`[^`]*\$\{[^}]+\}|["'`][^"'`]*["'`]\s*\+\s*\w|\breq\.(?:body|params|query|headers))/g,
  },
  {
    id: "py-command-injection",
    name: "Command Injection: subprocess/os.system with shell=True",
    severity: "critical",
    category: "command-injection",
    cwe: "CWE-78",
    description:
      "subprocess called with shell=True on a string that includes user input allows arbitrary command execution. Pass argv as a list and leave shell=False (default).",
    languages: ["python"],
    regex:
      /\b(?:subprocess\.(?:call|run|Popen|check_output|check_call))\s*\([^)]*shell\s*=\s*True[^)]*(?:\+|f["']|\.format\(|%|request\.(?:args|form|json))/g,
  },
  {
    id: "py-os-system",
    name: "Command Injection: os.system with string interpolation",
    severity: "critical",
    category: "command-injection",
    cwe: "CWE-78",
    description:
      "os.system passes its argument to /bin/sh -c. Any interpolated variable becomes a potential injection.",
    languages: ["python"],
    regex:
      /\bos\.system\s*\(\s*(?:f["']|[^)]*(?:\+|%|\.format\(|request\.|input\())/g,
  },

  // ─────────────────────────  XSS  ───────────────────────────────────────────
  {
    id: "js-xss-innerhtml",
    name: "XSS: innerHTML assigned from a variable",
    severity: "high",
    category: "xss",
    cwe: "CWE-79",
    description:
      "Setting .innerHTML with a non-literal string allows script injection. Use textContent or a sanitizer (DOMPurify).",
    languages: ["js"],
    regex: /\.innerHTML\s*=\s*(?!["'`](?:[^"'`]*)["'`]\s*[;}]?\s*$)[^=].*/g,
    suppress: (line) =>
      /\.innerHTML\s*=\s*["'`][^"'`]*["'`]\s*;?\s*(?:\/\/|$)/.test(line),
  },
  {
    id: "js-xss-react-dangerously",
    name: "XSS: dangerouslySetInnerHTML with non-constant value",
    severity: "high",
    category: "xss",
    cwe: "CWE-79",
    description:
      "React's dangerouslySetInnerHTML renders raw HTML. Only pass pre-sanitized (e.g. DOMPurify) or statically-known HTML strings.",
    languages: ["js"],
    regex: /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:\s*(?!["'`])/g,
  },
  {
    id: "js-xss-document-write",
    name: "XSS: document.write called with a variable",
    severity: "high",
    category: "xss",
    cwe: "CWE-79",
    description:
      "document.write with untrusted data injects script into the page. Avoid entirely in modern code.",
    languages: ["js"],
    regex: /\bdocument\.write(?:ln)?\s*\(\s*(?!["'`])[^)]+\)/g,
  },

  // ─────────────────────────  eval / dynamic code  ──────────────────────────
  {
    id: "js-eval",
    name: "Use of eval() with dynamic input",
    severity: "high",
    category: "eval",
    cwe: "CWE-95",
    description:
      "eval() executes arbitrary code. If the argument is influenced by user input, this is RCE. Avoid eval entirely.",
    languages: ["js"],
    regex: /\beval\s*\(\s*(?!["'`][^"'`]*["'`]\s*\))/g,
  },
  {
    id: "js-new-function",
    name: "new Function() constructor with dynamic body",
    severity: "high",
    category: "eval",
    cwe: "CWE-95",
    description:
      "new Function(...) is eval by another name and executes whatever string is passed in.",
    languages: ["js"],
    regex: /\bnew\s+Function\s*\(/g,
  },
  {
    id: "py-eval-exec",
    name: "Python eval()/exec() with dynamic input",
    severity: "high",
    category: "eval",
    cwe: "CWE-95",
    description:
      "eval/exec run arbitrary Python. Treat as RCE if the input is untrusted.",
    languages: ["python"],
    regex: /\b(?:eval|exec)\s*\(\s*(?!["'])/g,
  },

  // ─────────────────────────  Path traversal  ───────────────────────────────
  {
    id: "js-path-traversal",
    name: "Path Traversal: fs read with user-controlled path",
    severity: "high",
    category: "path-traversal",
    cwe: "CWE-22",
    description:
      "fs.readFile/createReadStream with a user-derived path can read arbitrary files (../../etc/passwd). Resolve against a fixed root and verify with path.resolve + startsWith.",
    languages: ["js"],
    regex:
      /\bfs\.(?:readFile(?:Sync)?|createReadStream|readdir(?:Sync)?)\s*\(\s*[^)]*\breq\.(?:body|params|query)/g,
  },
  {
    id: "py-path-traversal",
    name: "Path Traversal: open() with user-controlled path",
    severity: "high",
    category: "path-traversal",
    cwe: "CWE-22",
    description:
      "open() with a path derived from request data can read arbitrary files. Resolve via os.path.realpath and verify it stays in an allowlisted root.",
    languages: ["python"],
    regex:
      /\bopen\s*\(\s*[^)]*\b(?:request\.(?:args|form|json|GET|POST|files)|params\.get)/g,
  },

  // ─────────────────────────  Weak crypto  ───────────────────────────────────
  {
    id: "js-weak-hash-password",
    name: "Weak hashing: MD5/SHA1 used in auth/password context",
    severity: "medium",
    category: "weak-crypto",
    cwe: "CWE-327",
    description:
      "MD5 and SHA1 are unsuitable for password hashing or tokens. Use bcrypt/argon2/scrypt for passwords, HMAC-SHA256 for tokens.",
    languages: ["js"],
    regex:
      /\bcrypto\.createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)[\s\S]{0,200}?\b(?:password|passwd|pwd|token|auth|secret|sign)\b/gi,
  },
  {
    id: "py-weak-hash-password",
    name: "Weak hashing: hashlib.md5/sha1 used in auth context",
    severity: "medium",
    category: "weak-crypto",
    cwe: "CWE-327",
    description:
      "hashlib.md5/sha1 for passwords or tokens is insecure. Use argon2-cffi/bcrypt/passlib for passwords.",
    languages: ["python"],
    regex:
      /\bhashlib\.(?:md5|sha1)\s*\([\s\S]{0,150}?\b(?:password|passwd|pwd|token|auth|secret|sign)\b/gi,
  },
  {
    id: "js-insecure-random",
    name: "Insecure randomness: Math.random() in security context",
    severity: "medium",
    category: "weak-crypto",
    cwe: "CWE-338",
    description:
      "Math.random() is not cryptographically secure. For tokens/session IDs use crypto.randomBytes or crypto.randomUUID.",
    languages: ["js"],
    regex:
      /\bMath\.random\s*\(\s*\)[\s\S]{0,200}?\b(?:token|session|nonce|salt|password|otp|csrf|secret|key)\b/gi,
  },
  {
    id: "py-insecure-random",
    name: "Insecure randomness: random module used for security token",
    severity: "medium",
    category: "weak-crypto",
    cwe: "CWE-338",
    description:
      "Python's random module is not cryptographically secure. Use secrets.token_* for tokens and secrets.choice for sampling.",
    languages: ["python"],
    regex:
      /\brandom\.(?:random|randint|choice|sample|getrandbits)\s*\([\s\S]{0,150}?\b(?:token|session|nonce|salt|password|otp|csrf|secret|key)\b/gi,
  },

  // ─────────────────────────  JWT misuse  ───────────────────────────────────
  {
    id: "js-jwt-none-algorithm",
    name: "JWT verified with 'none' algorithm",
    severity: "critical",
    category: "jwt",
    cwe: "CWE-347",
    description:
      "Allowing the 'none' algorithm lets any caller forge tokens. Pin a specific algorithm list like ['HS256'] or ['RS256'].",
    languages: ["js"],
    regex: /\bjwt\.verify\s*\([^)]*algorithms?\s*:\s*\[[^\]]*["']none["']/gi,
  },
  {
    id: "js-jwt-decode-instead-of-verify",
    name: "JWT decoded without verification",
    severity: "high",
    category: "jwt",
    cwe: "CWE-347",
    description:
      "jwt.decode() does NOT verify the signature — callers often mistake it for authentication. Use jwt.verify with the signing key.",
    languages: ["js"],
    regex: /\bjwt\.decode\s*\([^)]*\)[\s\S]{0,120}?\b(?:user|auth|role|scope|admin)\b/gi,
  },

  // ─────────────────────────  CORS  ─────────────────────────────────────────
  {
    id: "js-cors-wildcard-credentials",
    name: "CORS: wildcard origin with credentials allowed",
    severity: "high",
    category: "cors",
    cwe: "CWE-942",
    description:
      "Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true is insecure (and ignored by browsers, usually silently). Use an explicit origin list.",
    languages: ["js"],
    regex:
      /(?:Access-Control-Allow-Origin\s*["'`]?\s*:\s*["']\*["'`]|origin\s*:\s*["']\*["'`])[\s\S]{0,300}?(?:Access-Control-Allow-Credentials\s*["'`]?\s*:\s*["']?true|credentials\s*:\s*true)/gi,
  },

  // ─────────────────────────  Deserialization  ──────────────────────────────
  {
    id: "py-pickle-loads",
    name: "Insecure deserialization: pickle.loads on untrusted data",
    severity: "critical",
    category: "deserialization",
    cwe: "CWE-502",
    description:
      "pickle.loads executes arbitrary code during deserialization. Never use it on data that could be user-controlled.",
    languages: ["python"],
    regex: /\bpickle\.loads?\s*\(/g,
  },
  {
    id: "py-yaml-load",
    name: "Insecure deserialization: yaml.load without SafeLoader",
    severity: "high",
    category: "deserialization",
    cwe: "CWE-502",
    description:
      "yaml.load (without Loader=SafeLoader) deserializes Python objects and can execute code. Use yaml.safe_load.",
    languages: ["python"],
    regex: /\byaml\.load\s*\([^)]*(?!Loader\s*=\s*(?:yaml\.)?(?:Safe|C?Safe)Loader)[^)]*\)/g,
  },

  // ─────────────────────────  Open redirect  ────────────────────────────────
  {
    id: "js-open-redirect",
    name: "Open redirect: res.redirect with user-controlled URL",
    severity: "medium",
    category: "open-redirect",
    cwe: "CWE-601",
    description:
      "Redirecting to a URL derived from the request allows attackers to craft phishing links that look genuine. Validate against an allowlist or relative paths only.",
    languages: ["js"],
    regex:
      /\bres\.(?:redirect|location)\s*\(\s*(?:req\.(?:body|params|query|headers)|\w+\.(?:body|params|query)\.\w+)/g,
  },

  // ─────────────────────────  TLS verification  ─────────────────────────────
  {
    id: "js-tls-verify-disabled",
    name: "TLS certificate verification disabled",
    severity: "high",
    category: "tls-verification",
    cwe: "CWE-295",
    description:
      "rejectUnauthorized: false disables TLS certificate validation, breaking the trust chain and exposing the connection to MitM attacks. Common when AI assistants suggest 'fixes' for self-signed cert errors — the right fix is to add the CA to the trust store, not to disable validation.",
    languages: ["js"],
    regex: /\brejectUnauthorized\s*:\s*false\b/g,
  },
  {
    id: "py-tls-verify-disabled",
    name: "TLS verification disabled in HTTP client",
    severity: "high",
    category: "tls-verification",
    cwe: "CWE-295",
    description:
      "Passing verify=False to requests/httpx skips certificate validation and exposes the call to MitM. Configure the CA bundle (REQUESTS_CA_BUNDLE / verify='/path/to/ca.pem') instead.",
    languages: ["python"],
    regex: /\b(?:requests|httpx)\.(?:get|post|put|delete|patch|head|request)\s*\([^)]*\bverify\s*=\s*False\b/g,
  },

  // ─────────────────────────  Insecure cookie config  ───────────────────────
  {
    id: "js-cookie-httponly-false",
    name: "Cookie set with httpOnly: false in auth context",
    severity: "high",
    category: "insecure-cookie",
    cwe: "CWE-1004",
    description:
      "Auth/session cookies should always be HttpOnly so client-side scripts can't read them, eliminating cookie-stealing XSS. AI-generated cookie middleware often omits httpOnly or sets it to false to enable client JS reads.",
    languages: ["js"],
    regex: /\bhttpOnly\s*:\s*false\b/g,
  },
  {
    id: "js-cookie-insecure-prod",
    name: "Session cookie with secure: false",
    severity: "medium",
    category: "insecure-cookie",
    cwe: "CWE-614",
    description:
      "secure: false sends the cookie over plain HTTP, making it interceptable on any shared network. Production session cookies must be `secure: true` so they ride only over TLS.",
    languages: ["js"],
    regex:
      /\b(?:session|cookie)\s*\([\s\S]{0,200}?\bsecure\s*:\s*false\b/gi,
  },

  // ─────────────────────────  Weak password hashing  ────────────────────────
  {
    id: "js-bcrypt-low-rounds",
    name: "bcrypt cost factor below 10",
    severity: "medium",
    category: "weak-crypto",
    cwe: "CWE-916",
    description:
      "bcrypt.hash(..., N) with N below 10 makes offline password cracking cheap. Use at least 10 (current OWASP recommendation is 12+). AI-generated examples often default to 4 or 8 for 'speed'.",
    languages: ["js"],
    regex: /\bbcrypt\.(?:hash|hashSync)\s*\([^,]+,\s*[1-9]\s*[,)]/g,
  },

  // ─────────────────────────  Hardcoded / leaked credentials  ───────────────
  {
    id: "js-env-fallback-secret",
    name: "process.env fallback to a hardcoded secret-shaped string",
    severity: "high",
    category: "hardcoded-creds",
    cwe: "CWE-798",
    description:
      "`process.env.FOO || \"sk-...\"` makes the fallback string a hardcoded credential committed to the repo. AI assistants frequently emit this pattern so the snippet 'works' without an env var — and it then ships to prod.",
    languages: ["js"],
    regex:
      /\bprocess\.env\.[A-Z0-9_]+\s*(?:\|\||\?\?)\s*["'`](?:sk-[A-Za-z0-9_-]{20,}|sk_(?:live|test)_[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|xox[baprs]-[0-9]{6,})/g,
  },
  {
    id: "js-next-public-secret-name",
    name: "NEXT_PUBLIC_ env var with a secret-like name",
    severity: "high",
    category: "hardcoded-creds",
    cwe: "CWE-200",
    description:
      "Any env var prefixed NEXT_PUBLIC_ is inlined into the client bundle at build time and visible to every visitor. Naming one *SECRET*, *KEY*, *TOKEN*, *PASSWORD* (other than well-known public keys like Stripe pk_*) almost certainly leaks a credential. AI assistants confuse client-side and server-side env in Next.js routinely.",
    languages: ["js"],
    regex:
      /\bprocess\.env\.NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|PRIVATE|API_KEY|AUTH_TOKEN|PASSWORD|SERVICE_ROLE|ACCESS_TOKEN)[A-Z0-9_]*\b/g,
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

function maskLineForDisplay(line: string): string {
  const trimmed = line.trim()
  return trimmed.length > 200 ? trimmed.slice(0, 200) + "…" : trimmed
}

/**
 * Scan a single file's text for code-level vulnerabilities. Designed to run
 * alongside the secret scanner on the same content so we pay only one blob
 * fetch per file.
 */
export function findCodeVulns(
  content: string,
  filePath: string,
  likelyTestFixture: boolean,
): CodeFinding[] {
  const language = detectLanguage(filePath)
  if (!language) return []

  const findings: CodeFinding[] = []
  const lines = content.split("\n")

  for (const rule of CODE_RULES) {
    if (!rule.languages.includes(language) && !rule.languages.includes("any")) {
      continue
    }
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i]
      // Skip trivially-commented lines to reduce noise.
      const trimmed = line.trimStart()
      if (
        trimmed.startsWith("//") ||
        trimmed.startsWith("*") ||
        trimmed.startsWith("#")
      ) {
        continue
      }
      rule.regex.lastIndex = 0
      if (!rule.regex.test(line)) continue
      if (rule.suppress?.(line)) continue
      findings.push({
        ruleId: rule.id,
        ruleName: rule.name,
        severity: rule.severity,
        category: rule.category,
        description: rule.description,
        cwe: rule.cwe,
        filePath,
        lineNumber: i + 1,
        lineContent: maskLineForDisplay(line),
        likelyTestFixture,
      })
    }
  }

  return findings
}
