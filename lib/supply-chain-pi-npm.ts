// TriageRook - Supply Chain Scanner: Postinstall Content Analysis (npm) - E3
// Analyzes the CONTENT of npm install lifecycle scripts in package.json
// for malicious patterns, beyond the IaC scanner's binary "exists" signal.

import type {
  SupplyChainFinding,
  SupplyChainSeverity,
} from "./supply-chain";

// npm lifecycle hooks that run automatically during install / pack / publish.
const HOOKS = [
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "prepublish",
  "prepublishOnly",
  "prerestart",
  "prestart",
  "predev",
];

// ---------- Regex constants ----------

// curl/wget piped into a shell: "curl URL | bash", "wget -O- URL | sh", etc.
const RE_PIPE_TO_SHELL = /\b(?:curl|wget)\b[^|;]*\|\s*(?:ba)?sh\b/i;

// JavaScript eval call.
const RE_EVAL_CALL = /\beval\s*\(/i;

// Base64 decoding via atob() or Buffer.from(..., 'base64').
const RE_BASE64_DECODE =
  /(\batob\s*\(|\bBuffer\.from\s*\([^)]*['"]base64['"])/i;

// Access to process.env (env vars).
const RE_PROCESS_ENV = /\bprocess\.env\b/i;

// Network calls in JavaScript code: fetch(), http.get/request, axios, require('https').
const RE_NETWORK_CODE =
  /(\bfetch\s*\(|\bhttps?\.(?:get|request|post|put|delete)\s*\(|\baxios\s*[\(.]|\brequire\s*\(\s*['"]https?['"])/i;

// Shell-level network tools (curl, wget) without piping context.
const RE_SHELL_NETWORK = /\b(?:wget|curl)\b/i;

// Dynamic require/import of remote URL: require("https://evil.com/x.js").
const RE_DYNAMIC_REQUIRE_HTTP = /\brequire\s*\(\s*['"]https?:/i;

// ---------- Pattern definitions ----------

interface NpmPattern {
  id: string;
  severity: SupplyChainSeverity;
  pattern: string;
  test: (script: string) => boolean;
  message: string;
}

const HIGH_PATTERNS: NpmPattern[] = [
  {
    id: "pipe-to-shell",
    severity: "HIGH",
    pattern: "pipe-to-shell",
    test: (s) => RE_PIPE_TO_SHELL.test(s),
    message:
      "Pipe-to-shell pattern (curl|bash) - downloads and executes remote code at install time",
  },
  {
    id: "decode-and-exec",
    severity: "HIGH",
    pattern: "decode-and-exec",
    test: (s) => RE_EVAL_CALL.test(s) && RE_BASE64_DECODE.test(s),
    message:
      "Decode-and-execute pattern (eval combined with base64 decode) - obfuscated payload",
  },
  {
    id: "env-exfil",
    severity: "HIGH",
    pattern: "env-exfil",
    test: (s) => RE_PROCESS_ENV.test(s) && RE_NETWORK_CODE.test(s),
    message:
      "Possible env exfiltration (process.env access combined with network call in same hook)",
  },
];

const MEDIUM_PATTERNS: NpmPattern[] = [
  {
    id: "network-in-hook",
    severity: "MEDIUM",
    pattern: "network-in-hook",
    test: (s) =>
      RE_SHELL_NETWORK.test(s) ||
      RE_NETWORK_CODE.test(s) ||
      RE_DYNAMIC_REQUIRE_HTTP.test(s),
    message:
      "Network call in install hook (downloads or contacts remote endpoint during install)",
  },
];

const LOW_PATTERNS: NpmPattern[] = [
  {
    id: "command-chain",
    severity: "LOW",
    pattern: "command-chain",
    test: (s) => {
      const parts = s.split(/\s*(?:&&|\|\||;)\s*/);
      let cmds = 0;
      for (const p of parts) {
        // Count segments that look like real shell commands
        // (start with a letter, followed by word chars).
        if (/^[a-zA-Z][a-zA-Z0-9_\-]*\b/.test(p.trim())) cmds++;
      }
      return cmds >= 4;
    },
    message:
      "Install hook chains 4+ commands (unusual complexity for an install script)",
  },
];

// ---------- Helpers ----------

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n) + "...";
}

function findingId(file: string, hook: string, patternId: string): string {
  const safeFile = file.replace(/[^a-zA-Z0-9]/g, "_");
  return `pi-npm-${safeFile}-${hook}-${patternId}`;
}

function makeFinding(
  pattern: NpmPattern,
  hook: string,
  script: string,
  file: string,
): SupplyChainFinding {
  return {
    id: findingId(file, hook, pattern.id),
    categoryId: "postinstall",
    severity: pattern.severity,
    file,
    pattern: pattern.pattern,
    message: pattern.message,
    evidence: `hook=${hook}: ${truncate(script, 120)}`,
  };
}

// Evaluate all patterns against the scripts of one package.json.
// Anti-duplication rule: if any HIGH pattern fires for a hook, skip MEDIUM
// for the same hook (a HIGH pipe-to-shell already covers the network signal
// that MEDIUM network-in-hook would redundantly flag). LOW is orthogonal
// and always evaluated.
function detectInScripts(
  scripts: Record<string, string>,
  file: string,
): SupplyChainFinding[] {
  const findings: SupplyChainFinding[] = [];

  for (const hook of HOOKS) {
    const script = scripts[hook];
    if (typeof script !== "string" || script.trim().length === 0) continue;

    let highHit = false;
    for (const p of HIGH_PATTERNS) {
      if (p.test(script)) {
        findings.push(makeFinding(p, hook, script, file));
        highHit = true;
      }
    }

    if (!highHit) {
      for (const p of MEDIUM_PATTERNS) {
        if (p.test(script)) {
          findings.push(makeFinding(p, hook, script, file));
        }
      }
    }

    for (const p of LOW_PATTERNS) {
      if (p.test(script)) {
        findings.push(makeFinding(p, hook, script, file));
      }
    }
  }

  return findings;
}

function isPackageJsonPath(path: string): boolean {
  if (path.includes("node_modules/")) return false;
  const lower = path.toLowerCase();
  return lower === "package.json" || lower.endsWith("/package.json");
}

// ---------- Public detector ----------

export interface PiNpmScanResult {
  findings: SupplyChainFinding[];
}

export async function detectPostInstallNpm(
  files: Map<string, string>,
): Promise<PiNpmScanResult> {
  const findings: SupplyChainFinding[] = [];

  for (const [path, content] of files) {
    if (!isPackageJsonPath(path)) continue;
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(content) as Record<string, unknown>;
    } catch {
      continue;
    }
    const scripts = parsed.scripts;
    if (!scripts || typeof scripts !== "object") continue;
    findings.push(
      ...detectInScripts(scripts as Record<string, string>, path),
    );
  }

  return { findings };
}

export const __testAnalyzePostInstall = {
  HIGH_PATTERNS,
  MEDIUM_PATTERNS,
  LOW_PATTERNS,
  detectInScripts,
  isPackageJsonPath,
};
