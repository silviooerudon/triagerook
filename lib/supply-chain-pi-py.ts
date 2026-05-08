// RepoGuard - Supply Chain Scanner: Postinstall Content Analysis (python) - E4
// Analyzes the CONTENT of setuptools cmdclass overrides and pyproject.toml
// build hooks for malicious patterns, beyond the IaC scanner's binary "exists"
// signal. Mirrors lib/supply-chain-pi-npm.ts shape and conventions.

import type {
  SupplyChainFinding,
  SupplyChainSeverity,
} from "./supply-chain";

// setuptools.command.* parent classes whose subclasses run automatically
// during install / build / packaging. A class extending one of these in
// setup.py is a "hook" body to scan.
const HOOK_PARENTS = [
  "install",
  "develop",
  "build_py",
  "build_ext",
  "build_clib",
  "build_scripts",
  "sdist",
  "bdist_egg",
  "bdist_wheel",
  "egg_info",
  "install_lib",
  "install_scripts",
  "install_data",
  "install_headers",
  "test",
];

// ---------- Regex constants ----------

// subprocess/os.system call whose first string arg pipes curl/wget into a shell.
// Matches: subprocess.call("curl URL | bash", ...), os.system("wget -O- URL | sh"),
// subprocess.run("curl ... | bash", shell=True), etc.
const RE_PY_PIPE_TO_SHELL =
  /\b(?:subprocess\.[a-zA-Z_]+|os\.(?:system|popen))\s*\(\s*[fr]?["'][^"']*\b(?:curl|wget)\b[^"']*\|\s*(?:ba)?sh\b/i;

// Python eval/exec call.
const RE_PY_EXEC = /\b(?:eval|exec)\s*\(/;

// Base64 / codec decoding: base64.b64decode(...), codecs.decode(...).
const RE_PY_DECODE = /\b(?:base64\.b64decode|codecs\.decode)\s*\(/;

// os.environ access (read or write, dict-style or .get()).
const RE_PY_OSENV = /\bos\.environ(?:\b|\.)/;

// Python network calls: urllib, requests, socket, http.client, httpx, urllib3, aiohttp.
const RE_PY_NETWORK =
  /\b(?:urllib(?:\.\w+)*\.urlopen|urllib\.request\.\w+|requests\.(?:get|post|put|delete|request|head|patch)|socket\.socket|httpx?\.(?:get|post|put|delete|request|head|patch|stream|Client|AsyncClient)|http\.client\.\w+|urllib3\.\w+|aiohttp\.\w+)/;

// Shell-tool network call without explicit pipe context: subprocess/os.system
// invoking curl or wget (covers MEDIUM where there's no |bash).
const RE_PY_SHELL_NET =
  /\b(?:subprocess\.[a-zA-Z_]+|os\.(?:system|popen))\s*\(\s*[fr]?["'][^"']*\b(?:curl|wget)\b/i;

// Single subprocess/os.system call site (used for command-chain counting).
const RE_PY_SHELL_CALL = /\b(?:subprocess\.[a-zA-Z_]+|os\.(?:system|popen))\s*\(/g;

// ---------- Pattern definitions ----------

interface PyPattern {
  id: string;
  severity: SupplyChainSeverity;
  pattern: string;
  test: (body: string) => boolean;
  message: string;
}

const HIGH_PATTERNS: PyPattern[] = [
  {
    id: "pipe-to-shell",
    severity: "HIGH",
    pattern: "pipe-to-shell",
    test: (s) => RE_PY_PIPE_TO_SHELL.test(s),
    message:
      "Pipe-to-shell pattern (curl|bash via subprocess/os.system) - downloads and executes remote code at install time",
  },
  {
    id: "decode-and-exec",
    severity: "HIGH",
    pattern: "decode-and-exec",
    test: (s) => RE_PY_EXEC.test(s) && RE_PY_DECODE.test(s),
    message:
      "Decode-and-execute pattern (eval/exec combined with base64/codec decode) - obfuscated payload",
  },
  {
    id: "env-exfil",
    severity: "HIGH",
    pattern: "env-exfil",
    test: (s) => RE_PY_OSENV.test(s) && RE_PY_NETWORK.test(s),
    message:
      "Possible env exfiltration (os.environ access combined with network call in same hook)",
  },
];

const MEDIUM_PATTERNS: PyPattern[] = [
  {
    id: "network-in-hook",
    severity: "MEDIUM",
    pattern: "network-in-hook",
    test: (s) => RE_PY_NETWORK.test(s) || RE_PY_SHELL_NET.test(s),
    message:
      "Network call in build hook (downloads or contacts remote endpoint during install/build)",
  },
];

const LOW_PATTERNS: PyPattern[] = [
  {
    id: "command-chain",
    severity: "LOW",
    pattern: "command-chain",
    test: (s) => {
      const matches = s.match(RE_PY_SHELL_CALL);
      return (matches?.length ?? 0) >= 4;
    },
    message:
      "Build hook chains 4+ subprocess/os.system calls (unusual complexity for an install/build script)",
  },
];

// ---------- Helpers ----------

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n) + "...";
}

function findingId(file: string, hook: string, patternId: string): string {
  const safeFile = file.replace(/[^a-zA-Z0-9]/g, "_");
  return `pi-py-${safeFile}-${hook}-${patternId}`;
}

// Lines we skip when picking an evidence preview: structural lines
// (def/class/decorator) and noise (comments, docstring openers) - we want
// the first real statement so the preview shows what triggered the pattern.
const PREVIEW_SKIP =
  /^(?:def\s|class\s|@|#|"""|''')/;

function makeFinding(
  pattern: PyPattern,
  hook: string,
  body: string,
  file: string,
): SupplyChainFinding {
  const trimmedLines = body
    .split("\n")
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
  const preview =
    trimmedLines.find((l) => !PREVIEW_SKIP.test(l)) ??
    trimmedLines[0] ??
    "";
  return {
    id: findingId(file, hook, pattern.id),
    categoryId: "postinstall",
    severity: pattern.severity,
    file,
    pattern: pattern.pattern,
    message: pattern.message,
    evidence: `hook=${hook}: ${truncate(preview, 120)}`,
  };
}

interface ExtractedHook {
  hook: string;
  body: string;
}

// Parse setup.py line-by-line: every class declaration whose parent list
// includes a known setuptools command parent (install, develop, build_py, ...)
// becomes a hook. Body = lines from the declaration up to (but not including)
// the next top-level definition (lines starting at column 0 with a letter,
// underscore or @).
function extractHooksFromSetupPy(content: string): ExtractedHook[] {
  const lines = content.split("\n");
  const out: ExtractedHook[] = [];
  const parentRe = new RegExp(`\\b(${HOOK_PARENTS.join("|")})\\b`);

  let i = 0;
  while (i < lines.length) {
    const decl = lines[i].match(/^class\s+\w+\s*\(([^)]*)\)\s*:/);
    if (decl) {
      const parents = decl[1];
      const hookMatch = parents.match(parentRe);
      if (hookMatch) {
        const hook = hookMatch[1];
        let body = "";
        let j = i + 1;
        while (j < lines.length) {
          const line = lines[j];
          // Top-level non-empty line starting with a letter/underscore/@
          // ends the class body (next class, def, decorator, assignment,
          // import, or call like setup(...)).
          if (line.length > 0 && /^[A-Za-z_@]/.test(line)) {
            break;
          }
          body += line + "\n";
          j++;
        }
        out.push({ hook, body });
        i = j;
        continue;
      }
    }
    i++;
  }
  return out;
}

// pyproject.toml: TOML, not Python. Treat raw content as a single "pyproject"
// hook so suspicious inline strings (build-system requires git+https://...,
// custom build backend pointing at remote code, etc.) are still flagged.
// Most legitimate pyproject.toml files match no pattern.
function extractHooksFromPyproject(content: string): ExtractedHook[] {
  if (content.trim().length === 0) return [];
  return [{ hook: "pyproject", body: content }];
}

function detectInHooks(
  hooks: ExtractedHook[],
  file: string,
): SupplyChainFinding[] {
  const findings: SupplyChainFinding[] = [];

  for (const { hook, body } of hooks) {
    if (body.trim().length === 0) continue;

    let highHit = false;
    for (const p of HIGH_PATTERNS) {
      if (p.test(body)) {
        findings.push(makeFinding(p, hook, body, file));
        highHit = true;
      }
    }

    if (!highHit) {
      for (const p of MEDIUM_PATTERNS) {
        if (p.test(body)) {
          findings.push(makeFinding(p, hook, body, file));
        }
      }
    }

    for (const p of LOW_PATTERNS) {
      if (p.test(body)) {
        findings.push(makeFinding(p, hook, body, file));
      }
    }
  }

  return findings;
}

function isSetupPyPath(path: string): boolean {
  if (path.includes("node_modules/")) return false;
  const lower = path.toLowerCase();
  return lower === "setup.py" || lower.endsWith("/setup.py");
}

function isPyprojectPath(path: string): boolean {
  if (path.includes("node_modules/")) return false;
  const lower = path.toLowerCase();
  return lower === "pyproject.toml" || lower.endsWith("/pyproject.toml");
}

// ---------- Public detector ----------

export interface PiPyScanResult {
  findings: SupplyChainFinding[];
}

export async function detectPostInstallPython(
  files: Map<string, string>,
): Promise<PiPyScanResult> {
  const findings: SupplyChainFinding[] = [];

  for (const [path, content] of files) {
    if (isSetupPyPath(path)) {
      const hooks = extractHooksFromSetupPy(content);
      findings.push(...detectInHooks(hooks, path));
    } else if (isPyprojectPath(path)) {
      const hooks = extractHooksFromPyproject(content);
      findings.push(...detectInHooks(hooks, path));
    }
  }

  return { findings };
}

export const __testAnalyzePostInstallPy = {
  HIGH_PATTERNS,
  MEDIUM_PATTERNS,
  LOW_PATTERNS,
  detectInHooks,
  extractHooksFromSetupPy,
  extractHooksFromPyproject,
  isSetupPyPath,
  isPyprojectPath,
};
