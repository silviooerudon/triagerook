// scripts/smoke-supply-chain.ts
// Smoke test for Supply Chain Scanner.
// Run: npx tsx scripts/smoke-supply-chain.ts [<fixture-dir>]
// Default fixture: ../supply-chain-fixture
//
// E2: typosquatting findings
// E3: postinstall npm content findings
// E4: postinstall python content findings

import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import {
  scanSupplyChain,
  type SupplyChainFinding,
  type SupplyChainSeverity,
} from "../lib/supply-chain";

const DEFAULT_FIXTURE = join(process.cwd(), "..", "supply-chain-fixture");

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  ".next",
  "venv",
  ".venv",
  "__pycache__",
]);

const MAX_FILE_BYTES = 1024 * 1024;

interface ExpectedTypoFinding {
  package: string;
  target: string;
  severity: SupplyChainSeverity;
  pattern: string;
  ecosystem: "npm" | "pypi";
}

interface ExpectedPiFinding {
  hook: string;
  pattern: string;
  severity: SupplyChainSeverity;
}

const EXPECTED_TYPO: ExpectedTypoFinding[] = [
  {
    package: "lodahs",
    target: "lodash",
    severity: "HIGH",
    pattern: "edit-distance-1",
    ecosystem: "npm",
  },
  {
    package: "expres",
    target: "express",
    severity: "HIGH",
    pattern: "edit-distance-1",
    ecosystem: "npm",
  },
  {
    package: "reactt",
    target: "react",
    severity: "HIGH",
    pattern: "edit-distance-1",
    ecosystem: "npm",
  },
  {
    package: "Chalk",
    target: "chalk",
    severity: "HIGH",
    pattern: "case-fold",
    ecosystem: "npm",
  },
  {
    package: "lodashes",
    target: "lodash",
    severity: "MEDIUM",
    pattern: "edit-distance-2-prefix",
    ecosystem: "npm",
  },
  {
    package: "urllib33",
    target: "urllib3",
    severity: "HIGH",
    pattern: "edit-distance-1",
    ecosystem: "pypi",
  },
  {
    package: "reqests",
    target: "requests",
    severity: "HIGH",
    pattern: "edit-distance-1",
    ecosystem: "pypi",
  },
  {
    package: "flas",
    target: "flask",
    severity: "HIGH",
    pattern: "edit-distance-1",
    ecosystem: "pypi",
  },
];

const EXPECTED_PI_NPM: ExpectedPiFinding[] = [
  { hook: "postinstall", pattern: "pipe-to-shell", severity: "HIGH" },
  { hook: "prepare", pattern: "decode-and-exec", severity: "HIGH" },
  { hook: "install", pattern: "env-exfil", severity: "HIGH" },
  { hook: "prepublish", pattern: "network-in-hook", severity: "MEDIUM" },
  { hook: "prerestart", pattern: "command-chain", severity: "LOW" },
];

const EXPECTED_PI_PY: ExpectedPiFinding[] = [
  { hook: "install", pattern: "pipe-to-shell", severity: "HIGH" },
  { hook: "develop", pattern: "decode-and-exec", severity: "HIGH" },
  { hook: "build_py", pattern: "env-exfil", severity: "HIGH" },
  { hook: "sdist", pattern: "network-in-hook", severity: "MEDIUM" },
  { hook: "egg_info", pattern: "command-chain", severity: "LOW" },
];

const FORBIDDEN_TYPO_PACKAGES = [
  "axios",
  "my-internal-pkg",
  "requests",
  "numpy",
  "boto3",
  "django",
];

// npm hooks that should NOT generate any postinstall finding (benign content
// or not part of the install lifecycle).
const FORBIDDEN_PI_NPM_HOOKS = ["preinstall", "build", "test"];

// python hooks that should NOT generate any postinstall finding.
// pyproject = the pyproject.toml file (only deps, no malicious content).
// test = the BenignTest class in setup.py (just a print, no pattern).
const FORBIDDEN_PI_PY_HOOKS = ["pyproject", "test"];

async function loadFiles(root: string): Promise<Map<string, string>> {
  const files = new Map<string, string>();

  async function walk(dir: string): Promise<void> {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const e of entries) {
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        await walk(full);
      } else if (e.isFile()) {
        const s = await stat(full);
        if (s.size > MAX_FILE_BYTES) continue;
        const rel = relative(root, full).split(sep).join("/");
        const content = await readFile(full, "utf-8").catch(() => "");
        files.set(rel, content);
      }
    }
  }

  await walk(root);
  return files;
}

function typoMatches(
  f: SupplyChainFinding,
  exp: ExpectedTypoFinding,
): boolean {
  return (
    f.categoryId === "typosquatting" &&
    f.package === exp.package &&
    f.severity === exp.severity &&
    f.pattern === exp.pattern &&
    f.evidence.includes(`-> ${exp.target}`) &&
    f.evidence.includes(`ecosystem=${exp.ecosystem}`)
  );
}

function piNpmMatches(
  f: SupplyChainFinding,
  exp: ExpectedPiFinding,
): boolean {
  return (
    f.id.startsWith("pi-npm-") &&
    f.severity === exp.severity &&
    f.pattern === exp.pattern &&
    f.evidence.startsWith(`hook=${exp.hook}:`)
  );
}

function piPyMatches(
  f: SupplyChainFinding,
  exp: ExpectedPiFinding,
): boolean {
  return (
    f.id.startsWith("pi-py-") &&
    f.severity === exp.severity &&
    f.pattern === exp.pattern &&
    f.evidence.startsWith(`hook=${exp.hook}:`)
  );
}

async function main(): Promise<void> {
  const fixture = process.argv[2] || DEFAULT_FIXTURE;
  console.log(`Smoke supply chain against fixture: ${fixture}`);

  const files = await loadFiles(fixture);
  console.log(`  loaded ${files.size} files`);

  const result = await scanSupplyChain({ files });

  console.log("");
  console.log(`Score: ${result.score} (${result.level})`);
  console.log(`Findings: ${result.findings.length}`);
  console.log(`Scanned: ${JSON.stringify(result.scanned)}`);
  console.log("");
  console.log("Findings detail:");
  for (const f of result.findings) {
    const head =
      `  [${f.severity}] ${f.categoryId} ${f.pattern}: ${f.message}`;
    if (f.package) {
      console.log(`${head} (pkg=${f.package}, file=${f.file})`);
    } else {
      console.log(`${head} (file=${f.file})`);
      console.log(`        ${f.evidence}`);
    }
  }
  console.log("");

  let allOk = true;

  // 1. Typosquat asserts.
  for (const exp of EXPECTED_TYPO) {
    const found = result.findings.find((f) => typoMatches(f, exp));
    if (!found) {
      console.error(
        `MISSING typo: ${exp.package} -> ${exp.target} ` +
          `${exp.severity} ${exp.pattern} (${exp.ecosystem})`,
      );
      allOk = false;
    }
  }

  // 2. Postinstall npm asserts.
  for (const exp of EXPECTED_PI_NPM) {
    const found = result.findings.find((f) => piNpmMatches(f, exp));
    if (!found) {
      console.error(
        `MISSING pi-npm: hook=${exp.hook} pattern=${exp.pattern} severity=${exp.severity}`,
      );
      allOk = false;
    }
  }

  // 3. Postinstall python asserts.
  for (const exp of EXPECTED_PI_PY) {
    const found = result.findings.find((f) => piPyMatches(f, exp));
    if (!found) {
      console.error(
        `MISSING pi-py: hook=${exp.hook} pattern=${exp.pattern} severity=${exp.severity}`,
      );
      allOk = false;
    }
  }

  // 4. Forbidden typosquat packages must NOT generate findings.
  for (const pkg of FORBIDDEN_TYPO_PACKAGES) {
    const wrong = result.findings.find(
      (f) => f.categoryId === "typosquatting" && f.package === pkg,
    );
    if (wrong) {
      console.error(
        `FALSE POSITIVE typo: '${pkg}' is legit but flagged as ` +
          `${wrong.severity} ${wrong.pattern}`,
      );
      allOk = false;
    }
  }

  // 5. Forbidden npm hooks must NOT generate postinstall findings.
  for (const hook of FORBIDDEN_PI_NPM_HOOKS) {
    const wrong = result.findings.find(
      (f) =>
        f.id.startsWith("pi-npm-") &&
        f.evidence.startsWith(`hook=${hook}:`),
    );
    if (wrong) {
      console.error(
        `FALSE POSITIVE pi-npm: hook=${hook} should not fire ` +
          `(got ${wrong.severity} ${wrong.pattern})`,
      );
      allOk = false;
    }
  }

  // 6. Forbidden python hooks must NOT generate postinstall findings.
  for (const hook of FORBIDDEN_PI_PY_HOOKS) {
    const wrong = result.findings.find(
      (f) =>
        f.id.startsWith("pi-py-") &&
        f.evidence.startsWith(`hook=${hook}:`),
    );
    if (wrong) {
      console.error(
        `FALSE POSITIVE pi-py: hook=${hook} should not fire ` +
          `(got ${wrong.severity} ${wrong.pattern})`,
      );
      allOk = false;
    }
  }

  // 7. Sanity coverage.
  if (result.scanned.depsAnalyzed === 0) {
    console.error("FAIL: depsAnalyzed=0 - typo parsers not extracting deps");
    allOk = false;
  }
  if (result.scanned.setupPyCount === 0) {
    console.error("FAIL: setupPyCount=0 - python fixture not loaded");
    allOk = false;
  }

  if (!allOk) {
    console.error("");
    console.error("E4 FAIL");
    process.exit(1);
  }

  console.log(
    `E4 PASS - ${EXPECTED_TYPO.length} typo + ${EXPECTED_PI_NPM.length} npm pi + ${EXPECTED_PI_PY.length} py pi findings present, ` +
      `${FORBIDDEN_TYPO_PACKAGES.length} legit deps + ${FORBIDDEN_PI_NPM_HOOKS.length} benign npm hooks + ${FORBIDDEN_PI_PY_HOOKS.length} benign py hooks not flagged, ` +
      `${result.scanned.depsAnalyzed} deps analyzed`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
