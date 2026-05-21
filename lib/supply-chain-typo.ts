// TriageRook - Supply Chain Scanner: Typosquatting Detector (E2)
// Detects packages with names suspiciously close to popular packages.
//
// Strategy:
//   - Damerau-Levenshtein edit distance with cap=2 and length-diff early-exit
//   - case-fold collision (distance 0 but case differs) -> HIGH
//   - distance 1: HIGH if target rank <= 100, MEDIUM if <= 1000, LOW otherwise
//   - distance 2 with shared 3-char prefix: MEDIUM if rank <= 100, LOW otherwise
//
// Skips:
//   - scoped packages (@scope/name) - namespace ownership precludes typosquat
//   - deps whose lowercased name is itself in the popular list with matching case

import type {
  SupplyChainFinding,
  SupplyChainSeverity,
} from "./supply-chain";

import popularNpmRaw from "./data/popular-npm.json";
import popularPypiRaw from "./data/popular-pypi.json";

interface PopularPackage {
  name: string;
  rank: number;
}

interface PopularList {
  meta: { ecosystem: string; count: number; [k: string]: unknown };
  packages: PopularPackage[];
}

const popularNpm = popularNpmRaw as PopularList;
const popularPypi = popularPypiRaw as PopularList;

const NPM_NAME_SET = new Set(
  popularNpm.packages.map((p) => p.name.toLowerCase()),
);
const PYPI_NAME_SET = new Set(
  popularPypi.packages.map((p) => p.name.toLowerCase()),
);
const NPM_BY_LOWER = new Map(
  popularNpm.packages.map((p) => [p.name.toLowerCase(), p]),
);
const PYPI_BY_LOWER = new Map(
  popularPypi.packages.map((p) => [p.name.toLowerCase(), p]),
);

export type Ecosystem = "npm" | "pypi";

// ---------- Damerau-Levenshtein (capped) ----------

// Returns the edit distance, or cap+1 if it would exceed `cap`.
function damerauLevenshtein(a: string, b: string, cap: number): number {
  if (a === b) return 0;
  const la = a.length;
  const lb = b.length;
  if (Math.abs(la - lb) > cap) return cap + 1;

  const d: number[][] = Array.from({ length: la + 1 }, () =>
    new Array(lb + 1).fill(0),
  );
  for (let i = 0; i <= la; i++) d[i][0] = i;
  for (let j = 0; j <= lb; j++) d[0][j] = j;

  for (let i = 1; i <= la; i++) {
    let rowMin = Infinity;
    for (let j = 1; j <= lb; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let v = Math.min(
        d[i - 1][j] + 1,
        d[i][j - 1] + 1,
        d[i - 1][j - 1] + cost,
      );
      if (
        i > 1 &&
        j > 1 &&
        a[i - 1] === b[j - 2] &&
        a[i - 2] === b[j - 1]
      ) {
        v = Math.min(v, d[i - 2][j - 2] + 1);
      }
      d[i][j] = v;
      if (v < rowMin) rowMin = v;
    }
    if (rowMin > cap) return cap + 1;
  }

  return d[la][lb];
}

// ---------- Match logic ----------

type TyposquatPattern =
  | "case-fold"
  | "edit-distance-1"
  | "edit-distance-2-prefix";

interface MatchResult {
  target: PopularPackage;
  distance: number;
  pattern: TyposquatPattern;
}

function sharesPrefix(a: string, b: string, n: number): boolean {
  if (a.length < n || b.length < n) return false;
  return a.slice(0, n) === b.slice(0, n);
}

function severityForDistance1(rank: number): SupplyChainSeverity {
  if (rank <= 100) return "HIGH";
  if (rank <= 1000) return "MEDIUM";
  return "LOW";
}

function severityForDistance2(rank: number): SupplyChainSeverity {
  if (rank <= 100) return "MEDIUM";
  return "LOW";
}

function findBestMatch(
  dep: string,
  ecosystem: Ecosystem,
): MatchResult | null {
  const list =
    ecosystem === "npm" ? popularNpm.packages : popularPypi.packages;
  const ownSet = ecosystem === "npm" ? NPM_NAME_SET : PYPI_NAME_SET;
  const byLower = ecosystem === "npm" ? NPM_BY_LOWER : PYPI_BY_LOWER;

  const depLower = dep.toLowerCase();

  // Case-insensitive exact match: legit, OR case-fold collision.
  if (ownSet.has(depLower)) {
    const target = byLower.get(depLower)!;
    if (dep === target.name) return null;
    return { target, distance: 0, pattern: "case-fold" };
  }

  let best: MatchResult | null = null;

  for (const target of list) {
    const targetLower = target.name.toLowerCase();
    if (Math.abs(depLower.length - targetLower.length) > 2) continue;
    const dist = damerauLevenshtein(depLower, targetLower, 2);
    if (dist > 2) continue;

    let pattern: TyposquatPattern;
    if (dist === 1) {
      pattern = "edit-distance-1";
    } else if (dist === 2 && sharesPrefix(depLower, targetLower, 3)) {
      pattern = "edit-distance-2-prefix";
    } else {
      continue;
    }

    if (
      best === null ||
      dist < best.distance ||
      (dist === best.distance && target.rank < best.target.rank)
    ) {
      best = { target, distance: dist, pattern };
    }
  }

  return best;
}

// ---------- Manifest parsers ----------

function parsePackageJsonDeps(content: string): string[] {
  try {
    const j = JSON.parse(content) as Record<string, unknown>;
    const out: string[] = [];
    const blocks = [
      "dependencies",
      "devDependencies",
      "optionalDependencies",
      "peerDependencies",
    ];
    for (const key of blocks) {
      const block = j[key];
      if (block && typeof block === "object") {
        for (const name of Object.keys(block as Record<string, unknown>)) {
          if (name.startsWith("@")) continue;
          out.push(name);
        }
      }
    }
    return out;
  } catch {
    return [];
  }
}

function parseRequirementsTxt(content: string): string[] {
  const out: string[] = [];
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (line.startsWith("#") || line.startsWith("-")) continue;
    const m = line.match(/^([A-Za-z0-9_.\-]+)/);
    if (m) out.push(m[1]);
  }
  return out;
}

function parsePyprojectDeps(content: string): string[] {
  const out: string[] = [];
  const projIdx = content.indexOf("[project]");
  if (projIdx === -1) return out;
  const afterHeader = projIdx + "[project]".length;
  const after = content.slice(afterHeader);
  const nextSecRel = after.search(/\n\[/);
  const sectionEnd =
    nextSecRel === -1 ? content.length : afterHeader + nextSecRel;
  const block = content.slice(projIdx, sectionEnd);
  const depMatch = block.match(/dependencies\s*=\s*\[([\s\S]*?)\]/);
  if (!depMatch) return out;
  const items = depMatch[1].matchAll(/['"]([A-Za-z0-9_.\-]+)/g);
  for (const it of items) out.push(it[1]);
  return out;
}

function parseSetupPyDeps(content: string): string[] {
  const out: string[] = [];
  const m = content.match(/install_requires\s*=\s*\[([\s\S]*?)\]/);
  if (!m) return out;
  const items = m[1].matchAll(/['"]([A-Za-z0-9_.\-]+)/g);
  for (const it of items) out.push(it[1]);
  return out;
}

// ---------- Public detector ----------

function fileBasename(path: string): string {
  const parts = path.split("/");
  return parts[parts.length - 1].toLowerCase();
}

function findingId(ecosystem: Ecosystem, file: string, pkg: string): string {
  const safeFile = file.replace(/[^a-zA-Z0-9]/g, "_");
  const safePkg = pkg.replace(/[^a-zA-Z0-9]/g, "_");
  return `typo-${ecosystem}-${safeFile}-${safePkg}`;
}

export interface TyposquatScanResult {
  findings: SupplyChainFinding[];
  depsAnalyzed: number;
}

export async function detectTyposquatting(
  files: Map<string, string>,
): Promise<TyposquatScanResult> {
  const findings: SupplyChainFinding[] = [];
  let depsAnalyzed = 0;

  for (const [path, content] of files) {
    const base = fileBasename(path);
    let deps: string[] = [];
    let ecosystem: Ecosystem | null = null;

    if (base === "package.json") {
      deps = parsePackageJsonDeps(content);
      ecosystem = "npm";
    } else if (base === "requirements.txt") {
      deps = parseRequirementsTxt(content);
      ecosystem = "pypi";
    } else if (base === "pyproject.toml") {
      deps = parsePyprojectDeps(content);
      ecosystem = "pypi";
    } else if (base === "setup.py") {
      deps = parseSetupPyDeps(content);
      ecosystem = "pypi";
    }

    if (!ecosystem || deps.length === 0) continue;

    const seen = new Set<string>();
    for (const dep of deps) {
      if (seen.has(dep)) continue;
      seen.add(dep);
      depsAnalyzed += 1;

      const match = findBestMatch(dep, ecosystem);
      if (!match) continue;

      let severity: SupplyChainSeverity;
      if (match.pattern === "case-fold") {
        severity = "HIGH";
      } else if (match.pattern === "edit-distance-1") {
        severity = severityForDistance1(match.target.rank);
      } else {
        severity = severityForDistance2(match.target.rank);
      }

      findings.push({
        id: findingId(ecosystem, path, dep),
        categoryId: "typosquatting",
        severity,
        package: dep,
        file: path,
        pattern: match.pattern,
        message: `Suspected typosquat of '${match.target.name}' (rank #${match.target.rank})`,
        evidence: `${dep} -> ${match.target.name} (distance=${match.distance}, ecosystem=${ecosystem})`,
      });
    }
  }

  return { findings, depsAnalyzed };
}

// Test-only export.
export const __testMatchTyposquat = {
  damerauLevenshtein,
  findBestMatch,
  parsePackageJsonDeps,
  parseRequirementsTxt,
  parsePyprojectDeps,
  parseSetupPyDeps,
  sharesPrefix,
};
