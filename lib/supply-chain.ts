// RepoGuard - Supply Chain Scanner
// Foundation lib (E1) + typosquatting (E2) + postinstall npm (E3) + postinstall python (E4) wired.
// Detectors:
//   - lib/supply-chain-typo.ts    (E2: typosquatting) [WIRED]
//   - lib/supply-chain-pi-npm.ts  (E3: postinstall content npm) [WIRED]
//   - lib/supply-chain-pi-py.ts   (E4: postinstall content python) [WIRED]

import { detectTyposquatting } from "./supply-chain-typo";
import { detectPostInstallNpm } from "./supply-chain-pi-npm";
import { detectPostInstallPython } from "./supply-chain-pi-py";

export type SupplyChainSeverity = "HIGH" | "MEDIUM" | "LOW";

export type SupplyChainCategoryId = "typosquatting" | "postinstall";

export type SupplyChainLevel =
  | "excellent"
  | "good"
  | "needs-attention"
  | "critical";

export interface SupplyChainFinding {
  id: string;
  categoryId: SupplyChainCategoryId;
  severity: SupplyChainSeverity;
  package?: string;
  file: string;
  line?: number;
  pattern: string;
  message: string;
  evidence: string;
}

export interface SupplyChainCategoryBreakdown {
  id: SupplyChainCategoryId;
  score: number;
  findingCount: number;
  severityCounts: { HIGH: number; MEDIUM: number; LOW: number };
}

export interface SupplyChainScanned {
  packageJsonCount: number;
  setupPyCount: number;
  pyprojectCount: number;
  depsAnalyzed: number;
}

export interface SupplyChainResult {
  score: number;
  level: SupplyChainLevel;
  categories: SupplyChainCategoryBreakdown[];
  findings: SupplyChainFinding[];
  scanned: SupplyChainScanned;
}

const PENALTY: Record<SupplyChainSeverity, number> = {
  HIGH: 25,
  MEDIUM: 10,
  LOW: 3,
};

export function computeScore(findings: SupplyChainFinding[]): number {
  const total = findings.reduce((sum, f) => sum + PENALTY[f.severity], 0);
  return Math.max(0, 100 - total);
}

export function levelFromScore(score: number): SupplyChainLevel {
  if (score >= 90) return "excellent";
  if (score >= 70) return "good";
  if (score >= 50) return "needs-attention";
  return "critical";
}

export function buildCategoryBreakdown(
  categoryId: SupplyChainCategoryId,
  findings: SupplyChainFinding[],
): SupplyChainCategoryBreakdown {
  const ofCategory = findings.filter((f) => f.categoryId === categoryId);
  return {
    id: categoryId,
    score: computeScore(ofCategory),
    findingCount: ofCategory.length,
    severityCounts: {
      HIGH: ofCategory.filter((f) => f.severity === "HIGH").length,
      MEDIUM: ofCategory.filter((f) => f.severity === "MEDIUM").length,
      LOW: ofCategory.filter((f) => f.severity === "LOW").length,
    },
  };
}

export interface SupplyChainScanInput {
  files: Map<string, string>;
}

function isManifest(path: string, manifest: string): boolean {
  const lower = path.toLowerCase();
  return lower === manifest || lower.endsWith("/" + manifest);
}

export async function scanSupplyChain(
  input: SupplyChainScanInput,
): Promise<SupplyChainResult> {
  const findings: SupplyChainFinding[] = [];

  let packageJsonCount = 0;
  let setupPyCount = 0;
  let pyprojectCount = 0;
  let depsAnalyzed = 0;

  for (const [path] of input.files) {
    if (isManifest(path, "package.json")) packageJsonCount++;
    if (isManifest(path, "setup.py")) setupPyCount++;
    if (isManifest(path, "pyproject.toml")) pyprojectCount++;
  }

  // E2: typosquatting detector
  const typoResult = await detectTyposquatting(input.files);
  findings.push(...typoResult.findings);
  depsAnalyzed += typoResult.depsAnalyzed;

  // E3: postinstall npm content analysis
  const piNpmResult = await detectPostInstallNpm(input.files);
  findings.push(...piNpmResult.findings);

  // E4: postinstall python content analysis
  const piPyResult = await detectPostInstallPython(input.files);
  findings.push(...piPyResult.findings);

  const score = computeScore(findings);
  const level = levelFromScore(score);

  return {
    score,
    level,
    categories: [
      buildCategoryBreakdown("typosquatting", findings),
      buildCategoryBreakdown("postinstall", findings),
    ],
    findings,
    scanned: {
      packageJsonCount,
      setupPyCount,
      pyprojectCount,
      depsAnalyzed,
    },
  };
}

export const __testHelpers = {
  computeScore,
  levelFromScore,
  buildCategoryBreakdown,
  isManifest,
};
