import { minimatch } from "minimatch";
import type { AnyFinding } from "@/lib/risk";

export interface FindingLike {
  kind?: string;
  data?: {
    patternId?: string | null;
    source?: string | null;
    ruleId?: string | null;
    cwe?: string | number | null;
    category?: string | null;
    package?: string | null;
    ghsa?: string | null;
    filePath?: string | null;
    kind?: string | null;
  };
}
export type Suppression = {
  pathGlob: string;
  ruleGlob?: string;
  reason?: string;
  expires?: string; // ISO date YYYY-MM-DD
  sourceLine: number; // 1-indexed line in .repoguardignore
};

export type SuppressedFinding = {
  finding: AnyFinding;
  suppression: Suppression;
  expired: boolean;
};

export type SuppressionResult = {
  kept: AnyFinding[]; // findings que NÃO foram suprimidos
  suppressed: SuppressedFinding[];
  expiredSuppressionsCount: number;
};

const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function isValidIsoDate(s: string): boolean {
  if (!ISO_DATE_RE.test(s)) return false;
  const d = new Date(s + "T00:00:00Z");
  return !Number.isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s;
}

function extractModifiers(rest: string): Record<string, string> {
  const out: Record<string, string> = {};
  // Quoted form first: [key="value with spaces"]
  const quoted = /\[(\w+)="([^"]*)"\]/g;
  // Unquoted form: [key=token-without-spaces]
  const unquoted = /\[(\w+)=([^\s\]]+)\]/g;

  let m: RegExpExecArray | null;
  while ((m = quoted.exec(rest)) !== null) {
    out[m[1]] = m[2];
  }
  // Mask quoted matches so unquoted regex doesn't double-pick them.
  // (replace() resets the regex's lastIndex on its own, no manual reset needed.)
  const masked = rest.replace(quoted, (full) => " ".repeat(full.length));

  while ((m = unquoted.exec(masked)) !== null) {
    if (out[m[1]] === undefined) {
      out[m[1]] = m[2];
    }
  }
  return out;
}

export function parseSuppressions(content: string): Suppression[] {
  const out: Suppression[] = [];
  const lines = content.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const lineNumber = i + 1;
    const trimmed = lines[i].trim();
    if (trimmed.length === 0) continue;
    if (trimmed.startsWith("#")) continue;

    // pathGlob = first token until first space, tab, or '['.
    // Known limitation (MVP wontfix): a pathGlob containing a glob char-class
    // like `tests/file[123].js` will be cut at the `[` and the rest treated as
    // a modifier. Workaround for now: avoid char-classes in pathGlob.
    let cutIdx = trimmed.length;
    for (let j = 0; j < trimmed.length; j++) {
      const c = trimmed[j];
      if (c === " " || c === "\t" || c === "[") {
        cutIdx = j;
        break;
      }
    }
    const pathGlob = trimmed.slice(0, cutIdx);
    if (pathGlob.length === 0) continue;

    const rest = trimmed.slice(cutIdx);
    const mods = extractModifiers(rest);

    const suppression: Suppression = {
      pathGlob,
      sourceLine: lineNumber,
    };
    if (mods.rule) suppression.ruleGlob = mods.rule;
    if (mods.reason) suppression.reason = mods.reason;
    if (mods.expires && isValidIsoDate(mods.expires)) {
      suppression.expires = mods.expires;
    }

    out.push(suppression);
  }

  return out;
}

export function findRuleIdForFinding(finding: FindingLike): string {
  const kind = finding?.kind;
  const data = finding?.data ?? {};

  switch (kind) {
    case "secret": {
      const patternId = String(data.patternId ?? "unknown");
      if (patternId.startsWith("entropy-")) return `entropy/${patternId}`;
      if (data.source === "history") return `git-history/${patternId}`;
      return `secret/${patternId}`;
    }
    case "code":
      return `code/${data.ruleId ?? "unknown"}`;
    case "iac":
      return `iac/${data.ruleId ?? "unknown"}`;
    case "sensitive-file":
      return `sensitive-file/${data.kind ?? "unknown"}`;
    // Deps are path-light; the typical user writes `* [rule=dependency/<pkg>]`.
    case "dependency":
      return `dependency/${data.package ?? "unknown"}`;
    // License findings suppress per-package, same as deps.
    case "license":
      return `license/${data.package ?? "unknown"}`;
    default:
      return "unknown/unknown";
  }
}

export function getFindingPath(finding: FindingLike): string {
  const kind = finding?.kind;
  const data = finding?.data ?? {};
  if (kind === "dependency") return data.source ?? "package.json";
  if (kind === "license") return data.source ?? "package-lock.json";
  if (kind === "secret" || kind === "code" || kind === "iac" || kind === "sensitive-file") {
    return data.filePath ?? "";
  }
  return "";
}

const NPM_MANIFESTS = new Set(["package.json", "package-lock.json"]);
const PY_MANIFESTS = new Set(["requirements.txt", "pyproject.toml", "Pipfile"]);

// Dep findings can carry a `source` of either the human-edited manifest
// (package.json, requirements.txt) or a lockfile / alternate manifest
// (package-lock.json, pyproject.toml, Pipfile). Users almost always
// suppress per-package without caring which file the bad version lives
// in, and the comment in findRuleIdForFinding even recommends
// `* [rule=dependency/<pkg>]`. To make the more natural pathGlob
// `package.json [rule=dependency/<pkg>]` work for transitives too, we
// match against all manifests in the same ecosystem.
export function getFindingPaths(finding: FindingLike): string[] {
  const kind = finding?.kind;
  const data = finding?.data ?? {};

  if (kind !== "dependency" && kind !== "license") return [getFindingPath(finding)];

  const source = data.source ?? (kind === "license" ? "package-lock.json" : "package.json");
  if (NPM_MANIFESTS.has(source)) return Array.from(NPM_MANIFESTS);
  if (PY_MANIFESTS.has(source)) return Array.from(PY_MANIFESTS);
  return [source];
}

export function findAlternateRuleIds(finding: FindingLike): string[] {
  const primary = findRuleIdForFinding(finding);
  const kind = finding?.kind;
  const data = finding?.data ?? {};

  switch (kind) {
    case "code": {
      const ids = [primary];
      if (data.cwe != null) {
        ids.push(`code/${String(data.cwe).toLowerCase()}`);
      }
      return ids;
    }
    case "iac": {
      const ids = [primary];
      if (data.category) ids.push(`iac/${data.category}`);
      return ids;
    }
    case "dependency": {
      const ids = [primary];
      if (data.ghsa != null) {
        ids.push(`dependency/${data.package}/${data.ghsa}`);
        ids.push(`dependency/${data.ghsa}`);
      }
      return ids;
    }
    default:
      return [primary];
  }
}

function hasGlobChars(s: string): boolean {
  return s.includes("*") || s.includes("?") || s.includes("[");
}

function specificityScore(s: Suppression): number {
  return (s.ruleGlob ? 2 : 0) + (hasGlobChars(s.pathGlob) ? 0 : 1);
}

function isExpired(suppression: Suppression, now: Date): boolean {
  if (!suppression.expires) return false;
  // End-of-day UTC: "expires=2025-12-31" remains valid through that whole day.
  const parsed = new Date(suppression.expires + "T23:59:59Z");
  if (Number.isNaN(parsed.getTime())) return false;
  return now > parsed;
}

export function applySuppressions(
  findings: AnyFinding[],
  suppressions: Suppression[],
  now: Date = new Date(),
): SuppressionResult {
  // Stable sort by specificity (DESC), tiebreaker = original order.
  const ordered = suppressions
    .map((s, idx) => ({ s, idx, score: specificityScore(s) }))
    .sort((a, b) => (b.score - a.score) || (a.idx - b.idx))
    .map((x) => x.s);

  const kept: AnyFinding[] = [];
  const suppressed: SuppressedFinding[] = [];
  const expiredSuppressionLines = new Set<number>();

  for (const finding of findings) {
    const paths = getFindingPaths(finding);
    const ruleIds = findAlternateRuleIds(finding);

    let matched: Suppression | null = null;
    for (const s of ordered) {
      const pathHit = paths.some((p) => minimatch(p, s.pathGlob, { dot: true }));
      if (!pathHit) continue;
      if (s.ruleGlob !== undefined) {
        const ruleHit = ruleIds.some((rid) => minimatch(rid, s.ruleGlob!, { dot: true }));
        if (!ruleHit) continue;
      }
      matched = s;
      break;
    }

    if (matched) {
      const expired = isExpired(matched, now);
      if (expired) expiredSuppressionLines.add(matched.sourceLine);
      suppressed.push({ finding, suppression: matched, expired });
    } else {
      kept.push(finding);
    }
  }

  return {
    kept,
    suppressed,
    expiredSuppressionsCount: expiredSuppressionLines.size,
  };
}
