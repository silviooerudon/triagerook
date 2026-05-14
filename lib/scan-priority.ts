// Path-based scan prioritization. When a repo has more scannable files
// than MAX_FILES_TO_SCAN, the cap is reached before everything has been
// inspected — so the budget is most useful when spent on files that are
// most likely to contain real findings. Source paths get scanned first;
// tests / fixtures / examples / sample apps drop to the back of the
// queue and only get reached when there's budget left.
//
// Tiers (lower number = higher priority):
//   1  source dirs — src/, lib/, app/, pages/, server/, api/, ...
//   2  top-level configs / workflows — package.json, Dockerfile,
//      .github/workflows/*.yml, next.config.*, webpack.config.*
//   3  unknown / mid — everything that isn't tier 1, 2, or 4
//   4  tests / fixtures / examples / docs-only — usually low-signal
//
// Within a tier we preserve the original input order (Array.prototype
// .sort is stable in V8 / Node 22 / modern browsers) so two scans of the
// same repo on the same tree return the same first-1000 files.

export type ScanPriorityTier = 1 | 2 | 3 | 4

// Top-level directory prefixes (case-insensitive) for tier 1 source
// code. Match is "starts with `<dir>/` after normalisation" so we don't
// flag a file literally named `lib` or a deep `vendor/foo/lib/` path.
const TIER1_SOURCE_DIRS = [
  "src/",
  "lib/",
  "libs/",
  "app/",
  "pages/",
  "server/",
  "servers/",
  "api/",
  "apis/",
  "services/",
  "service/",
  "routes/",
  "controllers/",
  "controller/",
  "handlers/",
  "handler/",
  "models/",
  "model/",
  "core/",
  "internal/",
  "internals/",
  "packages/",
  "modules/",
  "components/",
  "domain/",
]

// Tier 2 hand-picked config and workflow paths. Hit-rate per file is
// high (Dockerfile root-user, package.json typosquats, workflow
// pull_request_target etc.) so they ride above tier 3.
const TIER2_PATH_PATTERNS: RegExp[] = [
  /^[^/]+$/,                          // any root-level file (Dockerfile, etc.)
  /^\.github\/workflows\//i,          // GHA workflows
  /^\.github\/actions\//i,            // composite actions
]

// Tier 4 — test / fixture / example. Mirrors TEST_PATH_PATTERNS in
// scan.ts but kept here so this module stays self-contained.
const TIER4_PATH_PATTERNS: RegExp[] = [
  /(^|\/)(tests?|__tests?__|specs?|fixtures?|mocks?|examples?|samples?|testdata|stubs?|cypress|e2e|demos?)\//i,
  /\.(test|spec)\.[a-z0-9]+$/i,
  /_test\.[a-z0-9]+$/i,
  /_spec\.[a-z0-9]+$/i,
  /^docs?\//i,                        // pure docs dirs deprioritised over src/
]

function startsWithDir(path: string, dir: string): boolean {
  const lower = path.toLowerCase()
  return lower.startsWith(dir) || lower.includes(`/${dir}`)
}

export function scanPriorityTier(path: string): ScanPriorityTier {
  // Tier 4 wins over tier 1 — a file at `src/foo/__tests__/bar.test.ts`
  // is still a test, not source. Check tests first so tier 1 doesn't
  // accidentally rescue test files into the high-priority bucket.
  for (const pattern of TIER4_PATH_PATTERNS) {
    if (pattern.test(path)) return 4
  }
  for (const dir of TIER1_SOURCE_DIRS) {
    if (startsWithDir(path, dir)) return 1
  }
  for (const pattern of TIER2_PATH_PATTERNS) {
    if (pattern.test(path)) return 2
  }
  return 3
}

export function prioritizeFilesForScan<T extends { path: string }>(
  files: readonly T[],
): T[] {
  return [...files].sort((a, b) => scanPriorityTier(a.path) - scanPriorityTier(b.path))
}
