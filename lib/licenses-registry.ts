import type {
  LicenseFinding,
  DependencyEcosystem,
  DetectorHealth,
} from "./types"
import { classifyLicense } from "./licenses"
import { buildGitHubHeaders } from "./github-fetch"
import { GitHubRateLimitError, parseGitHubRateLimit } from "./scan"
import { parseGoMod } from "./go-deps"
import { parseGemfileLock } from "./ruby-deps"
import {
  parseRequirementsTxt,
  parsePyprojectToml,
  parsePipfile,
} from "./python-deps"

// Registry-backed license scanner for PyPI / Go / RubyGems.
//
// Unlike npm (whose lockfile records a `license` field, so lib/licenses.ts is
// zero-network), these ecosystems carry no license data in their manifests.
// We enrich them via deps.dev (Google Open Source Insights) — the same kind of
// benign, unauthenticated public metadata API the vulnerability scanners
// already hit (OSV.dev). One GET per (package, version), but bounded hard:
//   - a global cap on packages queried (MAX_PACKAGES),
//   - bounded concurrency (CONCURRENCY),
//   - a short per-request timeout,
//   - graceful degradation (a DetectorHealth entry) when the API is down,
//   - and an explicit "N packages not license-checked" note when we hit the
//     cap, so a truncated scan never silently reads as "all clear".
//
// Production vs. dev distinction: these manifests don't reliably mark dev
// groups (unlike npm's lockfile), so we scan all parsed deps. A copyleft
// dependency is a compliance signal regardless of direct/transitive.

export type FetchLike = (
  url: string,
  init?: RequestInit,
) => Promise<{
  ok: boolean
  status: number
  json: () => Promise<unknown>
  text: () => Promise<string>
  headers: { get: (name: string) => string | null }
}>

type DepRef = {
  name: string
  version: string
  ecosystem: Extract<DependencyEcosystem, "PyPI" | "Go" | "RubyGems">
  source: NonNullable<LicenseFinding["source"]>
}

const MAX_PACKAGES = 200
const CONCURRENCY = 8
const REQUEST_TIMEOUT_MS = 5000
const DEPS_DEV_BASE = "https://api.deps.dev/v3/systems"

// deps.dev system path segment per ecosystem.
const DEPS_DEV_SYSTEM: Record<DepRef["ecosystem"], string> = {
  PyPI: "pypi",
  Go: "go",
  RubyGems: "rubygems",
}

// Registry landing page for a package (used as the finding URL when SPDX
// classification doesn't supply a better one — classifyLicense already returns
// an SPDX url, so this is a fallback we rarely need).
function registryUrl(dep: DepRef): string {
  switch (dep.ecosystem) {
    case "PyPI":
      return `https://pypi.org/project/${encodeURIComponent(dep.name)}/${encodeURIComponent(dep.version)}/`
    case "RubyGems":
      return `https://rubygems.org/gems/${encodeURIComponent(dep.name)}/versions/${encodeURIComponent(dep.version)}`
    case "Go":
      return `https://pkg.go.dev/${dep.name}@${depsDevGoVersion(dep.version)}`
  }
}

// deps.dev (and pkg.go.dev) index Go versions with the leading `v`. The Go
// vuln scanner strips it for OSV, so re-add it here when missing.
function depsDevGoVersion(version: string): string {
  return /^v/.test(version) ? version : `v${version}`
}

function depsDevUrl(dep: DepRef): string {
  const system = DEPS_DEV_SYSTEM[dep.ecosystem]
  const name = encodeURIComponent(dep.name) // encodes the slashes in Go module paths
  const version =
    dep.ecosystem === "Go" ? depsDevGoVersion(dep.version) : dep.version
  return `${DEPS_DEV_BASE}/${system}/packages/${name}/versions/${encodeURIComponent(version)}`
}

type DepsDevVersion = { licenses?: string[] }

// Of a set of detected license ids, pick the one classifyLicense rates as the
// highest legal risk. deps.dev returns detected licenses (not an SPDX
// expression), so each applies — the riskiest is the one to surface.
const RISK_RANK = { "copyleft-strong": 3, "copyleft-weak": 2, "non-standard": 1, missing: 0 } as const

function riskiestClassification(licenses: string[]) {
  let best: ReturnType<typeof classifyLicense> = null
  let bestLicense: string | null = null
  for (const lic of licenses) {
    const c = classifyLicense(lic)
    if (!c) continue
    if (!best || RISK_RANK[c.risk] > RISK_RANK[best.risk]) {
      best = c
      bestLicense = lic
    }
  }
  return best ? { classification: best, license: bestLicense } : null
}

async function withTimeout<T>(p: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  try {
    return await p(controller.signal)
  } finally {
    clearTimeout(timer)
  }
}

// Run `worker` over `items` with at most `limit` in flight at once.
async function mapWithConcurrency<T, R>(
  items: T[],
  limit: number,
  worker: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array(items.length)
  let next = 0
  async function run() {
    while (true) {
      const idx = next++
      if (idx >= items.length) return
      results[idx] = await worker(items[idx])
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, run))
  return results
}

const GITHUB_RAW = "application/vnd.github.v3.raw"

async function fetchManifest(
  fetchImpl: FetchLike,
  owner: string,
  repo: string,
  path: string,
  token: string | null,
): Promise<string | null> {
  const res = await fetchImpl(
    `https://api.github.com/repos/${owner}/${repo}/contents/${path}`,
    { headers: buildGitHubHeaders(token, GITHUB_RAW), cache: "no-store" },
  )
  if (res.status === 404) return null
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res as unknown as Response)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    return null
  }
  return res.text()
}

export type RegistryLicenseResult = {
  findings: LicenseFinding[]
  degraded: DetectorHealth | null
}

/**
 * Fetch the PyPI/Go/Ruby manifests, parse them, and enrich each dependency
 * with its license from deps.dev. Returns license findings for risky licenses
 * plus an optional degraded marker. Network is injected for testability.
 */
export async function scanRegistryLicenses(
  owner: string,
  repo: string,
  token: string | null,
  fetchImpl: FetchLike = fetch as unknown as FetchLike,
): Promise<RegistryLicenseResult> {
  // 1. Fetch + parse every manifest in parallel.
  const [requirements, pyproject, pipfile, goMod, gemfileLock] = await Promise.all([
    fetchManifest(fetchImpl, owner, repo, "requirements.txt", token),
    fetchManifest(fetchImpl, owner, repo, "pyproject.toml", token),
    fetchManifest(fetchImpl, owner, repo, "Pipfile", token),
    fetchManifest(fetchImpl, owner, repo, "go.mod", token),
    fetchManifest(fetchImpl, owner, repo, "Gemfile.lock", token),
  ])

  const refs: DepRef[] = []
  const pushAll = (
    deps: { name: string; version: string }[],
    ecosystem: DepRef["ecosystem"],
    source: DepRef["source"],
  ) => {
    for (const d of deps) refs.push({ name: d.name, version: d.version, ecosystem, source })
  }
  if (requirements) pushAll(parseRequirementsTxt(requirements), "PyPI", "requirements.txt")
  if (pyproject) pushAll(parsePyprojectToml(pyproject), "PyPI", "pyproject.toml")
  if (pipfile) pushAll(parsePipfile(pipfile), "PyPI", "Pipfile")
  if (goMod) pushAll(parseGoMod(goMod), "Go", "go.mod")
  if (gemfileLock) pushAll(parseGemfileLock(gemfileLock), "RubyGems", "Gemfile.lock")

  if (refs.length === 0) return { findings: [], degraded: null }

  // 2. De-dupe by (ecosystem, name, version), then cap.
  const seen = new Set<string>()
  const unique = refs.filter((r) => {
    const key = `${r.ecosystem}:${r.name}@${r.version}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
  const truncatedCount = Math.max(0, unique.length - MAX_PACKAGES)
  const toQuery = unique.slice(0, MAX_PACKAGES)

  // 3. Query deps.dev with bounded concurrency + per-request timeout. Track a
  //    hard network failure so we can degrade rather than report a clean scan.
  let hardFailure = false
  const results = await mapWithConcurrency(toQuery, CONCURRENCY, async (dep) => {
    try {
      const res = await withTimeout((signal) =>
        fetchImpl(depsDevUrl(dep), { cache: "no-store", signal }),
      )
      // 404 = package/version unknown to deps.dev; not a failure, just no data.
      if (res.status === 404) return null
      if (!res.ok) {
        hardFailure = true
        return null
      }
      const body = (await res.json()) as DepsDevVersion
      const licenses = Array.isArray(body.licenses) ? body.licenses.filter(Boolean) : []
      // Empty = unknown license (NOT "missing"); avoid false missing-license noise.
      if (licenses.length === 0) return null
      const picked = riskiestClassification(licenses)
      if (!picked) return null
      const { classification, license } = picked
      const finding: LicenseFinding = {
        package: dep.name,
        version: dep.version,
        ecosystem: dep.ecosystem,
        license: licenses.length > 1 ? licenses.join(", ") : license,
        risk: classification.risk,
        severity: classification.severity,
        description: classification.description,
        url: classification.url || registryUrl(dep),
        source: dep.source,
      }
      return finding
    } catch {
      hardFailure = true
      return null
    }
  })

  const findings = results.filter((f): f is LicenseFinding => f !== null)

  // 4. Build a degraded marker for hard failures and/or cap truncation, so the
  //    UI never presents a partial license scan as comprehensive.
  let degraded: DetectorHealth | null = null
  if (hardFailure && findings.length === 0) {
    degraded = {
      detector: "license-registry",
      reason:
        "deps.dev unreachable. PyPI/Go/Ruby license scan skipped (npm licenses, read from the lockfile, are unaffected).",
    }
  } else if (truncatedCount > 0) {
    degraded = {
      detector: "license-registry",
      reason: `License check capped at ${MAX_PACKAGES} packages; ${truncatedCount} PyPI/Go/Ruby dependencies were not license-checked.`,
    }
  }

  return { findings, degraded }
}
