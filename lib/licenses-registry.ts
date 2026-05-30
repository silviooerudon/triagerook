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

export type DepRef = {
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

// For a Go major-version >= 2 the module may be indexed only under its
// "+incompatible" form. Returns that variant (e.g. "2.0.0" → "2.0.0+incompatible")
// when eligible, or null when it can't apply (major < 2, or already suffixed).
function goIncompatibleVariant(version: string): string | null {
  if (/\+incompatible$/.test(version)) return null
  const major = version.replace(/^v/, "").split(".")[0]
  if (!/^\d+$/.test(major) || Number(major) < 2) return null
  return `${version}+incompatible`
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
 * Enrich PyPI/Go/Ruby dependencies with their license from deps.dev. Returns
 * license findings for risky licenses plus an optional degraded marker.
 *
 * `injectedDeps` lets the scan pipeline pass the deps already parsed by the
 * vulnerability scanners (scanPython/Go/RubyDependencies), so we don't re-fetch
 * and re-parse the same five manifests. When omitted (standalone use / tests),
 * we fetch and parse the manifests ourselves. Network is injected for testability.
 */
export async function scanRegistryLicenses(
  owner: string,
  repo: string,
  token: string | null,
  fetchImpl: FetchLike = fetch as unknown as FetchLike,
  injectedDeps?: DepRef[],
): Promise<RegistryLicenseResult> {
  // 1. Collect dep refs — from the caller's pre-parsed deps when available,
  //    otherwise by fetching + parsing the manifests ourselves.
  let refs: DepRef[]
  if (injectedDeps) {
    refs = injectedDeps
  } else {
    refs = []
    const [requirements, pyproject, pipfile, goMod, gemfileLock] = await Promise.all([
      fetchManifest(fetchImpl, owner, repo, "requirements.txt", token),
      fetchManifest(fetchImpl, owner, repo, "pyproject.toml", token),
      fetchManifest(fetchImpl, owner, repo, "Pipfile", token),
      fetchManifest(fetchImpl, owner, repo, "go.mod", token),
      fetchManifest(fetchImpl, owner, repo, "Gemfile.lock", token),
    ])
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
  }

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

  // 3. Query deps.dev with bounded concurrency + per-request timeout. Count
  //    hard failures (not just a boolean) so we can degrade accurately even
  //    when SOME packages still resolved.
  let failedCount = 0
  const getJson = async (url: string) =>
    withTimeout((signal) => fetchImpl(url, { cache: "no-store", signal }))
  const results = await mapWithConcurrency(toQuery, CONCURRENCY, async (dep) => {
    try {
      let res = await getJson(depsDevUrl(dep))
      // Go v2+ modules that predate module-path versioning are indexed by
      // deps.dev only under their "+incompatible" version. parseGoMod strips
      // that suffix for OSV, so a 404 here may just be the missing suffix —
      // retry once with it before giving up (otherwise a copyleft +incompatible
      // module is silently never license-checked).
      if (res.status === 404 && dep.ecosystem === "Go") {
        const incompatible = goIncompatibleVariant(dep.version)
        if (incompatible) res = await getJson(depsDevUrl({ ...dep, version: incompatible }))
      }
      // 404 = package/version unknown to deps.dev; not a failure, just no data.
      if (res.status === 404) return null
      if (!res.ok) {
        failedCount++
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
      failedCount++
      return null
    }
  })

  const findings = results.filter((f): f is LicenseFinding => f !== null)

  // 4. Build a degraded marker whenever ANY package was not fully checked —
  //    a hard failure OR cap truncation — so a partial license scan never
  //    silently reads as comprehensive. (A partial failure that still resolves
  //    some findings must still warn about the ones it couldn't reach.)
  let degraded: DetectorHealth | null = null
  const reasons: string[] = []
  if (failedCount > 0) {
    reasons.push(
      `deps.dev did not respond for ${failedCount} package(s); their PyPI/Go/Ruby licenses were not checked (npm licenses, read from the lockfile, are unaffected).`,
    )
  }
  if (truncatedCount > 0) {
    reasons.push(
      `License check capped at ${MAX_PACKAGES} packages; ${truncatedCount} PyPI/Go/Ruby dependencies were not license-checked.`,
    )
  }
  if (reasons.length > 0) {
    degraded = { detector: "license-registry", reason: reasons.join(" ") }
  }

  return { findings, degraded }
}
