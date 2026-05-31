import type { DependencyFinding, DetectorHealth } from "./types"
import { GitHubRateLimitError, parseGitHubRateLimit } from "./scan"
import { buildGitHubHeaders } from "./github-fetch"
import { runOsvScan, type OsvParsedDep } from "./osv"

// PHP / Composer dependency scanner.
//
// Parses composer.lock and queries OSV with ecosystem "Packagist". OSV
// indexes the FriendsOfPHP/security-advisories database (what
// `composer audit` uses), so coverage matches a local Composer audit.
//
// Why composer.lock and not composer.json:
//   - composer.json carries version *constraints* (`"^8.0"`), not pinned
//     versions. OSV needs an exact version.
//   - composer.lock pins every package (direct + transitive) to a concrete
//     version under the `packages` (and `packages-dev`) arrays.
//   - A repo with composer.json but no composer.lock isn't version-locked;
//     scanning the constraints would give false signal, so we skip it.

// composer.lock is JSON: { "packages": [{name, version}], "packages-dev": [...] }.
// Composer version strings are often `v1.2.3` — OSV/Packagist indexes the bare
// form, so strip a single leading `v`. Dev packages are included (a vuln in a
// dev dep is still a vuln in CI / local tooling).
export function parseComposerLock(content: string): OsvParsedDep[] {
  let json: unknown
  try {
    json = JSON.parse(content)
  } catch {
    return []
  }
  if (!json || typeof json !== "object") return []
  const root = json as { packages?: unknown; "packages-dev"?: unknown }

  const out: OsvParsedDep[] = []
  const collect = (arr: unknown) => {
    if (!Array.isArray(arr)) return
    for (const entry of arr) {
      if (!entry || typeof entry !== "object") continue
      const pkg = entry as { name?: unknown; version?: unknown }
      if (typeof pkg.name !== "string" || typeof pkg.version !== "string") continue
      const version = pkg.version.replace(/^v/, "").trim()
      // Skip branch aliases / dev refs that aren't concrete versions.
      if (!version || version.startsWith("dev-") || version.includes("@")) continue
      out.push({ name: pkg.name, version, source: "composer.lock" })
    }
  }
  collect(root.packages)
  collect(root["packages-dev"])
  return out
}

async function fetchRepoFile(
  owner: string,
  repo: string,
  path: string,
  token: string | null,
): Promise<string | null> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${path}`,
    {
      headers: buildGitHubHeaders(token, "application/vnd.github.v3.raw"),
      cache: "no-store",
    },
  )
  if (res.status === 404) return null
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    return null
  }
  return res.text()
}

export type PhpDepsScanResult = {
  findings: DependencyFinding[]
  degraded: DetectorHealth | null
}

export async function scanPhpDependencies(
  owner: string,
  repo: string,
  token: string | null,
): Promise<PhpDepsScanResult> {
  const content = await fetchRepoFile(owner, repo, "composer.lock", token)
  if (!content) return { findings: [], degraded: null }

  const parsed = parseComposerLock(content)
  const { findings, degraded } = await runOsvScan(parsed, {
    osvEcosystem: "Packagist",
    displayEcosystem: "Composer",
    scanLabel: "PHP",
  })
  return { findings, degraded }
}
