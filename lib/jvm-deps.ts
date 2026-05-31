import type { DependencyFinding, DetectorHealth } from "./types"
import { GitHubRateLimitError, parseGitHubRateLimit } from "./scan"
import { buildGitHubHeaders } from "./github-fetch"
import { runOsvScan, type OsvParsedDep } from "./osv"

// JVM dependency scanner — Maven (pom.xml) and Gradle (build.gradle /
// build.gradle.kts).
//
// Both build tools resolve the same artifacts (Maven coordinates
// `groupId:artifactId`), so they share one OSV ecosystem ("Maven") and one
// display ecosystem ("Maven"); the `source` field distinguishes pom.xml from
// build.gradle. OSV indexes the GitHub Advisory Database for Maven, so
// coverage matches what Dependabot/`mvn dependency-check` would surface.
//
// Static-parse limitations (documented, not silent):
//   - Versions defined via a property (`${spring.version}`) or BOM-managed
//     (no explicit <version>) can't be resolved from a single file → skipped.
//   - Gradle dynamic versions (`1.+`, `latest.release`) and interpolated
//     Kotlin/Groovy variables (`$kotlinVersion`) → skipped.
//   - The Gradle map form (`group: 'g', name: 'a', version: 'v'`) is parsed in
//     addition to the common `'g:a:v'` string form.

type JvmSource = Extract<DependencyFinding["source"], "pom.xml" | "build.gradle">

// pom.xml: pull each <dependency> block's groupId/artifactId/version. We skip
// blocks whose version is missing or property-interpolated (`${...}`) — OSV
// needs a concrete version and we have no way to resolve the property here.
export function parsePomXml(content: string): OsvParsedDep[] {
  const deps: OsvParsedDep[] = []
  const blocks = content.match(/<dependency>[\s\S]*?<\/dependency>/g) ?? []
  for (const block of blocks) {
    const group = block.match(/<groupId>\s*([^<\s][^<]*?)\s*<\/groupId>/)?.[1]
    const artifact = block.match(/<artifactId>\s*([^<\s][^<]*?)\s*<\/artifactId>/)?.[1]
    const version = block.match(/<version>\s*([^<\s][^<]*?)\s*<\/version>/)?.[1]
    if (!group || !artifact || !version) continue
    if (version.includes("${")) continue
    deps.push({
      name: `${group.trim()}:${artifact.trim()}`,
      version: version.trim(),
      source: "pom.xml" satisfies JvmSource,
    })
  }
  return deps
}

// Gradle build scripts (Groovy + Kotlin DSL). Two declaration shapes:
//   implementation 'group:artifact:version'
//   implementation("group:artifact:version")
//   implementation group: 'g', name: 'a', version: 'v'
export function parseGradle(content: string): OsvParsedDep[] {
  const deps: OsvParsedDep[] = []

  const pushIf = (group?: string, artifact?: string, version?: string) => {
    if (!group || !artifact || !version) return
    // Skip interpolated / dynamic versions we can't resolve statically.
    if (/[$+]|latest/i.test(version)) return
    deps.push({
      name: `${group}:${artifact}`,
      version,
      source: "build.gradle" satisfies JvmSource,
    })
  }

  // String coordinate form: '...:...:...' inside any quotes.
  const coordRe = /['"]([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):([A-Za-z0-9_.+-]+?)(?::[A-Za-z0-9_.-]+)?['"]/g
  for (const m of content.matchAll(coordRe)) pushIf(m[1], m[2], m[3])

  // Map form: group: 'g', name: 'a', version: 'v' (order-independent).
  const mapLineRe = /\b(?:group|name|version)\s*[:=]\s*['"][^'"]+['"]/g
  for (const line of content.split("\n")) {
    if (!/\bgroup\s*[:=]/.test(line) || !/\bname\s*[:=]/.test(line)) continue
    const fields: Record<string, string> = {}
    for (const f of line.match(mapLineRe) ?? []) {
      const kv = f.match(/\b(group|name|version)\s*[:=]\s*['"]([^'"]+)['"]/)
      if (kv) fields[kv[1]] = kv[2]
    }
    pushIf(fields.group, fields.name, fields.version)
  }

  return deps
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

export type JvmDepsScanResult = {
  findings: DependencyFinding[]
  degraded: DetectorHealth | null
}

export async function scanJvmDependencies(
  owner: string,
  repo: string,
  token: string | null,
): Promise<JvmDepsScanResult> {
  const [pom, gradleGroovy, gradleKts] = await Promise.all([
    fetchRepoFile(owner, repo, "pom.xml", token),
    fetchRepoFile(owner, repo, "build.gradle", token),
    fetchRepoFile(owner, repo, "build.gradle.kts", token),
  ])

  const parsed: OsvParsedDep[] = []
  if (pom) parsed.push(...parsePomXml(pom))
  if (gradleGroovy) parsed.push(...parseGradle(gradleGroovy))
  if (gradleKts) parsed.push(...parseGradle(gradleKts))

  const { findings, degraded } = await runOsvScan(parsed, {
    osvEcosystem: "Maven",
    displayEcosystem: "Maven",
    scanLabel: "Java",
  })
  return { findings, degraded }
}
