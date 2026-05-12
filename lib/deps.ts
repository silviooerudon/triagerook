import type { DependencyFinding, IaCFinding } from "./types"
import { GitHubRateLimitError, parseGitHubRateLimit } from "./scan"
import { normalizeSeverity } from "./severity"

type PackageJson = {
  name?: string
  version?: string
  dependencies?: Record<string, string>
  devDependencies?: Record<string, string>
  optionalDependencies?: Record<string, string>
  peerDependencies?: Record<string, string>
  scripts?: Record<string, string>
}

type LockfileV2Entry = {
  version?: string
  dev?: boolean
  optional?: boolean
  integrity?: string
}

type LockfileV2 = {
  lockfileVersion?: number
  packages?: Record<string, LockfileV2Entry>
  dependencies?: Record<string, unknown>
}

type Advisory = {
  severity: string
  title: string
  vulnerable_versions: string
  url: string
  cvss?: { score?: number }
}

type AdvisoryResponse = Record<string, Advisory[]>

type PkgRef = {
  name: string
  version: string
  isTransitive: boolean
  source: "package.json" | "package-lock.json"
}

const MAX_PACKAGES = 1000
const NPM_AUDIT_URL = "https://registry.npmjs.org/-/npm/v1/security/advisories/bulk"

/** Regex patterns that indicate a shell script piping remote content into a
 *  shell interpreter — the classic malware-install vector. */
const SUSPICIOUS_SCRIPT_PATTERNS: Array<{ pattern: RegExp; reason: string }> = [
  {
    pattern: /\b(?:curl|wget)\b[^|\n]*\|\s*(?:ba)?sh\b/,
    reason: "Pipes a downloaded script straight into sh/bash — classic malware install pattern.",
  },
  {
    pattern: /\bbase64\s+-d\b|\bbase64\s+--decode\b/,
    reason: "Decodes base64 during install — commonly used to hide malicious payloads.",
  },
  {
    pattern: /\beval\s+[`$]/,
    reason: "Runs eval on dynamic content during install.",
  },
  {
    pattern: /\bnode\s+-e\s+["']/,
    reason: "Executes inline Node.js code during install — hard to audit.",
  },
  {
    pattern: /\bpython\d?\s+-c\s+["']/,
    reason: "Executes inline Python code during install — hard to audit.",
  },
  {
    pattern: /\bssh\b[^\n]*-o\s+StrictHostKeyChecking=no/,
    reason: "Disables SSH host-key checking — susceptible to MITM.",
  },
  {
    pattern: /\brm\s+-rf\s+\/?\*/,
    reason: "Destructive rm -rf during install.",
  },
]

const LIFECYCLE_KEYS = [
  "preinstall",
  "install",
  "postinstall",
  "prepublish",
  "prepublishOnly",
  "prepare",
  "prepack",
]

function buildGithubHeaders(token: string | null): HeadersInit {
  const h: Record<string, string> = { Accept: "application/vnd.github.v3.raw" }
  if (token) h.Authorization = `Bearer ${token}`
  return h
}

async function fetchRepoFile(
  owner: string,
  repo: string,
  path: string,
  token: string | null,
): Promise<string | null> {
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${path}`,
    { headers: buildGithubHeaders(token), cache: "no-store" },
  )
  if (res.status === 404) return null
  if (!res.ok) {
    const retry = parseGitHubRateLimit(res)
    if (retry !== null) throw new GitHubRateLimitError(retry)
    return null
  }
  return res.text()
}

function cleanVersion(spec: string): string {
  // ^1.2.3 / ~1.2.3 / >=1.2.3 / 1.2.3 — extract the first X.Y.Z sequence
  const match = spec.match(/\d+(?:\.\d+){0,2}(?:-[A-Za-z0-9.-]+)?/)
  return match ? match[0] : ""
}

function parsePackageJsonDeps(json: PackageJson): PkgRef[] {
  const out: PkgRef[] = []
  const sections = [
    json.dependencies ?? {},
    json.devDependencies ?? {},
    json.optionalDependencies ?? {},
  ]
  for (const section of sections) {
    for (const [name, spec] of Object.entries(section)) {
      const version = cleanVersion(spec)
      if (!version) continue
      out.push({ name, version, isTransitive: false, source: "package.json" })
    }
  }
  return out
}

function parseLockfile(json: LockfileV2): PkgRef[] {
  const out: PkgRef[] = []

  // npm v7+ / v8+ / v9+ format
  if (json.packages && typeof json.packages === "object") {
    for (const [path, entry] of Object.entries(json.packages)) {
      if (!path) continue // root entry = ""
      // Only the last "node_modules/<name>" component is the package name
      const lastIdx = path.lastIndexOf("node_modules/")
      if (lastIdx < 0) continue
      const name = path.slice(lastIdx + "node_modules/".length)
      if (!entry?.version) continue
      // Direct deps show up once; transitive ones are nested node_modules
      const isTransitive = path.indexOf("node_modules/", lastIdx + 1) !== -1
      out.push({
        name,
        version: entry.version,
        isTransitive,
        source: "package-lock.json",
      })
    }
  }

  // npm v6 fallback: "dependencies" object with nested dependencies
  if (out.length === 0 && json.dependencies) {
    const walk = (deps: Record<string, unknown>, depth: number) => {
      for (const [name, raw] of Object.entries(deps)) {
        const entry = raw as { version?: string; dependencies?: Record<string, unknown> }
        if (entry?.version) {
          out.push({
            name,
            version: entry.version,
            isTransitive: depth > 0,
            source: "package-lock.json",
          })
        }
        if (entry?.dependencies) walk(entry.dependencies, depth + 1)
      }
    }
    walk(json.dependencies as Record<string, unknown>, 0)
  }

  return out
}

function dedupe(refs: PkgRef[]): PkgRef[] {
  const seen = new Map<string, PkgRef>()
  for (const ref of refs) {
    const key = `${ref.name}@${ref.version}`
    const existing = seen.get(key)
    // Prefer lockfile source and non-transitive info
    if (!existing) {
      seen.set(key, ref)
      continue
    }
    if (existing.isTransitive && !ref.isTransitive) seen.set(key, ref)
  }
  return Array.from(seen.values()).slice(0, MAX_PACKAGES)
}

async function queryNpmAudit(refs: PkgRef[]): Promise<DependencyFinding[]> {
  if (refs.length === 0) return []

  const payload: Record<string, string[]> = {}
  const versionsMap = new Map<string, string[]>()
  for (const ref of refs) {
    const list = payload[ref.name] ?? []
    if (!list.includes(ref.version)) list.push(ref.version)
    payload[ref.name] = list
    const metaList = versionsMap.get(ref.name) ?? []
    if (!metaList.includes(ref.version)) metaList.push(ref.version)
    versionsMap.set(ref.name, metaList)
  }

  const res = await fetch(NPM_AUDIT_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
    cache: "no-store",
  })
  if (!res.ok) return []

  const advisories = (await res.json()) as AdvisoryResponse
  const byKey = new Map<string, PkgRef>(refs.map((r) => [`${r.name}@${r.version}`, r]))
  const findings: DependencyFinding[] = []
  for (const [pkgName, advList] of Object.entries(advisories)) {
    if (!Array.isArray(advList)) continue
    for (const adv of advList) {
      const ghsaMatch = adv.url.match(/GHSA-[\w-]+/)
      // We don't know which installed version triggered each advisory; pick
      // first version present for this package. For accuracy we'd need to
      // compare against vulnerable_versions semver — acceptable deferral.
      const versions = versionsMap.get(pkgName) ?? [""]
      for (const version of versions) {
        const ref = byKey.get(`${pkgName}@${version}`)
        findings.push({
          package: pkgName,
          version,
          ecosystem: "npm",
          severity: normalizeSeverity(adv.severity),
          title: adv.title,
          ghsa: ghsaMatch ? ghsaMatch[0] : null,
          vulnerable_versions: adv.vulnerable_versions,
          cvss_score: adv.cvss?.score ?? null,
          url: adv.url,
          source: ref?.source,
          isTransitive: ref?.isTransitive,
        })
      }
    }
  }
  return findings
}

export type NpmDepsScanResult = {
  vulns: DependencyFinding[]
  lifecycleIssues: IaCFinding[]
}

export function findLifecycleScriptIssues(pkg: PackageJson): IaCFinding[] {
  const issues: IaCFinding[] = []
  const scripts = pkg.scripts ?? {}
  for (const key of LIFECYCLE_KEYS) {
    const cmd = scripts[key]
    if (!cmd) continue
    for (const { pattern, reason } of SUSPICIOUS_SCRIPT_PATTERNS) {
      if (pattern.test(cmd)) {
        issues.push({
          ruleId: `npm-lifecycle-${key}-suspicious`,
          ruleName: `Suspicious code in npm "${key}" script`,
          severity: "critical",
          category: "npm-scripts",
          description:
            `The "${key}" script runs automatically during npm install. ${reason}`,
          filePath: "package.json",
          lineNumber: null,
          lineContent: cmd.length > 200 ? cmd.slice(0, 200) + "…" : cmd,
          remediation:
            "Remove or move this logic to a documented command the user must run explicitly. Never run remote code during install.",
        })
        break
      }
    }
  }
  return issues
}

export async function scanDependencies(
  owner: string,
  repo: string,
  accessToken: string | null,
): Promise<NpmDepsScanResult> {
  const [pkgRaw, lockRaw] = await Promise.all([
    fetchRepoFile(owner, repo, "package.json", accessToken),
    fetchRepoFile(owner, repo, "package-lock.json", accessToken),
  ])

  if (!pkgRaw && !lockRaw) return { vulns: [], lifecycleIssues: [] }

  let pkg: PackageJson = {}
  try {
    if (pkgRaw) pkg = JSON.parse(pkgRaw) as PackageJson
  } catch {
    // malformed package.json — keep going with lockfile only
  }

  let refs: PkgRef[] = []
  if (lockRaw) {
    try {
      const lock = JSON.parse(lockRaw) as LockfileV2
      refs = parseLockfile(lock)
    } catch {
      // malformed lockfile — fall back to package.json
    }
  }
  if (refs.length === 0 && pkgRaw) {
    refs = parsePackageJsonDeps(pkg)
  }

  refs = dedupe(refs)

  const [vulns, lifecycleIssues] = await Promise.all([
    queryNpmAudit(refs),
    Promise.resolve(findLifecycleScriptIssues(pkg)),
  ])

  return { vulns, lifecycleIssues }
}
