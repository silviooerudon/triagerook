import type { SupplyChainFinding } from "./supply-chain"

// Registry-backed supply-chain signals (npm) — E6.
//
// Three signals the offline detectors can't see, each derived from public npm
// registry metadata (benign public API, same nature as OSV/deps.dev — no
// gating needed):
//
//   - dependency-confusion: a declared dependency whose name is NOT published
//     on the public registry (404). An attacker can register that name and win
//     resolution for any install that isn't scoped to a private registry. This
//     is the canonical dependency-confusion setup.
//   - recently-published: the package was first created on the registry very
//     recently. New packages are disproportionately typosquats / hijack
//     vehicles; a freshly created name pulled into a build warrants a look.
//   - suspicious-maintainer: zero maintainers listed, or the package is
//     deprecated — weak ownership signals that correlate with abandoned /
//     hijacked packages.
//
// Bounded like the other network detectors: capped package count, limited
// concurrency, per-request timeout, graceful skip on any failure.

export type FetchLike = (
  url: string,
  init?: { signal?: AbortSignal },
) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>

const REGISTRY = "https://registry.npmjs.org"
const MAX_PACKAGES = 60
const CONCURRENCY = 6
const REQUEST_TIMEOUT_MS = 4000
const RECENT_DAYS = 30

// Specs that don't resolve from the public registry — local paths, workspace
// protocol, git/url installs. Those can't be dependency-confused and have no
// registry metadata, so skip them.
function isRegistrySpec(spec: string): boolean {
  const s = spec.trim()
  if (!s) return false
  return !/^(?:file:|link:|workspace:|git\+|github:|git:|https?:|\.{0,2}\/|portal:)/i.test(s)
}

// Pull the dependency names from a package.json's dependency maps. dev deps are
// included — a malicious dev dep still runs in CI / on the developer's machine.
export function parsePackageJsonDeps(content: string): string[] {
  let json: unknown
  try {
    json = JSON.parse(content)
  } catch {
    return []
  }
  if (!json || typeof json !== "object") return []
  const root = json as Record<string, unknown>
  const names = new Set<string>()
  for (const key of [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ]) {
    const map = root[key]
    if (!map || typeof map !== "object") continue
    for (const [name, spec] of Object.entries(map as Record<string, unknown>)) {
      if (typeof spec === "string" && isRegistrySpec(spec)) names.add(name)
    }
  }
  return [...names]
}

type RegistryMeta = {
  status: number
  created?: string
  maintainers?: unknown
  deprecated?: boolean
}

async function fetchMeta(name: string, fetchImpl: FetchLike): Promise<RegistryMeta> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS)
  try {
    const res = await fetchImpl(`${REGISTRY}/${encodeURIComponent(name).replace("%40", "@")}`, {
      signal: controller.signal,
    })
    if (res.status === 404) return { status: 404 }
    if (!res.ok) return { status: res.status }
    const body = (await res.json()) as {
      time?: { created?: string }
      maintainers?: unknown
      versions?: Record<string, { deprecated?: unknown }>
      "dist-tags"?: { latest?: string }
    }
    const latest = body["dist-tags"]?.latest
    const deprecated = latest ? Boolean(body.versions?.[latest]?.deprecated) : false
    return {
      status: 200,
      created: body.time?.created,
      maintainers: body.maintainers,
      deprecated,
    }
  } catch {
    return { status: 0 } // network error / timeout → treat as unknown, no finding
  } finally {
    clearTimeout(timer)
  }
}

async function mapLimited<T, R>(
  items: T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const out: R[] = new Array(items.length)
  let i = 0
  async function worker() {
    while (i < items.length) {
      const idx = i++
      out[idx] = await fn(items[idx])
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
  return out
}

function findingId(kind: string, name: string): string {
  return `${kind}-${name.replace(/[^A-Za-z0-9._@/-]/g, "_")}`
}

export type RegistrySignalsResult = { findings: SupplyChainFinding[] }

export async function detectRegistrySignals(
  files: Map<string, string>,
  fetchImpl: FetchLike,
  now: Date = new Date(),
): Promise<RegistrySignalsResult> {
  // Collect unique dependency names across every package.json in the repo.
  const names = new Set<string>()
  const sourceFor = new Map<string, string>()
  for (const [path, content] of files) {
    const lower = path.toLowerCase()
    if (lower !== "package.json" && !lower.endsWith("/package.json")) continue
    for (const name of parsePackageJsonDeps(content)) {
      if (!names.has(name)) sourceFor.set(name, path)
      names.add(name)
    }
  }
  if (names.size === 0) return { findings: [] }

  const capped = [...names].slice(0, MAX_PACKAGES)
  const metas = await mapLimited(capped, CONCURRENCY, (name) => fetchMeta(name, fetchImpl))

  const findings: SupplyChainFinding[] = []
  capped.forEach((name, idx) => {
    const meta = metas[idx]
    const file = sourceFor.get(name) ?? "package.json"

    if (meta.status === 404) {
      findings.push({
        id: findingId("depconfusion", name),
        categoryId: "dependency-confusion",
        severity: "HIGH",
        package: name,
        file,
        pattern: "name-unpublished-on-public-registry",
        message: `Dependency "${name}" is not published on the public npm registry. If your install isn't scoped to a private registry, an attacker can publish this name and hijack resolution (dependency confusion).`,
        evidence: `GET ${REGISTRY}/${name} → 404`,
      })
      return
    }
    if (meta.status !== 200) return // unknown / network error — no signal

    if (meta.created) {
      const ageDays = (now.getTime() - new Date(meta.created).getTime()) / 86_400_000
      if (ageDays >= 0 && ageDays <= RECENT_DAYS) {
        findings.push({
          id: findingId("recent", name),
          categoryId: "recently-published",
          severity: "MEDIUM",
          package: name,
          file,
          pattern: "package-recently-created",
          message: `Dependency "${name}" was first published only ${Math.round(ageDays)} day(s) ago. Newly created packages are a common vehicle for typosquats and hijacks — verify it's the intended package.`,
          evidence: `registry time.created = ${meta.created}`,
        })
      }
    }

    const maintainerCount = Array.isArray(meta.maintainers) ? meta.maintainers.length : 0
    if (meta.deprecated || maintainerCount === 0) {
      findings.push({
        id: findingId("maintainer", name),
        categoryId: "suspicious-maintainer",
        severity: meta.deprecated ? "MEDIUM" : "LOW",
        package: name,
        file,
        pattern: meta.deprecated ? "package-deprecated" : "no-maintainers-listed",
        message: meta.deprecated
          ? `Dependency "${name}" is marked deprecated on the registry — unmaintained packages don't receive security fixes and are higher-risk hijack targets.`
          : `Dependency "${name}" lists no maintainers on the registry, a weak-ownership signal that correlates with abandoned or hijacked packages.`,
        evidence: meta.deprecated
          ? "dist-tags.latest is deprecated"
          : "maintainers = []",
      })
    }
  })

  return { findings }
}
