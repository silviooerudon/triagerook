import type { DependencyFinding } from "@/lib/types"

export type DepBumpInput = {
  finding: DependencyFinding
  manifestContent: string
  manifestPath: string
}

export type DepBumpResult = {
  patches: { path: string; content: string }[]
  newVersion: string
}

const SEMVER = "(\\d+\\.\\d+\\.\\d+(?:[-+][0-9A-Za-z.-]+)?)"

export function deriveSafeVersion(vulnerableVersions: string): string | null {
  if (!vulnerableVersions) return null

  const ltMatch = new RegExp(`<\\s*${SEMVER}`).exec(vulnerableVersions)
  if (ltMatch) return ltMatch[1]

  return null
}

export function applyDepBump(input: DepBumpInput): DepBumpResult {
  const { finding, manifestContent, manifestPath } = input

  const safeVersion = deriveSafeVersion(finding.vulnerable_versions)
  if (!safeVersion) {
    throw new Error(
      `Cannot derive safe version from range '${finding.vulnerable_versions}' for ${finding.package}`
    )
  }

  if (manifestPath.endsWith("package.json")) {
    return bumpNpm(manifestContent, manifestPath, finding.package, safeVersion)
  }

  if (manifestPath.endsWith("requirements.txt")) {
    return bumpPyRequirements(manifestContent, manifestPath, finding.package, safeVersion)
  }

  throw new Error(`Unsupported manifest path: ${manifestPath}`)
}

function bumpNpm(
  content: string,
  path: string,
  pkg: string,
  safeVersion: string
): DepBumpResult {
  const manifest = JSON.parse(content) as Record<string, unknown>
  const blocks = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]

  let touched = false
  for (const block of blocks) {
    const deps = manifest[block]
    if (!isStringMap(deps)) continue
    if (pkg in deps) {
      const current = deps[pkg]
      const prefix = current.startsWith("^") ? "^" : current.startsWith("~") ? "~" : ""
      deps[pkg] = `${prefix}${safeVersion}`
      touched = true
    }
  }

  if (!touched) {
    throw new Error(`Package '${pkg}' not found in any dependency block of ${path}`)
  }

  const trailingNewline = content.endsWith("\n") ? "\n" : ""
  return {
    patches: [{ path, content: JSON.stringify(manifest, null, 2) + trailingNewline }],
    newVersion: safeVersion,
  }
}

function bumpPyRequirements(
  content: string,
  path: string,
  pkg: string,
  safeVersion: string
): DepBumpResult {
  const lines = content.split("\n")
  const target = pkg.toLowerCase()
  let touched = false

  const newLines = lines.map((line) => {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith("#")) return line

    const match = /^([A-Za-z0-9_.\-]+)\s*([=<>!~]=|==|>=|<=|>|<)\s*(.+)$/.exec(trimmed)
    if (!match) return line
    if (match[1].toLowerCase() !== target) return line

    touched = true
    return `${match[1]}==${safeVersion}`
  })

  if (!touched) {
    throw new Error(`Package '${pkg}' not found in ${path}`)
  }

  return {
    patches: [{ path, content: newLines.join("\n") }],
    newVersion: safeVersion,
  }
}

function isStringMap(v: unknown): v is Record<string, string> {
  return typeof v === "object" && v !== null && !Array.isArray(v)
}
