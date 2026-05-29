import type {
  LicenseFinding,
  LicenseRisk,
  Severity,
  DependencyEcosystem,
} from "./types"

// Open-source license / compliance scanner.
//
// The angle here is legal risk, not security: a transitive GPL dependency in
// a proprietary SaaS, or a package with no license at all (which legally
// grants you no rights to use it), is a real problem that secrets/CVE scans
// never surface.
//
// Cost model: this is ZERO extra network calls for npm. The npm
// `package-lock.json` (v2/v3) records a `license` field on every package
// entry, so we read licenses straight out of the lockfile we already fetched
// for the vulnerability scan. Other ecosystems (PyPI/Go/Ruby) don't carry
// license data in their lockfiles and would need per-package registry
// lookups — deferred to a follow-up (see docs/ROADMAP.md 1.3).
//
// Dev dependencies are intentionally skipped: a GPL build tool or test
// runner isn't distributed with your product, so it doesn't create a
// redistribution obligation. We only flag licenses that ship.

// Permissive licenses that never trigger a finding. Compared case-insensitively
// against SPDX ids. Kept deliberately broad so unknown-but-clearly-permissive
// ids don't generate noise.
const PERMISSIVE = new Set(
  [
    "MIT", "MIT-0", "ISC", "0BSD", "BSD-2-CLAUSE", "BSD-3-CLAUSE",
    "BSD-3-CLAUSE-CLEAR", "APACHE-2.0", "APACHE-1.1", "UNLICENSE", "CC0-1.0",
    "ZLIB", "WTFPL", "BSL-1.0", "PYTHON-2.0", "PSF-2.0", "BLUEOAK-1.0.0",
    "ARTISTIC-2.0", "NCSA", "X11", "CC-BY-4.0", "CC-BY-3.0",
  ].map((s) => s.toUpperCase()),
)

// Strong copyleft — source-disclosure can extend to the whole combined work.
const COPYLEFT_STRONG = [/\bAGPL/i, /(?<!L)\bGPL-?[0-9]/i, /\bGPL-?ONLY/i, /\bSSPL/i]
// Weak / file-level copyleft.
const COPYLEFT_WEAK = [/\bLGPL/i, /\bMPL/i, /\bEPL/i, /\bCDDL/i, /\bCPL/i, /\bEUPL/i, /\bOSL/i, /\bMS-RL/i]

const RISK_SEVERITY: Record<LicenseRisk, Severity> = {
  "copyleft-strong": "high",
  "copyleft-weak": "medium",
  missing: "medium",
  "non-standard": "medium",
}

function spdxUrl(license: string): string {
  // SPDX hosts a page per license id; for expressions this still resolves to
  // a useful search landing. Encode to be safe.
  return `https://spdx.org/licenses/${encodeURIComponent(license)}.html`
}

export type LicenseClassification = {
  risk: LicenseRisk
  severity: Severity
  description: string
  url: string
}

/**
 * Classify a declared license string. Returns null for permissive / clearly
 * acceptable licenses (no finding). Handles SPDX expressions conservatively:
 * an `OR` expression that offers a permissive choice is treated as permissive
 * (you can comply by picking the permissive option).
 */
export function classifyLicense(
  raw: string | null | undefined,
): LicenseClassification | null {
  const license = (raw ?? "").trim()

  if (!license) {
    return {
      risk: "missing",
      severity: RISK_SEVERITY.missing,
      description:
        "This dependency declares no license. With no license, default copyright applies and you have no legal right to use, copy, or redistribute it.",
      url: "https://choosealicense.com/no-permission/",
    }
  }

  const upper = license.toUpperCase()

  if (upper === "UNLICENSED" || upper === "SEE LICENSE IN LICENSE" || upper.includes("PROPRIETARY")) {
    return {
      risk: "non-standard",
      severity: RISK_SEVERITY["non-standard"],
      description:
        `This dependency is published as proprietary/non-standard ("${license}"). Confirm you have a license grant before shipping it.`,
      url: spdxUrl(license),
    }
  }

  // Split the expression into tokens to inspect choices.
  const tokens = upper.split(/\s*(?:\bOR\b|\bAND\b|\bWITH\b|[()/])\s*/).filter(Boolean)
  const hasOr = /\bOR\b/.test(upper)
  const hasPermissiveChoice = tokens.some((t) => PERMISSIVE.has(t.trim()))

  // Dual-licensed with a permissive escape hatch → user can comply permissively.
  if (hasOr && hasPermissiveChoice) return null

  const isStrong = COPYLEFT_STRONG.some((re) => re.test(license))
  if (isStrong) {
    return {
      risk: "copyleft-strong",
      severity: RISK_SEVERITY["copyleft-strong"],
      description:
        `"${license}" is a strong copyleft license. Distributing (or, for AGPL, even network-serving) software that incorporates it can require releasing your own source under the same terms. Review with legal before shipping in a proprietary product.`,
      url: spdxUrl(license),
    }
  }

  const isWeak = COPYLEFT_WEAK.some((re) => re.test(license))
  if (isWeak) {
    return {
      risk: "copyleft-weak",
      severity: RISK_SEVERITY["copyleft-weak"],
      description:
        `"${license}" is a weak/file-level copyleft license. Modifications to the library itself must usually be shared, and dynamic vs. static linking matters. Lower risk than GPL/AGPL but still worth a compliance check.`,
      url: spdxUrl(license),
    }
  }

  // Recognised permissive, or an unknown-but-not-copyleft id → no finding.
  return null
}

// ---- npm lockfile extraction -------------------------------------------------

type LockfileEntry = {
  version?: string
  dev?: boolean
  devOptional?: boolean
  license?: string | string[] | { type?: string }
  optional?: boolean
}

type Lockfile = {
  lockfileVersion?: number
  packages?: Record<string, LockfileEntry>
}

// Lockfile `license` can be a string, a (deprecated) array, or an object.
// Normalise to a single string (or null).
function normalizeLockfileLicense(
  value: LockfileEntry["license"],
): string | null {
  if (typeof value === "string") return value
  if (Array.isArray(value)) return value.join(" OR ") || null
  if (value && typeof value === "object" && typeof value.type === "string") {
    return value.type
  }
  return null
}

const MAX_LICENSE_FINDINGS = 1000

/**
 * Scan an npm lockfile for production dependencies with risky licenses.
 * Reads the `license` recorded on each `packages` entry (npm lockfile v2/v3) —
 * no network calls. Returns one finding per (package@version) with a risky
 * license, deduplicated. Dev-only dependencies are skipped.
 */
export function scanNpmLicenses(lockfileContent: string): LicenseFinding[] {
  let lock: Lockfile
  try {
    lock = JSON.parse(lockfileContent) as Lockfile
  } catch {
    return []
  }
  if (!lock.packages || typeof lock.packages !== "object") return []

  const findings: LicenseFinding[] = []
  const seen = new Set<string>()

  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path) continue // root project entry
    const lastIdx = path.lastIndexOf("node_modules/")
    if (lastIdx < 0) continue
    const name = path.slice(lastIdx + "node_modules/".length)
    if (!name || !entry?.version) continue
    // Skip dev-only deps: not distributed, so no redistribution obligation.
    if (entry.dev || entry.devOptional) continue

    const key = `${name}@${entry.version}`
    if (seen.has(key)) continue

    const license = normalizeLockfileLicense(entry.license)
    // A lockfile that omits the `license` field is NOT evidence of "no license"
    // — npm lockfiles (especially older v2/v3) routinely drop it even for
    // MIT/BSD packages. Treating absent-in-lockfile as "missing" produced
    // hundreds of false positives on real repos (e.g. accepts, ansi-regex,
    // normalize-path on OWASP/NodeGoat — all MIT). So we skip unknown licenses
    // here, consistent with the deps.dev path (lib/licenses-registry.ts), which
    // treats an empty license list as unknown rather than missing. An
    // explicitly proprietary string ("UNLICENSED") still arrives as a non-null
    // value and is flagged.
    if (license === null) continue
    const classification = classifyLicense(license)
    if (!classification) continue

    seen.add(key)
    // More than one "node_modules/" segment means the package is nested under
    // another dependency — i.e. transitive rather than directly declared.
    const isTransitive = path.indexOf("node_modules/") !== lastIdx
    findings.push({
      package: name,
      version: entry.version,
      ecosystem: "npm" satisfies DependencyEcosystem,
      license,
      risk: classification.risk,
      severity: classification.severity,
      description: classification.description,
      url: classification.url,
      source: "package-lock.json",
      isTransitive,
    })
    if (findings.length >= MAX_LICENSE_FINDINGS) break
  }

  return findings
}
