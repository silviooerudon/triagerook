export type Severity = "critical" | "high" | "medium" | "low"

// Soft-failure marker. When an external dependency (GitHub, npm
// registry, OSV.dev) is unavailable or rate-limited, the detector
// returns an empty result rather than failing the whole scan — but
// it also pushes a DetectorHealth entry so the UI can surface "we
// skipped X" instead of letting the user believe the scan was clean.
//
// See AGENTS.md ("never silently swallow GitHub/Supabase errors").
export type DetectorHealth = {
  detector:
    | "history"
    | "npm-audit"
    | "osv"
    | "blob-fetch"
    | "suppressions-file"
    | "license-registry"
  reason: string
}

export type SecretFinding = {
  patternId: string
  patternName: string
  severity: Severity
  description: string
  filePath: string
  lineNumber: number
  lineContent: string
  likelyTestFixture: boolean
  source?: "tree" | "history"
  commitSha?: string
  commitDate?: string
  commitAuthor?: string
  // Liveness status from the secret-validation engine (lib/secret-validation.ts).
  // Only the status is ever stored — never the secret value. Absent on scans
  // where validation was disabled (the common case).
  validation?:
    | "active"
    | "inactive"
    | "unverifiable"
    | "error"
    | "skipped"
}

export type CodeVulnCategory =
  | "ssrf"
  | "sqli"
  | "command-injection"
  | "xss"
  | "path-traversal"
  | "weak-crypto"
  | "jwt"
  | "cors"
  | "deserialization"
  | "eval"
  | "open-redirect"
  | "tls-verification"
  | "insecure-cookie"
  | "hardcoded-creds"
  | "prototype-pollution"
  | "logging"
  | "denial-of-service"
  | "weak-session"
  | "timing-attack"
  | "xxe"
  | "framework"
  | "access-control"
  | "business-logic"
  | "ai-generated"

export type CodeFinding = {
  ruleId: string
  ruleName: string
  severity: Severity
  category: CodeVulnCategory
  description: string
  cwe: string | null
  filePath: string
  lineNumber: number
  lineContent: string
  likelyTestFixture: boolean
}

export type SensitiveFileKind =
  | "private-key"
  | "keystore"
  | "ssh-key"
  | "env-production"
  | "env-generic"
  | "aws-credentials"
  | "gcp-service-account"
  | "kubeconfig"
  | "docker-config"
  | "npmrc-auth"
  | "pypirc-auth"
  | "terraform-state"
  | "database-dump"
  | "backup"
  | "git-credentials"
  | "htpasswd"
  | "pgpass"
  | "keepass"

export type SensitiveFileFinding = {
  kind: SensitiveFileKind
  name: string
  severity: Severity
  description: string
  filePath: string
  remediation: string
}

export type IaCCategory =
  | "dockerfile"
  | "github-actions"
  | "terraform"
  | "cloudformation"
  | "kubernetes"
  | "iam-policy"
  | "npm-scripts"
  | "supply-chain"

export type IaCFinding = {
  ruleId: string
  ruleName: string
  severity: Severity
  category: IaCCategory
  description: string
  filePath: string
  lineNumber: number | null
  lineContent: string | null
  remediation: string
  // True when the file lives under a test/fixture/example path. Stamped by the
  // scan dispatch (lib/scan.ts) so risk scoring de-prioritises it the same way
  // it does for secret/code fixtures — a `privileged: true` Pod or wildcard
  // IAM policy inside tests/fixtures/ is almost always a dummy, not live infra.
  likelyTestFixture?: boolean
}

export type DependencyEcosystem =
  | "npm"
  | "PyPI"
  | "Go"
  | "RubyGems"
  // Maven covers both Maven (pom.xml) and Gradle (build.gradle*) — they
  // resolve the same Maven-coordinate artifacts and share OSV's "Maven"
  // ecosystem. Composer is PHP (composer.lock → OSV "Packagist").
  | "Maven"
  | "Composer"

export type DependencyFinding = {
  package: string
  version: string
  ecosystem?: DependencyEcosystem
  // "medium" is the canonical TriageRook severity emitted by the dep
  // detectors via normalizeSeverity. "moderate" remains valid in the
  // type so old scans persisted with that string still parse — see
  // lib/severity.ts for the full story.
  severity: Severity | "moderate"
  title: string
  ghsa: string | null
  vulnerable_versions: string
  cvss_score: number | null
  url: string
  source?:
    | "package.json"
    | "package-lock.json"
    | "requirements.txt"
    | "pyproject.toml"
    | "Pipfile"
    | "go.mod"
    | "Gemfile.lock"
    | "pom.xml"
    | "build.gradle"
    | "composer.lock"
  isTransitive?: boolean
}

// License/compliance risk class for a dependency.
//   copyleft-strong — GPL/AGPL: linking or network use can impose source-
//                      disclosure obligations on the whole work.
//   copyleft-weak   — LGPL/MPL/EPL/CDDL: file- or library-level reciprocity.
//   missing         — LEGACY / write-dead: no current detector emits this.
//                      classifyLicense (lib/licenses.ts) returns null for an
//                      absent/empty license (an omitted license is unknown
//                      metadata, not "no rights" — see PR #102: treating it as
//                      "missing" produced hundreds of false positives). Retained
//                      only so scans persisted before that change still parse.
//                      Do NOT wire new code to produce it without revisiting #102.
//   non-standard    — explicitly proprietary / UNLICENSED.
export type LicenseRisk =
  | "copyleft-strong"
  | "copyleft-weak"
  | "missing"
  | "non-standard"

export type LicenseFinding = {
  package: string
  version: string
  ecosystem: DependencyEcosystem
  // The raw SPDX id/expression as declared, or null when none was found.
  license: string | null
  risk: LicenseRisk
  severity: Severity
  description: string
  // SPDX license page when we have a recognised id, else the registry page.
  url: string
  source?: DependencyFinding["source"]
  isTransitive?: boolean
}

export type RulesetBypassFinding = {
  ruleId: string
  ruleName: string
  severity: Severity
  rulesetName: string
  ruleType: string
  branch: string
  actorCount: number
  actorTypes: string[]
  description: string
}
