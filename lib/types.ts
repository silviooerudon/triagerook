export type Severity = "critical" | "high" | "medium" | "low"

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
}

export type DependencyEcosystem = "npm" | "PyPI"

export type DependencyFinding = {
  package: string
  version: string
  ecosystem?: DependencyEcosystem
  severity: "critical" | "high" | "moderate" | "low"
  title: string
  ghsa: string | null
  vulnerable_versions: string
  cvss_score: number | null
  url: string
  source?: "package.json" | "package-lock.json" | "requirements.txt" | "pyproject.toml" | "Pipfile"
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
