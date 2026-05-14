import type { SensitiveFileFinding, SensitiveFileKind, Severity } from "./types"

export type FileRule = {
  kind: SensitiveFileKind
  name: string
  severity: Severity
  description: string
  remediation: string
  matches: (path: string, basename: string) => boolean
}

// Schema migration files are routinely committed (Prisma, Rails, Flyway,
// Supabase, Django, etc) and would create universal false positives if matched
// by the database-dump rule. They are *intentional* schema/version artifacts,
// not data dumps. We skip the rule based on path or basename heuristics.
const MIGRATION_PATH_RE =
  /(^|\/)(prisma\/migrations|supabase\/migrations|db\/migrate|database\/migrations|migrations?|migrate)\//i
const MIGRATION_BASENAME_RE =
  /^(v\d+(\.\d+)*[._-]|\d+[._-][a-z]|\d{4}-\d{2}-\d{2}[._-]|\d{14}_)/i

function looksLikeMigration(path: string, basename: string): boolean {
  return MIGRATION_PATH_RE.test(path) || MIGRATION_BASENAME_RE.test(basename)
}

export const FILE_RULES: FileRule[] = [
  {
    kind: "private-key",
    name: "Private key file",
    severity: "critical",
    description:
      "Private cryptographic key file (.pem/.key). Should never be committed — used to sign tokens, authenticate to TLS endpoints, or decrypt data.",
    remediation:
      "Remove from repo, rotate the key, and move to a secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager).",
    matches: (_p, b) => {
      if (/\.(pem|key)$/i.test(b)) {
        return !/(public|pub|cert|cer|crt|csr)\.(pem|key)$/i.test(b)
      }
      if (/\.asc$/i.test(b)) {
        const stem = b.replace(/\.asc$/i, "")
        if (/\.(json|tar|tgz|gz|bz2|xz|zip|sig|txt|md|pdf|deb|rpm|whl|jar|exe|dmg|iso|img|apk|tar\.gz)$/i.test(stem)) {
          return false
        }
        return /private|priv|secret/i.test(stem) || /^id_(rsa|dsa|ecdsa|ed25519)/i.test(stem)
      }
      return false
    },
  },
  {
    kind: "keystore",
    name: "Keystore / certificate bundle",
    severity: "critical",
    description:
      "Binary key/certificate container (.pfx/.p12/.jks/.keystore). Usually holds private keys plus a password.",
    remediation: "Delete from repo and rotate both the key and its password.",
    matches: (_p, b) => /\.(pfx|p12|jks|keystore|bks)$/i.test(b),
  },
  {
    kind: "ssh-key",
    name: "SSH private key",
    severity: "critical",
    description:
      "SSH private key (id_rsa/id_ed25519/id_ecdsa/id_dsa). Grants direct access to any host trusting the corresponding public key.",
    remediation:
      "Rotate the key on every server, remove from repo, and store only in ~/.ssh/ or a secrets manager.",
    matches: (_p, b) =>
      /^id_(rsa|dsa|ecdsa|ed25519|xmss)(\.old)?$/i.test(b),
  },
  {
    kind: "keepass",
    name: "KeePass database",
    severity: "critical",
    description: "KeePass password database file (.kdbx).",
    remediation: "Remove from repo immediately and rotate every entry inside it.",
    matches: (_p, b) => /\.kdbx$/i.test(b),
  },
  {
    kind: "env-production",
    name: "Production .env file",
    severity: "critical",
    description:
      "Production environment variable file. Typically contains DB credentials, API keys, and signing secrets.",
    remediation:
      "Delete from repo, rotate every value inside, and use a hosting-provider env system (Vercel, AWS SSM) instead.",
    matches: (_p, b) => /^\.env\.(production|prod|live)(\..+)?$/i.test(b),
  },
  {
    kind: "env-generic",
    name: "Environment file (.env)",
    severity: "high",
    description:
      "Generic .env file. Commonly holds secrets; even dev .env files often leak into real infrastructure.",
    remediation:
      "Confirm it contains only dummy values, otherwise rotate and delete. Add .env files to .gitignore.",
    matches: (_p, b) =>
      /^\.env(\.[A-Za-z0-9_-]+)?$/i.test(b) &&
      !/^\.env\.(example|template|sample|dist|defaults?)(\..+)?$/i.test(b),
  },
  {
    kind: "aws-credentials",
    name: "AWS credentials file",
    severity: "critical",
    description:
      "AWS shared credentials file (~/.aws/credentials). Typically holds one or more named profiles with access/secret keys.",
    remediation: "Rotate every access key listed and delete the file from the repo.",
    matches: (path) =>
      /(^|\/)\.aws\/credentials$/i.test(path) ||
      /(^|\/)aws[\s_-]?credentials(\.(txt|ini))?$/i.test(path),
  },
  {
    kind: "gcp-service-account",
    name: "GCP service-account key",
    severity: "critical",
    description:
      "Google Cloud service-account JSON key. Usually grants broad, long-lived project access.",
    remediation:
      "Revoke the key from IAM, delete the file, and switch to workload-identity or short-lived tokens.",
    matches: (_p, b) =>
      /^(service[-_]?account|gcp[-_]?(sa|key|service)|.+-[a-f0-9]{12}\.json)$/i.test(
        b,
      ) && /\.json$/i.test(b),
  },
  {
    kind: "kubeconfig",
    name: "Kubernetes kubeconfig",
    severity: "critical",
    description:
      "Kubernetes kubeconfig file with embedded cluster CA, user tokens, and/or client certs.",
    remediation:
      "Rotate any tokens/certs inside, remove from repo, and use short-lived auth (OIDC, exec plugins).",
    matches: (path, b) =>
      /(^|\/)\.kube\/config$/i.test(path) ||
      /^kubeconfig(\.ya?ml)?$/i.test(b),
  },
  {
    kind: "docker-config",
    name: "Docker auth config",
    severity: "critical",
    description:
      "Docker CLI auth config containing base64-encoded registry credentials.",
    remediation:
      "Delete file, revoke registry tokens, and use a credential helper instead.",
    matches: (path) => /(^|\/)\.docker\/config\.json$/i.test(path),
  },
  {
    kind: "npmrc-auth",
    name: ".npmrc with auth",
    severity: "high",
    description:
      "Commit of .npmrc — this file often contains `_authToken` granting publish rights on npm.",
    remediation: "Review the file; if it has `_authToken`, rotate immediately.",
    matches: (_p, b) => /^\.npmrc$/i.test(b),
  },
  {
    kind: "pypirc-auth",
    name: ".pypirc with auth",
    severity: "high",
    description:
      ".pypirc typically stores PyPI upload credentials or tokens (publishing supply-chain risk).",
    remediation: "Remove from repo and rotate the PyPI token.",
    matches: (_p, b) => /^\.pypirc$/i.test(b),
  },
  {
    kind: "terraform-state",
    name: "Terraform state",
    severity: "critical",
    description:
      "Terraform state files often contain decrypted secrets (DB passwords, IAM keys) alongside infra metadata.",
    remediation:
      "Delete from repo, rotate any secrets referenced in the state, and configure a remote backend (S3 + DynamoDB, Terraform Cloud).",
    matches: (_p, b) => /^terraform\.tfstate(\.backup)?$/i.test(b),
  },
  {
    kind: "database-dump",
    name: "Database dump",
    severity: "critical",
    description:
      "Database dump file (SQL dump, .dump, compressed SQL). May contain PII, hashed passwords, and business data.",
    remediation:
      "Remove from repo history (BFG/git-filter-repo) and sanitize any exposed data.",
    matches: (path, b) => {
      // Skip schema migration files (Prisma/Rails/Flyway/Supabase/Django).
      // These are intentional version artifacts, not data dumps.
      if (looksLikeMigration(path, b)) return false
      return (
        /\.(sql|dump)$/i.test(b) ||
        /\.sql\.(gz|bz2|xz|zip)$/i.test(b) ||
        /(^|[._-])db[-_]?dump\.(sql|db|sqlite)?$/i.test(b)
      )
    },
  },
  {
    kind: "backup",
    name: "Backup file",
    severity: "medium",
    description:
      "Backup file (.bak/.backup/.old). Often a snapshot of production state including secrets.",
    remediation: "Review contents; if sensitive, remove and rotate.",
    matches: (_p, b) => /\.(bak|backup|old|orig)$/i.test(b),
  },
  {
    kind: "git-credentials",
    name: "git-credentials file",
    severity: "critical",
    description:
      "Git credential store (plain-text usernames/passwords/tokens for remotes).",
    remediation:
      "Remove, rotate every token inside, and use credential helpers (osxkeychain, libsecret) instead.",
    matches: (_p, b) => /^\.git-credentials$/i.test(b),
  },
  {
    kind: "htpasswd",
    name: ".htpasswd file",
    severity: "high",
    description:
      "Apache/nginx basic-auth file with hashed user passwords. Easy to brute-force if the hash is MD5/SHA1.",
    remediation:
      "Rotate all passwords, move auth to an identity provider, and remove the file.",
    matches: (_p, b) => /^\.htpasswd$/i.test(b),
  },
  {
    kind: "pgpass",
    name: "PostgreSQL .pgpass",
    severity: "high",
    description:
      "PostgreSQL credential cache (.pgpass). Plain-text host:port:db:user:password lines.",
    remediation: "Delete and rotate every password listed.",
    matches: (_p, b) => /^\.pgpass$/i.test(b),
  },
]

const SKIP_PATH_PATTERNS: RegExp[] = [
  /(^|\/)node_modules\//,
  /(^|\/)\.next\//,
  /(^|\/)dist\//,
  /(^|\/)build\//,
  /(^|\/)vendor\//,
  /(^|\/)\.git\//,
]

/**
 * Flags files whose path/name alone indicates sensitive contents, regardless
 * of whether we also match a regex inside them. Catches cases like committed
 * id_rsa, terraform.tfstate, .env.production, etc.
 */
export function findSensitiveFiles(paths: string[]): SensitiveFileFinding[] {
  const findings: SensitiveFileFinding[] = []
  for (const path of paths) {
    if (SKIP_PATH_PATTERNS.some((re) => re.test(path))) continue
    const basename = path.split("/").pop() ?? path
    for (const rule of FILE_RULES) {
      if (rule.matches(path, basename)) {
        findings.push({
          kind: rule.kind,
          name: rule.name,
          severity: rule.severity,
          description: rule.description,
          filePath: path,
          remediation: rule.remediation,
        })
        break // first matching rule wins — rules are ordered specific → generic
      }
    }
  }
  return findings
}
