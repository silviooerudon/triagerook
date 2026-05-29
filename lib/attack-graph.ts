import type { AnyFinding } from "./risk"
import type { Severity } from "./types"

// Blast radius + attack graph.
//
// Individual findings answer "what's wrong". This layer answers "so what" —
// it turns a flat list into the reachability story a triager actually cares
// about: a leaked AWS key isn't just a secret, it's a path to every S3 bucket
// in the account; a public S3 bucket plus that key is a path to the data.
//
// Pure analysis over the already-collected findings (no extra I/O), so it runs
// on every scan for free and is trivial to test. If secret validation ran
// (Phase 2), a confirmed-live credential elevates the path to critical.

export type BlastDomain =
  | "cloud"
  | "scm"
  | "payments"
  | "data"
  | "comms"
  | "ai"
  | "package-registry"
  | "observability"
  | "other"

export type BlastRadius = {
  domain: BlastDomain
  // One-line statement of what an attacker gets with this credential.
  capability: string
  // Concrete assets reachable through it.
  assets: string[]
}

// Map a secret patternId to its blast radius. Keyed by prefix so the dozens of
// provider-specific ids collapse to a handful of domains.
export function blastRadiusForSecret(patternId: string): BlastRadius | null {
  const id = patternId.toLowerCase()
  const startsWithAny = (...ps: string[]) => ps.some((p) => id.startsWith(p))

  if (startsWithAny("aws-"))
    return {
      domain: "cloud",
      capability: "Programmatic access to the AWS account the key belongs to",
      assets: ["S3 buckets", "RDS / DynamoDB data", "EC2/Lambda compute", "IAM (potential privilege escalation)"],
    }
  if (startsWithAny("azure-"))
    return {
      domain: "cloud",
      capability: "Access to Azure resources / storage for the tenant",
      assets: ["Blob/Table/Queue storage", "AAD-protected resources"],
    }
  if (startsWithAny("gcp-"))
    return {
      domain: "cloud",
      capability: "Access to the GCP project the credential is scoped to",
      assets: ["GCS buckets", "Cloud SQL", "service-account impersonation"],
    }
  if (startsWithAny("digitalocean-", "heroku-", "cloudflare-", "vercel-", "netlify-", "render-", "flyio-", "hashicorp-vault-", "terraform-cloud-"))
    return {
      domain: "cloud",
      capability: "Control of the hosting / infra account",
      assets: ["Deployments", "DNS / edge config", "environment secrets"],
    }
  if (startsWithAny("github-", "gitlab-", "bitbucket-"))
    return {
      domain: "scm",
      capability: "Read/write access to source repositories",
      assets: ["Push to default branch", "CI/CD workflows", "downstream supply chain"],
    }
  if (startsWithAny("stripe-", "paypal-", "square-", "shopify-", "adyen-"))
    return {
      domain: "payments",
      capability: "Access to the payments / commerce account",
      assets: ["Customer PII", "charges / refunds", "payout configuration"],
    }
  if (startsWithAny("npm-", "pypi-", "docker-hub-", "jfrog-"))
    return {
      domain: "package-registry",
      capability: "Publish rights to package registries",
      assets: ["Malicious package releases", "supply-chain compromise of consumers"],
    }
  if (startsWithAny("anthropic-", "openai-", "huggingface-", "replicate-", "perplexity-", "groq-"))
    return {
      domain: "ai",
      capability: "Billable use of the AI provider account",
      assets: ["Quota / spend abuse", "access to fine-tunes / files"],
    }
  if (startsWithAny("slack-", "discord-", "telegram-", "sendgrid-", "mailgun-", "postmark-", "mailchimp-", "twilio-"))
    return {
      domain: "comms",
      capability: "Send messages / email as the organisation",
      assets: ["Phishing from a trusted sender", "contact-list exfiltration"],
    }
  if (startsWithAny("datadog-", "newrelic-", "sentry-", "pagerduty-", "segment-", "algolia-"))
    return {
      domain: "observability",
      capability: "Access to monitoring / analytics data",
      assets: ["Logs & traces (often contain secrets)", "alerting control"],
    }
  if (startsWithAny("private-key", "password-in-url", "basic-auth-url", "jwt"))
    return {
      domain: "data",
      capability: "Direct access to a service or data store",
      assets: ["Database / API behind the credential"],
    }
  return null
}

export type AttackNode = {
  id: string
  kind: "credential" | "resource" | "asset"
  label: string
  severity: Severity
}

export type AttackEdge = { from: string; to: string; reason: string }

export type AttackPath = {
  id: string
  title: string
  severity: Severity
  // Ordered human-readable hops, entry → impact.
  steps: string[]
  // Where the path starts, for deep-linking back to the finding.
  entry?: { filePath: string; lineNumber: number }
  // True when secret validation confirmed the entry credential is live.
  liveCredential?: boolean
}

export type AttackGraph = {
  nodes: AttackNode[]
  edges: AttackEdge[]
  paths: AttackPath[]
}

function isActive(finding: AnyFinding): boolean {
  // `validation` only exists once Phase 2 ships; read it defensively so this
  // module compiles and runs against the current finding shape too.
  const v = (finding.data as { validation?: string }).validation
  return v === "active"
}

// Does the scan contain an IaC/cloud-exposure finding that makes a cloud
// credential's blast radius concrete (public bucket, wildcard IAM, open SG)?
function cloudExposure(findings: AnyFinding[]): string | null {
  for (const f of findings) {
    if (f.kind !== "iac") continue
    if (f.data.likelyTestFixture) continue // dummy infra in tests/fixtures
    const id = f.data.ruleId.toLowerCase()
    if (/s3-public|public-access|wildcard|world-ingress|publicly-accessible|iam-/.test(id)) {
      return f.data.ruleName
    }
  }
  return null
}

function hasPublicSensitiveFile(findings: AnyFinding[]): boolean {
  return findings.some((f) => f.kind === "sensitive-file")
}

function maxSeverity(a: Severity, b: Severity): Severity {
  const order: Severity[] = ["low", "medium", "high", "critical"]
  return order.indexOf(a) >= order.indexOf(b) ? a : b
}

/**
 * Build the attack graph from the (suppression-filtered) finding list.
 * Produces blast-radius-derived nodes for each meaningful credential and a set
 * of correlated, multi-hop attack paths. Returns empty arrays when nothing
 * chains — callers should only render the section when `paths.length > 0`.
 */
export function buildAttackGraph(findings: AnyFinding[]): AttackGraph {
  const nodes: AttackNode[] = []
  const edges: AttackEdge[] = []
  const paths: AttackPath[] = []
  const nodeIds = new Set<string>()

  const addNode = (n: AttackNode) => {
    if (nodeIds.has(n.id)) return
    nodeIds.add(n.id)
    nodes.push(n)
  }

  const exposure = cloudExposure(findings)
  const exposureFinding = exposure !== null

  let pathSeq = 0
  for (const f of findings) {
    if (f.kind !== "secret") continue
    if (f.data.likelyTestFixture) continue
    const blast = blastRadiusForSecret(f.data.patternId)
    if (!blast) continue

    const live = isActive(f)
    const credId = `cred:${f.data.patternId}:${f.data.filePath}:${f.data.lineNumber}`
    const sev: Severity = live ? "critical" : f.data.severity
    addNode({ id: credId, kind: "credential", label: f.data.patternName, severity: sev })

    const assetId = `asset:${blast.domain}`
    addNode({ id: assetId, kind: "asset", label: blast.capability, severity: sev })
    edges.push({ from: credId, to: assetId, reason: blast.capability })

    const steps: string[] = [
      `Leaked ${f.data.patternName} in ${f.data.filePath}:${f.data.lineNumber}${live ? " (confirmed live)" : ""}`,
      blast.capability,
    ]

    let pathSev = sev

    // Correlate cloud credentials with a concrete cloud-exposure finding to
    // build the headline secret → cloud → data path.
    if (blast.domain === "cloud" && exposure) {
      steps.push(`Reachable resource exposed by: ${exposure}`)
      steps.push(`Compromise of: ${blast.assets.join(", ")}`)
      pathSev = "critical"
    } else {
      steps.push(`Exposure of: ${blast.assets.join(", ")}`)
    }

    if (blast.domain === "scm") {
      steps.push("Pivot: poison CI/CD → downstream supply chain")
    }

    paths.push({
      id: `path:${pathSeq++}`,
      title:
        blast.domain === "cloud" && exposure
          ? `${f.data.patternName} → cloud account → production data`
          : `${f.data.patternName} → ${blast.domain} blast radius`,
      severity: pathSev,
      steps,
      entry: { filePath: f.data.filePath, lineNumber: f.data.lineNumber },
      liveCredential: live || undefined,
    })
  }

  // A standalone cloud-exposure finding (no credential) is still a one-hop
  // path worth calling out, especially alongside committed sensitive files.
  if (exposureFinding && !paths.some((p) => p.title.includes("cloud account"))) {
    const sev: Severity = hasPublicSensitiveFile(findings) ? "high" : "medium"
    paths.push({
      id: `path:${pathSeq++}`,
      title: `Public cloud resource → data exposure`,
      severity: sev,
      steps: [
        `Misconfiguration: ${exposure}`,
        hasPublicSensitiveFile(findings)
          ? "Combined with a committed sensitive file, data is directly reachable"
          : "Anything stored in the resource is internet-reachable",
      ],
    })
  }

  // Sort paths by severity (critical first) so the UI leads with the worst.
  const order: Severity[] = ["critical", "high", "medium", "low"]
  paths.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity))

  void maxSeverity // reserved for future multi-credential path merging
  return { nodes, edges, paths }
}
