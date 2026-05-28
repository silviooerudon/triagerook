import type { IaCFinding, Severity } from "./types"

// Terraform IaC misconfiguration detector.
//
// Like the GitHub Actions scanner (lib/iac.ts), this reads HCL text
// directly rather than parsing it into an AST. A real HCL parser
// (@cdktf/hcl2json / a wasm port) would be more precise, but the patterns
// below are high-confidence line shapes that don't need full block
// semantics — and pulling a parser in would add weight to the scan path
// for marginal gain at this stage. A couple of rules (security-group
// ingress) need just enough block context to tell ingress from egress, so
// those track brace depth locally.
//
// Scope is the common, high-blast-radius AWS misconfigurations: public S3,
// world-open security groups, wildcard IAM, unencrypted storage, publicly
// reachable databases. Hardcoded credentials in .tf files are intentionally
// NOT handled here — the secret-pattern and entropy detectors already scan
// .tf/.tfvars, so duplicating that would double-report.

export type TerraformRule = {
  id: string
  name: string
  severity: Severity
  description: string
  remediation: string
  scan: (content: string, filePath: string) => IaCFinding[]
}

function makeFinding(
  rule: Pick<TerraformRule, "id" | "name" | "severity" | "description" | "remediation">,
  filePath: string,
  lineIndex: number,
  lineContent: string,
): IaCFinding {
  return {
    ruleId: rule.id,
    ruleName: rule.name,
    severity: rule.severity,
    category: "terraform",
    description: rule.description,
    filePath,
    lineNumber: lineIndex + 1,
    lineContent: lineContent.trim().slice(0, 200) || null,
    remediation: rule.remediation,
  }
}

// Simple per-line scanner: emit one finding per line matching `test`.
function lineRule(
  rule: Omit<TerraformRule, "scan"> & { test: (line: string) => boolean },
): TerraformRule {
  const { test, ...meta } = rule
  return {
    ...meta,
    scan: (content, filePath) => {
      const findings: IaCFinding[] = []
      const lines = content.split("\n")
      for (let i = 0; i < lines.length; i++) {
        if (test(lines[i])) findings.push(makeFinding(meta, filePath, i, lines[i]))
      }
      return findings
    },
  }
}

// An open CIDR is one that exposes a resource to the entire internet.
const OPEN_CIDR = /["'](?:0\.0\.0\.0\/0|::\/0)["']/

export const TERRAFORM_RULES: TerraformRule[] = [
  lineRule({
    id: "tf-s3-public-acl",
    name: "S3 bucket ACL is public",
    severity: "high",
    description:
      "An S3 bucket with a `public-read` or `public-read-write` ACL is readable (or writable) by anyone on the internet. This is one of the most common sources of large-scale data leaks.",
    remediation:
      "Set `acl = \"private\"` and front the bucket with a CloudFront/OAC or pre-signed URLs if public objects are genuinely required.",
    test: (l) => /^\s*acl\s*=\s*"(?:public-read|public-read-write)"/i.test(l),
  }),
  lineRule({
    id: "tf-s3-public-access-block-disabled",
    name: "S3 public access block is disabled",
    severity: "medium",
    description:
      "Setting any of `block_public_acls`, `block_public_policy`, `ignore_public_acls`, or `restrict_public_buckets` to `false` weakens the account/bucket guardrail that stops a bucket from accidentally becoming public.",
    remediation:
      "Keep all four `aws_s3_bucket_public_access_block` flags set to `true` unless you have a documented reason to serve objects publicly.",
    test: (l) =>
      /^\s*(?:block_public_acls|block_public_policy|ignore_public_acls|restrict_public_buckets)\s*=\s*false\b/i.test(
        l,
      ),
  }),
  lineRule({
    id: "tf-iam-wildcard-action",
    name: "IAM policy grants wildcard action",
    severity: "high",
    description:
      "A policy statement with `Action = \"*\"` (or `\"<service>:*\"`) grants every API call. Combined with a broad resource this is effectively admin, and it violates least privilege — a compromise of the principal becomes a compromise of everything it can reach.",
    remediation:
      "Enumerate the specific actions the principal needs (e.g. `s3:GetObject`, `s3:PutObject`) instead of `*`.",
    test: (l) =>
      /^\s*(?:"Action"|Action)\s*[:=]\s*\[?\s*"\*"/.test(l) ||
      /^\s*actions\s*=\s*\[\s*"\*"\s*\]/i.test(l),
  }),
  lineRule({
    id: "tf-iam-wildcard-resource",
    name: "IAM policy grants wildcard resource",
    severity: "medium",
    description:
      "`Resource = \"*\"` applies a statement to every resource in the account. Paired with broad actions it removes any blast-radius boundary on the granted permissions.",
    remediation:
      "Scope the statement to specific ARNs (e.g. a single bucket or table) instead of `*`.",
    test: (l) =>
      /^\s*(?:"Resource"|Resource)\s*[:=]\s*\[?\s*"\*"/.test(l) ||
      /^\s*resources\s*=\s*\[\s*"\*"\s*\]/i.test(l),
  }),
  lineRule({
    id: "tf-unencrypted-storage",
    name: "Storage encryption disabled",
    severity: "medium",
    description:
      "An explicit `storage_encrypted = false` / `encrypted = false` leaves data at rest unencrypted on RDS, EBS, or similar resources. Encryption at rest is free on AWS and expected by most compliance baselines.",
    remediation:
      "Set the encryption flag to `true` (and supply a KMS key where the resource supports one).",
    test: (l) => /^\s*(?:storage_encrypted|encrypted)\s*=\s*false\b/i.test(l),
  }),
  lineRule({
    id: "tf-rds-publicly-accessible",
    name: "Database is publicly accessible",
    severity: "high",
    description:
      "`publicly_accessible = true` gives an RDS instance a public endpoint. Databases should sit in private subnets reachable only from application security groups, never directly from the internet.",
    remediation:
      "Set `publicly_accessible = false` and reach the database through a bastion, VPN, or private application tier.",
    test: (l) => /^\s*publicly_accessible\s*=\s*true\b/i.test(l),
  }),
  {
    id: "tf-security-group-world-ingress",
    name: "Security group allows ingress from 0.0.0.0/0",
    severity: "high",
    description:
      "An `ingress` rule with `cidr_blocks = [\"0.0.0.0/0\"]` (or `[\"::/0\"]`) exposes the port to the entire internet. On management ports (SSH 22, RDP 3389, database ports) this is a direct attack surface; even on app ports it removes the network boundary.",
    remediation:
      "Restrict `cidr_blocks` to known office/VPN ranges or reference another security group. Egress to 0.0.0.0/0 is usually fine; ingress rarely is.",
    // Needs block context: only flag open CIDRs inside an `ingress` block,
    // not `egress`. Track brace depth from the line that opens the block.
    scan: (content, filePath) => {
      const findings: IaCFinding[] = []
      const lines = content.split("\n")
      let ingressDepth = -1 // brace depth at which the active ingress block opened, or -1
      let depth = 0
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]
        // Enter an ingress block. `ingress {` or `ingress = [` both count;
        // the dynamic `ingress` form is rarer, so we accept the common shapes.
        if (ingressDepth === -1 && /^\s*ingress\b[\s={[]/.test(line)) {
          ingressDepth = depth
        }
        if (ingressDepth !== -1 && /cidr_blocks/i.test(line) && OPEN_CIDR.test(line)) {
          findings.push(
            makeFinding(
              {
                id: "tf-security-group-world-ingress",
                name: "Security group allows ingress from 0.0.0.0/0",
                severity: "high",
                description:
                  "An `ingress` rule with `cidr_blocks = [\"0.0.0.0/0\"]` (or `[\"::/0\"]`) exposes the port to the entire internet. On management ports (SSH 22, RDP 3389, database ports) this is a direct attack surface; even on app ports it removes the network boundary.",
                remediation:
                  "Restrict `cidr_blocks` to known office/VPN ranges or reference another security group. Egress to 0.0.0.0/0 is usually fine; ingress rarely is.",
              },
              filePath,
              i,
              line,
            ),
          )
        }
        // Update depth after handling the line so an opening `{` on the
        // ingress line itself is counted toward the block we just entered.
        for (const ch of line) {
          if (ch === "{" || ch === "[") depth++
          else if (ch === "}" || ch === "]") {
            depth--
            if (ingressDepth !== -1 && depth <= ingressDepth) ingressDepth = -1
          }
        }
      }
      return findings
    },
  },
]

export function scanTerraform(content: string, filePath: string): IaCFinding[] {
  const findings: IaCFinding[] = []
  for (const rule of TERRAFORM_RULES) {
    findings.push(...rule.scan(content, filePath))
  }
  return findings
}

/** Returns true when a given tree path is a Terraform source or vars file. */
export function isTerraformPath(path: string): boolean {
  return /\.(tf|tfvars)$/i.test(path)
}
