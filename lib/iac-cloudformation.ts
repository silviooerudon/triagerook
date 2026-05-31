import type { IaCFinding, Severity } from "./types"

// CloudFormation IaC misconfiguration detector.
//
// Mirrors the Terraform scanner (lib/iac-terraform.ts) for the AWS-native
// template format. Like the other IaC scanners it reads the template text
// directly (CFN is YAML *or* JSON) rather than parsing it — the rule shapes
// below are high-confidence and don't need full block semantics, except the
// security-group rule which tracks ingress-vs-egress context.
//
// CloudFormation templates aren't path-identifiable (they're just .yaml/.yml/
// .json), so scanCloudFormation self-guards on content via
// looksLikeCloudFormation and returns [] for anything that isn't a template —
// the same approach the Kubernetes scanner uses.
//
// Scope matches Terraform: public S3, world-open security groups, wildcard
// IAM, unencrypted storage, publicly reachable databases. Hardcoded secrets
// in templates are intentionally NOT handled here (the secret/entropy
// detectors already scan .yaml/.json, so this would double-report).

// A template is CloudFormation when it declares the format version, or when it
// has a Resources section AND references at least one AWS:: resource type.
export function looksLikeCloudFormation(content: string): boolean {
  if (/AWSTemplateFormatVersion/.test(content)) return true
  const hasResources = /(^|\n)\s*"?Resources"?\s*:/.test(content)
  const hasAwsType = /"?Type"?\s*:\s*["']?AWS::/.test(content)
  return hasResources && hasAwsType
}

const OPEN_CIDR = /(?:0\.0\.0\.0\/0|::\/0)/

function makeFinding(
  rule: { id: string; name: string; severity: Severity; description: string; remediation: string },
  filePath: string,
  lineIndex: number,
  lineContent: string,
): IaCFinding {
  return {
    ruleId: rule.id,
    ruleName: rule.name,
    severity: rule.severity,
    category: "cloudformation",
    description: rule.description,
    filePath,
    lineNumber: lineIndex + 1,
    lineContent: lineContent.trim().slice(0, 200) || null,
    remediation: rule.remediation,
  }
}

type LineRule = {
  id: string
  name: string
  severity: Severity
  description: string
  remediation: string
  test: (line: string) => boolean
}

// Rules that fire on a single matching line, independent of block context.
// Each `test` handles both YAML (`Key: value`) and JSON (`"Key": value`).
const LINE_RULES: LineRule[] = [
  {
    id: "cfn-s3-public-acl",
    name: "S3 bucket ACL is public",
    severity: "high",
    description:
      "An S3 bucket with `AccessControl: PublicRead` / `PublicReadWrite` is readable (or writable) by anyone on the internet — one of the most common sources of large-scale data leaks.",
    remediation:
      "Remove the public `AccessControl` and front the bucket with CloudFront/OAC or pre-signed URLs if public objects are genuinely required.",
    test: (l) =>
      /(?:^|[\s{,])"?AccessControl"?\s*:\s*["']?(?:PublicRead|PublicReadWrite|AuthenticatedRead)\b/i.test(l),
  },
  {
    id: "cfn-s3-public-access-block-disabled",
    name: "S3 public access block is disabled",
    severity: "medium",
    description:
      "Setting any of `BlockPublicAcls`, `BlockPublicPolicy`, `IgnorePublicAcls`, or `RestrictPublicBuckets` to `false` weakens the guardrail that stops a bucket from accidentally becoming public.",
    remediation:
      "Keep all four `PublicAccessBlockConfiguration` flags `true` unless you have a documented reason to serve objects publicly.",
    test: (l) =>
      /(?:^|[\s{,])"?(?:BlockPublicAcls|BlockPublicPolicy|IgnorePublicAcls|RestrictPublicBuckets)"?\s*:\s*(?:false|"false")\b/i.test(
        l,
      ),
  },
  {
    id: "cfn-iam-wildcard-action",
    name: "IAM policy grants wildcard action",
    severity: "high",
    description:
      "A statement with `Action: \"*\"` (or `\"<service>:*\"`) grants every API call. Combined with a broad resource this is effectively admin and violates least privilege.",
    remediation:
      "Enumerate the specific actions the principal needs (e.g. `s3:GetObject`) instead of `*`.",
    test: (l) =>
      /(?:^|[\s{,])"?Action"?\s*:\s*\[?\s*["']\*["']/i.test(l) ||
      /^\s*-\s*["']\*["']\s*$/.test(l),
  },
  {
    id: "cfn-iam-wildcard-resource",
    name: "IAM policy grants wildcard resource",
    severity: "medium",
    description:
      "`Resource: \"*\"` applies a statement to every resource in the account. Paired with broad actions it removes any blast-radius boundary on the granted permissions.",
    remediation: "Scope the statement to specific ARNs instead of `*`.",
    test: (l) => /(?:^|[\s{,])"?Resource"?\s*:\s*\[?\s*["']\*["']/i.test(l),
  },
  {
    id: "cfn-unencrypted-storage",
    name: "Storage encryption disabled",
    severity: "medium",
    description:
      "An explicit `StorageEncrypted: false` / `Encrypted: false` leaves data at rest unencrypted on RDS, EBS, or similar resources. Encryption at rest is free on AWS and expected by most compliance baselines.",
    remediation: "Set the encryption flag to `true` (and supply a KMS key where supported).",
    test: (l) => /(?:^|[\s{,])"?(?:StorageEncrypted|Encrypted)"?\s*:\s*(?:false|"false")\b/i.test(l),
  },
  {
    id: "cfn-rds-publicly-accessible",
    name: "Database is publicly accessible",
    severity: "high",
    description:
      "`PubliclyAccessible: true` gives an RDS instance a public endpoint. Databases should sit in private subnets reachable only from application security groups, never directly from the internet.",
    remediation:
      "Set `PubliclyAccessible: false` and reach the database through a bastion, VPN, or private application tier.",
    test: (l) => /(?:^|[\s{,])"?PubliclyAccessible"?\s*:\s*(?:true|"true")\b/i.test(l),
  },
]

// Security-group ingress needs context: an open CidrIp/CidrIpv6 is only a
// finding inside ingress, not egress. CFN keys the two as SecurityGroupIngress
// and SecurityGroupEgress; we track the most recently entered mode and skip
// open CIDRs while in egress. A standalone open CidrIp (no surrounding mode)
// is treated as ingress — that's the conservative reading for an inline rule.
function scanSecurityGroupIngress(content: string, filePath: string): IaCFinding[] {
  const findings: IaCFinding[] = []
  const lines = content.split("\n")
  let mode: "ingress" | "egress" | "none" = "none"
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    if (/"?SecurityGroupIngress"?\s*:/i.test(line) || /AWS::EC2::SecurityGroupIngress/.test(line)) {
      mode = "ingress"
    } else if (/"?SecurityGroupEgress"?\s*:/i.test(line) || /AWS::EC2::SecurityGroupEgress/.test(line)) {
      mode = "egress"
    }
    if (mode !== "egress" && /"?CidrI(?:p|pv6)"?\s*:/i.test(line) && OPEN_CIDR.test(line)) {
      findings.push(
        makeFinding(
          {
            id: "cfn-security-group-world-ingress",
            name: "Security group allows ingress from 0.0.0.0/0",
            severity: "high",
            description:
              "A `SecurityGroupIngress` rule with `CidrIp: 0.0.0.0/0` (or `::/0`) exposes the port to the entire internet. On management ports (SSH 22, RDP 3389, database ports) this is a direct attack surface; even on app ports it removes the network boundary.",
            remediation:
              "Restrict `CidrIp` to known office/VPN ranges or reference a source security group. Egress to 0.0.0.0/0 is usually fine; ingress rarely is.",
          },
          filePath,
          i,
          line,
        ),
      )
    }
  }
  return findings
}

export function scanCloudFormation(content: string, filePath: string): IaCFinding[] {
  if (!looksLikeCloudFormation(content)) return []
  const findings: IaCFinding[] = []
  const lines = content.split("\n")
  for (const rule of LINE_RULES) {
    for (let i = 0; i < lines.length; i++) {
      if (rule.test(lines[i])) findings.push(makeFinding(rule, filePath, i, lines[i]))
    }
  }
  findings.push(...scanSecurityGroupIngress(content, filePath))
  return findings
}

// Exported for the rule catalog. Mirrors LINE_RULES + the security-group rule.
export const CLOUDFORMATION_RULES = [
  ...LINE_RULES.map(({ test: _test, ...meta }) => meta),
  {
    id: "cfn-security-group-world-ingress",
    name: "Security group allows ingress from 0.0.0.0/0",
    severity: "high" as Severity,
    description:
      "A `SecurityGroupIngress` rule with `CidrIp: 0.0.0.0/0` (or `::/0`) exposes the port to the entire internet.",
    remediation:
      "Restrict `CidrIp` to known office/VPN ranges or reference a source security group.",
  },
]
