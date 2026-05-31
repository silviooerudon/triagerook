import type { IaCFinding } from "./types"

// Cloud IAM-in-code scanner.
//
// Distinct from lib/iam.ts (which reads GitHub org/repo identity settings via
// the API) and from the Terraform scanner (HCL). This detector finds
// over-privileged cloud IAM declared in code and config: AWS IAM policy
// documents (in *.json or inline in source), and GCP primitive roles.
//
// Why a separate detector: a `"Action": "*"` policy or a `roles/owner`
// binding is the cloud-permissions equivalent of `chmod 777` — it removes the
// blast-radius boundary, so a single compromise becomes total. CVE/secret
// scans never surface it.
//
// HCL (.tf/.tfvars) is intentionally skipped here — the Terraform scanner owns
// that surface and has its own AWS IAM wildcard rules. This keeps the two from
// double-reporting the same line.

export type IamPolicyRule = {
  id: string
  name: string
  severity: IaCFinding["severity"]
  description: string
  remediation: string
}

const RULES = {
  awsWildcardAction: {
    id: "iam-aws-wildcard-action",
    name: "AWS IAM policy grants wildcard action (*)",
    severity: "high",
    description:
      'An IAM statement with `"Action": "*"` grants every AWS API call. Combined with any Allow effect this is effectively administrator access and violates least privilege — a compromise of the principal becomes a compromise of the account.',
    remediation:
      'Enumerate the specific actions the principal needs (e.g. `"s3:GetObject"`) instead of `"*"`.',
  },
  awsServiceWildcard: {
    id: "iam-aws-service-wildcard-action",
    name: "AWS IAM policy grants service-wide wildcard (service:*)",
    severity: "medium",
    description:
      'A `"<service>:*"` action grants every operation in that service (e.g. all of S3, including delete). Usually broader than the workload needs.',
    remediation: "List the specific operations required instead of the service-wide wildcard.",
  },
  awsWildcardResource: {
    id: "iam-aws-wildcard-resource",
    name: "AWS IAM policy grants wildcard resource (*)",
    severity: "medium",
    description:
      'A statement with `"Resource": "*"` applies to every resource in the account, removing any blast-radius boundary on the granted actions.',
    remediation: "Scope the statement to specific ARNs (a bucket, a table) instead of `*`.",
  },
  awsPublicPrincipal: {
    id: "iam-aws-public-principal",
    name: "AWS IAM policy trusts any principal (*)",
    severity: "high",
    description:
      'A `"Principal": "*"` (or `{"AWS": "*"}`) in a resource/trust policy lets ANY AWS account assume the role or access the resource. This is a frequent cause of public S3 buckets and confused-deputy role assumption.',
    remediation:
      "Restrict the principal to specific account IDs / role ARNs, and add a `Condition` (e.g. `aws:SourceArn`).",
  },
  gcpOwner: {
    id: "iam-gcp-primitive-owner",
    name: "GCP primitive role roles/owner granted",
    severity: "high",
    description:
      "`roles/owner` is a primitive role that grants full control of the project, including IAM and billing. Google explicitly recommends predefined or custom roles over primitive ones.",
    remediation:
      "Replace `roles/owner` with the least-privilege predefined role(s) the identity actually needs.",
  },
  gcpEditor: {
    id: "iam-gcp-primitive-editor",
    name: "GCP primitive role roles/editor granted",
    severity: "medium",
    description:
      "`roles/editor` is a broad primitive role granting write access to almost all resources. Prefer predefined or custom roles scoped to the task.",
    remediation: "Replace `roles/editor` with narrower predefined role(s).",
  },
  azureOwner: {
    id: "iam-azure-rbac-owner",
    name: "Azure RBAC Owner role assigned",
    severity: "high",
    description:
      "The Azure built-in `Owner` role grants full access to all resources in the scope, including the right to delegate access to others. At subscription or resource-group scope this is the cloud-permissions equivalent of administrator — a compromise of the identity is a compromise of everything in scope.",
    remediation:
      "Assign the least-privilege built-in role the identity needs (e.g. `Reader`, a service-specific Contributor) instead of `Owner`, and narrow the assignable scope.",
  },
  azureContributor: {
    id: "iam-azure-rbac-contributor",
    name: "Azure RBAC Contributor role assigned",
    severity: "medium",
    description:
      "The Azure built-in `Contributor` role grants full management of all resources in the scope (everything except granting access). It's broader than most workloads need and removes the blast-radius boundary.",
    remediation:
      "Assign a service-specific built-in role (e.g. `Storage Blob Data Contributor`) scoped to the resource the identity actually uses.",
  },
  azureCustomRoleWildcard: {
    id: "iam-azure-custom-role-wildcard",
    name: "Azure custom role grants wildcard actions (*)",
    severity: "high",
    description:
      'An Azure custom role definition with `"Actions": ["*"]` grants every control-plane operation in the assignable scope — effectively Owner-level management access.',
    remediation:
      'Enumerate the specific `Actions` the role needs (e.g. `Microsoft.Storage/storageAccounts/read`) instead of `"*"`.',
  },
  githubBroadScope: {
    id: "iam-github-broad-oauth-scope",
    name: "GitHub OAuth/PAT requests an over-broad scope",
    severity: "medium",
    description:
      "Requesting a high-privilege GitHub scope (`delete_repo`, `admin:org`, `admin:enterprise`, `admin:repo_hook`, `site_admin`) gives the resulting token administrative reach far beyond typical app needs. A leaked token with these scopes can delete repos, reconfigure the org, or tamper with webhooks.",
    remediation:
      "Request only the minimal scopes the integration needs (e.g. `read:org`, `repo:status`), and prefer fine-grained PATs / GitHub App permissions over classic broad scopes.",
  },
} satisfies Record<string, IamPolicyRule>

function finding(
  rule: IamPolicyRule,
  filePath: string,
  lineIndex: number,
  lineContent: string,
): IaCFinding {
  return {
    ruleId: rule.id,
    ruleName: rule.name,
    severity: rule.severity,
    category: "iam-policy",
    description: rule.description,
    filePath,
    lineNumber: lineIndex + 1,
    lineContent: lineContent.trim().slice(0, 200) || null,
    remediation: rule.remediation,
  }
}

// Heuristic: does this content look like (or contain) an AWS IAM policy doc?
// Requires both a Statement array and an Effect — keeps us off arbitrary JSON
// that merely contains the word "Action".
function looksLikeAwsPolicy(content: string): boolean {
  return /["']Statement["']\s*:/.test(content) && /["']Effect["']\s*:/.test(content)
}

const WILDCARD_ACTION = /["']Action["']\s*:\s*(?:\[\s*)?["']\*["']/
const SERVICE_WILDCARD = /["']Action["']\s*:\s*(?:\[\s*)?["'][a-z0-9-]+:\*["']/i
const WILDCARD_RESOURCE = /["']Resource["']\s*:\s*(?:\[\s*)?["']\*["']/
const PUBLIC_PRINCIPAL =
  /["']Principal["']\s*:\s*(?:["']\*["']|\{\s*["']AWS["']\s*:\s*(?:\[\s*)?["']\*["'])/

// GCP primitive roles are only meaningful when assigned to a `role` key —
// `role: roles/owner`, `role = "roles/owner"`, `"role": "roles/owner"`,
// `--role=roles/owner`. Requiring the assignment context (rather than matching
// the bare string anywhere) keeps prose ("`roles/owner` grants everything"),
// rule definitions, and comments that merely mention the role from being
// flagged as if they were live bindings.
const GCP_OWNER = /\broles?\b["']?\s*[:=]\s*\[?\s*["']?roles\/owner\b/i
const GCP_EDITOR = /\broles?\b["']?\s*[:=]\s*\[?\s*["']?roles\/editor\b/i

// Azure. Built-in role GUIDs are globally unique, so they're authoritative on
// their own. The friendly names "Owner"/"Contributor" are common English
// words, so those only fire inside an Azure RBAC context (see looksLikeAzure)
// and only when assigned to a role key (roleDefinitionName / role / --role).
const AZURE_OWNER_GUID = /\b8e3af657-a8ff-443c-a75c-2fe8c4bcb635\b/i
const AZURE_CONTRIBUTOR_GUID = /\bb24988ac-6180-42a0-ab88-20f7382dd24c\b/i
// Separator allows `:`/`=` (JSON/Bicep) or whitespace (CLI: `--role Owner`).
const AZURE_ROLE_OWNER =
  /(?:roleDefinitionName|roleName|--role|["']?role["']?)\s*[:=\s]\s*\[?\s*["']?Owner\b/i
const AZURE_ROLE_CONTRIBUTOR =
  /(?:roleDefinitionName|roleName|--role|["']?role["']?)\s*[:=\s]\s*\[?\s*["']?Contributor\b/i
// Azure custom-role definitions use a capital-A "Actions" array (distinct from
// the AWS lowercase-singular "Action"); gated on Azure context.
const AZURE_CUSTOM_ROLE_WILDCARD = /["']Actions["']\s*:\s*\[\s*["']\*["']/

// GitHub OAuth/PAT scope assignment that includes a high-privilege scope.
// Requires a scope(s) key so prose mentioning these tokens isn't flagged.
const GITHUB_BROAD_SCOPE =
  /\bscopes?\b["']?\s*[:=][^\n]*\b(?:delete_repo|admin:org|admin:enterprise|admin:repo_hook|admin:public_key|admin:gpg_key|site_admin)\b/i

function looksLikeAzure(content: string): boolean {
  return /Microsoft\.Authorization|roleDefinition|AssignableScopes|az\s+role\s+assignment|azurerm_role|RoleAssignment|roleAssignments/i.test(
    content,
  )
}

/** Returns true for paths this detector should NOT scan. */
function isSkippedPath(path: string): boolean {
  // .tf/.tfvars are owned by the Terraform scanner. Documentation files
  // (markdown/rst/plain text) describe IAM in prose, not as live bindings —
  // scanning them only produces false positives.
  return /\.(tf|tfvars|md|mdx|markdown|rst|txt)$/i.test(path)
}

export function scanIamPolicy(content: string, filePath: string): IaCFinding[] {
  if (isSkippedPath(filePath)) return []
  const findings: IaCFinding[] = []
  const lines = content.split("\n")
  const awsContext = looksLikeAwsPolicy(content)
  const azureContext = looksLikeAzure(content)

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]

    if (awsContext) {
      if (WILDCARD_ACTION.test(line)) {
        findings.push(finding(RULES.awsWildcardAction, filePath, i, line))
      } else if (SERVICE_WILDCARD.test(line)) {
        // `else if`: a full `*` is already the stronger finding for this line.
        findings.push(finding(RULES.awsServiceWildcard, filePath, i, line))
      }
      if (WILDCARD_RESOURCE.test(line)) {
        findings.push(finding(RULES.awsWildcardResource, filePath, i, line))
      }
      if (PUBLIC_PRINCIPAL.test(line)) {
        findings.push(finding(RULES.awsPublicPrincipal, filePath, i, line))
      }
    }

    // GCP primitive roles — only when assigned to a `role` key (see GCP_OWNER).
    if (GCP_OWNER.test(line)) {
      findings.push(finding(RULES.gcpOwner, filePath, i, line))
    } else if (GCP_EDITOR.test(line)) {
      findings.push(finding(RULES.gcpEditor, filePath, i, line))
    }

    // Azure RBAC. GUIDs are authoritative anywhere; friendly names need an
    // Azure context. Owner outranks Contributor on the same line.
    if (AZURE_OWNER_GUID.test(line) || (azureContext && AZURE_ROLE_OWNER.test(line))) {
      findings.push(finding(RULES.azureOwner, filePath, i, line))
    } else if (
      AZURE_CONTRIBUTOR_GUID.test(line) ||
      (azureContext && AZURE_ROLE_CONTRIBUTOR.test(line))
    ) {
      findings.push(finding(RULES.azureContributor, filePath, i, line))
    }
    if (azureContext && AZURE_CUSTOM_ROLE_WILDCARD.test(line)) {
      findings.push(finding(RULES.azureCustomRoleWildcard, filePath, i, line))
    }

    // GitHub over-broad OAuth/PAT scope request.
    if (GITHUB_BROAD_SCOPE.test(line)) {
      findings.push(finding(RULES.githubBroadScope, filePath, i, line))
    }
  }

  return findings
}

export const IAM_POLICY_RULES: IamPolicyRule[] = Object.values(RULES)
