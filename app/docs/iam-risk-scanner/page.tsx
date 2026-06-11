import Link from "next/link"
import type { Metadata } from "next"
import { DocHeader, Section, Callout, Code, Pre } from "../_components/doc-ui"

export const metadata: Metadata = {
  title: "IAM risk scanner",
  description:
    "How TriageRook analyzes IAM policy-as-code: GitHub Actions OIDC trust weaknesses, privilege-escalation paths, and admin-equivalent grants — 12 checks across Terraform, CloudFormation, JSON, and serverless, with vulnerable vs fixed examples.",
}

type Check = {
  rule: string
  name: string
  severity: "critical" | "high"
}
type Family = {
  id: string
  title: string
  intro: string
  checks: Check[]
}

// Mirrors lib/iam.ts (OIDC), lib/iam-privesc.ts, and lib/iam-admin.ts exactly.
const FAMILIES: Family[] = [
  {
    id: "oidc",
    title: "GitHub OIDC trust",
    intro:
      "When a repo uses GitHub Actions OIDC to assume an AWS role, the role's trust policy is what decides who can assume it. A trust policy that is too loose lets workflows you do not control mint your credentials.",
    checks: [
      {
        rule: "iam-oidc-no-condition",
        name: "OIDC trust has no Condition block",
        severity: "critical",
      },
      {
        rule: "iam-oidc-wildcard-repo",
        name: "Wildcard repo/org in the sub claim",
        severity: "critical",
      },
      {
        rule: "iam-oidc-pull-request-trust",
        name: "Trust accepts the pull_request context",
        severity: "critical",
      },
      {
        rule: "iam-oidc-wildcard-ref",
        name: "Wildcard ref/environment in the sub claim",
        severity: "high",
      },
    ],
  },
  {
    id: "privesc",
    title: "Privilege escalation",
    intro:
      "These cross statements rather than auditing a policy in isolation — the IGA angle. They flag permission combinations that let a principal grant itself more than it started with.",
    checks: [
      {
        rule: "iam-passrole-wildcard",
        name: "iam:PassRole granted on Resource: *",
        severity: "critical",
      },
      {
        rule: "iam-passrole-with-create-compute",
        name: "iam:PassRole + compute creation in the same file",
        severity: "critical",
      },
      {
        rule: "iam-self-managing",
        name: "Policy can modify IAM policies on Resource: *",
        severity: "critical",
      },
      {
        rule: "iam-assume-role-no-condition",
        name: "sts:AssumeRole allowed without a Condition",
        severity: "high",
      },
      {
        rule: "iam-not-action-allow",
        name: "Allow combined with NotAction (inverted logic)",
        severity: "high",
      },
    ],
  },
  {
    id: "admin",
    title: "Admin equivalents",
    intro:
      "The table-stakes wildcard checks — grants that are administrator-equivalent in practice even when they don't attach the AdministratorAccess policy by name.",
    checks: [
      {
        rule: "iam-action-resource-wildcard",
        name: "Allow with Action: * and Resource: * (or 3+ service:* on Resource: *)",
        severity: "critical",
      },
      {
        rule: "iam-sensitive-service-wildcard",
        name: "Sensitive service (iam/kms/secretsmanager/sts) with Resource: *",
        severity: "high",
      },
      {
        rule: "iam-principal-wildcard",
        name: "Resource policy with a wildcard Principal and no Condition",
        severity: "critical",
      },
    ],
  },
]

const SEV_CLS: Record<string, string> = {
  critical: "text-red-300 border-red-500/30 bg-red-500/10",
  high: "text-orange-300 border-orange-500/30 bg-orange-500/10",
}

export default function IamRiskScannerPage() {
  return (
    <div className="max-w-3xl">
      <DocHeader eyebrow="reference" title="IAM risk scanner">
        Cloud IAM is where a small mistake becomes a total compromise. The IAM risk
        scanner reads the IAM policy documents you commit &mdash; Terraform,
        CloudFormation, raw JSON, serverless configs &mdash; and flags the
        identity-and-access patterns that actually get people owned: loose GitHub
        OIDC trust, privilege-escalation paths, and admin-equivalent grants. 12
        checks across three families.
      </DocHeader>

      <Callout variant="warn" title="It reads policy-as-code, not your live cloud">
        <p>
          This scanner analyzes the IAM configuration <em>in your repository</em>.
          It does not connect to your AWS/GCP/Azure control plane, and it does not
          need <Code>read:org</Code> or any elevated GitHub scope &mdash; just the
          read access every scan already has. (Organization MFA enforcement, which
          some tools fold into &ldquo;IAM,&rdquo; is a <em>posture</em> signal here,
          not part of this scanner &mdash; see{" "}
          <Link href="/docs/posture-score" className="text-amber-400 hover:underline">
            Posture score
          </Link>
          .) If it can&apos;t read the repo&apos;s files, the result is marked{" "}
          <strong>degraded</strong> rather than reported as a clean pass.
        </p>
      </Callout>

      <Section title="How it runs">
        <p className="leading-relaxed text-slate-300">
          From the repo tree, it selects files that look like they carry IAM policy
          &mdash; <Code>.tf</Code>, <Code>serverless.yml</Code>, and JSON/YAML whose
          path mentions iam/policy/role/trust/cloudformation/template &mdash; up to
          80 files, 256 KB each. It extracts policy statements from each (JSON
          documents, Terraform <Code>jsonencode</Code> / <Code>aws_iam_policy_document</Code>{" "}
          / heredoc policies, and CloudFormation/SAM YAML), then runs the three
          check families over them. Findings deduct from a 100-point score:
          critical &minus;20, high &minus;10. The remaining score maps to a level:
          90+ low, 70+ medium, 50+ high, below 50 critical.
        </p>
      </Section>

      {FAMILIES.map((fam) => (
        <Section key={fam.id} title={fam.title}>
          <p className="mb-4 leading-relaxed text-slate-300">{fam.intro}</p>
          <ul className="mb-2 space-y-2">
            {fam.checks.map((c) => (
              <li key={c.rule} className="flex items-start gap-3">
                <span
                  className={`mt-0.5 shrink-0 rounded border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider ${SEV_CLS[c.severity]}`}
                >
                  {c.severity}
                </span>
                <div className="min-w-0">
                  <p className="text-sm text-slate-300">{c.name}</p>
                  <p className="font-mono text-xs text-slate-500">{c.rule}</p>
                </div>
              </li>
            ))}
          </ul>
        </Section>
      ))}

      <Section title="OIDC trust — vulnerable vs fixed">
        <p className="mb-3 text-sm leading-relaxed text-slate-400">
          A trust policy with no condition can be assumed by any workflow on the
          public GitHub OIDC provider &mdash; including repos you don&apos;t own:
        </p>
        <Pre>{`// FLAGGED: iam-oidc-no-condition (critical)
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity"
}`}</Pre>
        <p className="mb-3 mt-5 text-sm leading-relaxed text-slate-400">
          Fixed &mdash; the sub claim is pinned to one repo and one ref, so only
          that workflow can assume the role:
        </p>
        <Pre>{`// OK
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:sub": "repo:my-org/my-repo:ref:refs/heads/main"
    }
  }
}`}</Pre>
        <p className="mt-4 text-sm leading-relaxed text-slate-400">
          The same statement with a <Code>sub</Code> of{" "}
          <Code>repo:my-org/*:*</Code> trips <Code>iam-oidc-wildcard-repo</Code>; a{" "}
          <Code>sub</Code> ending in <Code>:pull_request</Code> trips{" "}
          <Code>iam-oidc-pull-request-trust</Code> (a fork PR could assume it); and
          one pinned to the repo but ending in <Code>:*</Code> trips{" "}
          <Code>iam-oidc-wildcard-ref</Code>.
        </p>
      </Section>

      <Section title="Privilege escalation — vulnerable vs fixed">
        <p className="mb-3 text-sm leading-relaxed text-slate-400">
          <Code>iam:PassRole</Code> on every resource lets a principal hand any role
          to compute it controls &mdash; a documented escalation path:
        </p>
        <Pre>{`// FLAGGED: iam-passrole-wildcard (critical)
{ "Effect": "Allow", "Action": "iam:PassRole", "Resource": "*" }`}</Pre>
        <p className="mb-3 mt-5 text-sm leading-relaxed text-slate-400">
          Fixed &mdash; scoped to the exact role, and constrained to the service
          that may receive it:
        </p>
        <Pre>{`// OK
{
  "Effect": "Allow",
  "Action": "iam:PassRole",
  "Resource": "arn:aws:iam::123456789012:role/my-app-task-role",
  "Condition": {
    "StringEquals": { "iam:PassedToService": "ecs-tasks.amazonaws.com" }
  }
}`}</Pre>
        <p className="mt-4 text-sm leading-relaxed text-slate-400">
          If the same file <em>also</em> grants compute creation (
          <Code>lambda:CreateFunction</Code>, <Code>ec2:RunInstances</Code>,{" "}
          <Code>ecs:RunTask</Code>, <Code>glue:CreateJob</Code>), that combination
          alone trips <Code>iam-passrole-with-create-compute</Code>. Granting{" "}
          IAM-mutating actions (<Code>iam:AttachRolePolicy</Code>,{" "}
          <Code>iam:PutRolePolicy</Code>, …) on <Code>Resource: *</Code> trips{" "}
          <Code>iam-self-managing</Code> &mdash; the principal can attach
          AdministratorAccess to itself.
        </p>
      </Section>

      <Section title="Admin equivalents — vulnerable vs fixed">
        <p className="mb-3 text-sm leading-relaxed text-slate-400">
          The classic full wildcard:
        </p>
        <Pre>{`// FLAGGED: iam-action-resource-wildcard (critical)
{ "Effect": "Allow", "Action": "*", "Resource": "*" }`}</Pre>
        <p className="mb-3 mt-5 text-sm leading-relaxed text-slate-400">
          Fixed &mdash; enumerate the actions and pin the resources:
        </p>
        <Pre>{`// OK
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::my-bucket/*"
}`}</Pre>
        <p className="mt-4 text-sm leading-relaxed text-slate-400">
          A resource policy whose <Code>Principal</Code> is <Code>&quot;*&quot;</Code>{" "}
          (or <Code>{`{ "AWS": "*" }`}</Code>) with no <Code>Condition</Code> trips{" "}
          <Code>iam-principal-wildcard</Code> &mdash; anyone in any AWS account can
          act on the resource. Constrain it with the specific principals, or add a{" "}
          <Code>Condition</Code> such as <Code>aws:PrincipalOrgID</Code>.
        </p>
      </Section>

      <Section title="Where this fits">
        <p className="leading-relaxed text-slate-300">
          IAM-in-code findings are computed dynamically, so they don&apos;t appear
          in the static{" "}
          <Link href="/docs/rules" className="text-amber-400 hover:underline">
            rule catalog
          </Link>
          . For a one-line summary of every detector, see{" "}
          <Link href="/docs/detectors" className="text-amber-400 hover:underline">
            Detectors
          </Link>
          . For deep cross-account IAM analysis against your live cloud, a dedicated
          CSPM/CIEM tool goes further than policy-as-code static analysis can.
        </p>
      </Section>

      <div className="mt-12 border-t border-slate-800/60 pt-8 text-sm text-slate-500">
        <p>
          Found an IAM pattern we should catch (or a false positive)?{" "}
          <a
            href="https://github.com/silviooerudon/triagerook/issues/new?title=IAM%20scanner%20feedback"
            target="_blank"
            rel="noopener noreferrer"
            className="text-amber-400 hover:underline"
          >
            Open an issue
          </a>
          .
        </p>
      </div>
    </div>
  )
}
