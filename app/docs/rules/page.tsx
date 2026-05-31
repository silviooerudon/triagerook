import Link from "next/link"
import type { Metadata } from "next"
import { PublicNav } from "@/app/components/public-nav"
import {
  getRuleCatalog,
  LAYER_LABELS,
  ruleIdToSlug,
  type CatalogEntry,
  type DetectorLayer,
} from "@/lib/rule-catalog"

export const metadata: Metadata = {
  title: "Detection rules",
  description:
    "Every rule TriageRook checks against. Severity, CWE mapping, plain-language description for each detector across AST SAST, code regex, secret patterns, sensitive files, and IaC checks.",
}

// Pages under /docs use the same chrome as the landing nav. No auth gate.

const LAYER_ORDER: DetectorLayer[] = [
  "ast",
  "regex-code",
  "secret-regex",
  "sensitive-file",
  "iac-dockerfile",
  "iac-github-actions",
  "iac-terraform",
  "iac-cloudformation",
  "iac-kubernetes",
  "iac-iam",
  "framework",
  "business-logic",
  "ai-generated",
]

const LAYER_BLURBS: Record<DetectorLayer, string> = {
  ast: "TypeScript Compiler API walkers. Detect user input flowing into dangerous sinks across hops the regex layer can't see.",
  "regex-code":
    "High-confidence single-line regex rules — fast, language-tagged, tied to a CWE. Bias toward few false positives over coverage.",
  "secret-regex":
    "Curated patterns for common credential formats: cloud keys, OAuth tokens, payment provider keys, database URIs. Plus an entropy fallback for env-shaped values.",
  "sensitive-file":
    "Files that should never be committed (.pem, .env, .pfx, .keystore, database dumps). Detected by path / extension / content header, not regex over content.",
  "iac-dockerfile":
    "Dockerfile hygiene checks: USER root, latest tags, ADD instead of COPY, unsafe shell escapes.",
  "iac-github-actions":
    "GitHub Actions workflow checks: pull_request_target with PR checkout, third-party actions pinned by tag instead of SHA, secrets in expressions.",
  "iac-terraform":
    "Terraform/HCL misconfiguration checks: public S3 buckets, security groups open to 0.0.0.0/0, wildcard IAM actions/resources, unencrypted or publicly accessible storage.",
  "iac-cloudformation":
    "CloudFormation template checks (YAML + JSON): public S3 buckets, security groups open to 0.0.0.0/0, wildcard IAM actions/resources, unencrypted or publicly accessible storage. Self-guards on AWSTemplateFormatVersion / Resources + AWS:: so non-template YAML/JSON is skipped.",
  "iac-kubernetes":
    "Kubernetes manifest checks: privileged containers, host namespaces, privilege escalation, running as root, mutable image tags, dangerous Linux capabilities. Helm-templated lines are skipped.",
  "iac-iam":
    "Cloud IAM-in-code checks: AWS IAM policy documents with wildcard actions/resources or a public principal, GCP primitive roles (roles/owner, roles/editor), Azure RBAC Owner/Contributor assignments + wildcard custom roles, and over-broad GitHub OAuth/PAT scopes (delete_repo, admin:org, …). Scans JSON/YAML/source; HCL is covered by the Terraform layer.",
  framework:
    "Context-aware rules that only fire when the repo actually uses the framework (Next.js, Express, NestJS, Django, Flask, FastAPI, Spring, Laravel, Rails). Catches framework-specific misconfig — DEBUG on, CSRF disabled, wildcard CORS — without false positives on unrelated code.",
  "business-logic":
    "Broken-access-control and business-logic flaws: IDOR (records fetched by client id with no ownership check), mass assignment (the whole request body written to an ORM), privilege escalation (role/admin set from input), and payment tampering (charge amount taken from the client). Framed as 'verify there's a check here' — conservative, because the authorization check may live a few lines away.",
  "ai-generated":
    "Tell-tale signs of LLM-scaffolded code shipped without hardening: placeholder credentials left in literals, security controls deferred with a TODO, \"not for production\" disclaimers next to the missing check, and swallowed exceptions (bare except: pass / empty catch {}). Reads comment lines too; low/medium severity so these hygiene tells don't drown out real vulnerabilities.",
}

const SEV_STYLES: Record<string, string> = {
  critical: "text-red-300 border-red-500/30 bg-red-500/10",
  high: "text-orange-300 border-orange-500/30 bg-orange-500/10",
  medium: "text-yellow-300 border-yellow-500/30 bg-yellow-500/10",
  low: "text-slate-400 border-slate-700 bg-slate-800/30",
}

export default function RulesIndexPage() {
  const catalog = getRuleCatalog()
  const byLayer = new Map<DetectorLayer, CatalogEntry[]>()
  for (const entry of catalog) {
    const bucket = byLayer.get(entry.layer)
    if (bucket) bucket.push(entry)
    else byLayer.set(entry.layer, [entry])
  }

  const totalCount = catalog.length
  const criticalCount = catalog.filter((e) => e.severity === "critical").length
  const highCount = catalog.filter((e) => e.severity === "high").length

  return (
    <>
      <PublicNav />
      <main className="px-6 py-16">
        <div className="max-w-5xl mx-auto">
          <div className="font-mono text-xs text-amber-400 mb-6 flex items-center gap-2.5">
            <span className="inline-block w-1.5 h-1.5 bg-amber-400 animate-pulse" />
            detection rules
          </div>

          <h1 className="font-display text-3xl md:text-4xl font-bold tracking-tight mb-3">
            What TriageRook checks for
          </h1>
          <p className="text-slate-400 text-base leading-relaxed mb-3 max-w-2xl">
            Every detection rule that runs against your repo. Open source, with
            CWE mapping and a plain-language description on each. Use the layer
            grouping below to see how each finding gets to your dashboard.
          </p>

          <div className="font-mono text-xs text-slate-500 mb-3 flex flex-wrap gap-x-5 gap-y-1">
            <span>
              <span className="text-amber-400">{totalCount}</span> rules total
            </span>
            <span>
              <span className="text-red-300">{criticalCount}</span> critical
            </span>
            <span>
              <span className="text-orange-300">{highCount}</span> high
            </span>
            <span className="text-slate-600">
              + dependency CVE lookup via npm + OSV (not listed; dynamic)
            </span>
          </div>

          <p className="font-mono text-xs text-slate-500 mb-12">
            <Link
              href="/docs/sarif"
              className="text-amber-400 hover:underline"
            >
              SARIF export →
            </Link>{" "}
            <span className="text-slate-600">
              upload findings to GitHub Code Scanning
            </span>
          </p>

          {LAYER_ORDER.map((layer) => {
            const entries = byLayer.get(layer)
            if (!entries || entries.length === 0) return null
            return (
              <section key={layer} className="mb-16">
                <header className="mb-5">
                  <h2 className="text-xl font-semibold tracking-tight inline-flex items-baseline gap-3">
                    {LAYER_LABELS[layer]}
                    <span className="font-mono text-xs text-slate-500">
                      {entries.length} {entries.length === 1 ? "rule" : "rules"}
                    </span>
                  </h2>
                  <p className="text-slate-400 text-sm mt-1 max-w-2xl">
                    {LAYER_BLURBS[layer]}
                  </p>
                </header>

                <ul className="grid sm:grid-cols-2 gap-3">
                  {entries.map((entry) => (
                    <li
                      key={entry.id}
                      className="bg-slate-900 border border-slate-800 rounded-xl p-4 hover:border-slate-700 transition"
                    >
                      <Link
                        href={`/docs/rules/${ruleIdToSlug(entry.id)}`}
                        className="block"
                      >
                        <div className="flex items-start justify-between gap-3 mb-1.5">
                          <h3 className="font-medium text-slate-100 leading-tight">
                            {entry.name}
                          </h3>
                          <span
                            className={`shrink-0 text-[10px] uppercase tracking-wider font-mono px-1.5 py-0.5 rounded border ${SEV_STYLES[entry.severity] ?? SEV_STYLES.low}`}
                          >
                            {entry.severity}
                          </span>
                        </div>
                        <p className="text-slate-500 text-xs font-mono mb-1.5">
                          {entry.id}
                        </p>
                        <p className="text-slate-400 text-xs line-clamp-2 leading-relaxed">
                          {entry.description}
                        </p>
                      </Link>
                    </li>
                  ))}
                </ul>
              </section>
            )
          })}

          <div className="mt-16 pt-8 border-t border-slate-800/60 text-sm text-slate-500">
            <p>
              Want a rule we don&apos;t have?{" "}
              <a
                href="https://github.com/silviooerudon/triagerook/issues/new"
                target="_blank"
                rel="noopener noreferrer"
                className="text-amber-400 hover:underline"
              >
                Open an issue on GitHub
              </a>
              .
            </p>
          </div>
        </div>
      </main>
    </>
  )
}
