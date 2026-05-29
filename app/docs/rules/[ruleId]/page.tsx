import Link from "next/link"
import { notFound } from "next/navigation"
import type { Metadata } from "next"
import { PublicNav } from "@/app/components/public-nav"
import {
  getRuleCatalog,
  LAYER_LABELS,
  resolveCatalogEntry,
  ruleIdToSlug,
  slugToRuleId,
} from "@/lib/rule-catalog"

type PageProps = {
  params: Promise<{ ruleId: string }>
}

const SEV_STYLES: Record<string, string> = {
  critical: "text-red-300 border-red-500/30 bg-red-500/10",
  high: "text-orange-300 border-orange-500/30 bg-orange-500/10",
  medium: "text-yellow-300 border-yellow-500/30 bg-yellow-500/10",
  low: "text-slate-400 border-slate-700 bg-slate-800/30",
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const { ruleId: slug } = await params
  const entry = resolveCatalogEntry(slugToRuleId(slug))
  if (!entry) return { title: "Rule not found" }
  return {
    title: entry.name,
    description: entry.description.slice(0, 160),
  }
}

// Pre-render every rule at build time. Generates as many static pages
// as we have rules, so the docs section pays cost once at build, never
// at request time.
export async function generateStaticParams(): Promise<{ ruleId: string }[]> {
  return getRuleCatalog().map((entry) => ({ ruleId: ruleIdToSlug(entry.id) }))
}

export default async function RulePage({ params }: PageProps) {
  const { ruleId: slug } = await params
  const entry = resolveCatalogEntry(slugToRuleId(slug))
  if (!entry) notFound()

  const cweUrl = entry.cwe
    ? `https://cwe.mitre.org/data/definitions/${entry.cwe.replace(/^CWE-/i, "")}.html`
    : null

  return (
    <>
      <PublicNav />
      <main className="px-6 py-16">
        <div className="max-w-3xl mx-auto">
          <Link
            href="/docs/rules"
            className="inline-flex items-center gap-1 text-xs font-mono text-slate-500 hover:text-amber-400 transition mb-8"
          >
            ← all rules
          </Link>

          <p className="font-mono text-xs text-amber-400 mb-3">{entry.id}</p>

          <h1 className="font-display text-3xl md:text-4xl font-bold tracking-tight mb-4 leading-tight">
            {entry.name}
          </h1>

          <div className="flex flex-wrap gap-2 mb-8">
            <span
              className={`text-xs uppercase tracking-wider font-mono px-2 py-0.5 rounded border ${SEV_STYLES[entry.severity] ?? SEV_STYLES.low}`}
            >
              {entry.severity}
            </span>
            <span className="text-xs font-mono px-2 py-0.5 rounded border border-slate-700 bg-slate-800/40 text-slate-300">
              {LAYER_LABELS[entry.layer]}
            </span>
            <span className="text-xs font-mono px-2 py-0.5 rounded border border-slate-700 bg-slate-800/40 text-slate-300">
              {entry.category}
            </span>
            {entry.cwe && cweUrl && (
              <a
                href={cweUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs font-mono px-2 py-0.5 rounded border border-amber-400/40 text-amber-300 hover:bg-amber-400/10 transition"
              >
                {entry.cwe} ↗
              </a>
            )}
            {entry.languages && entry.languages.length > 0 && (
              <span className="text-xs font-mono px-2 py-0.5 rounded border border-slate-700 bg-slate-800/40 text-slate-300">
                {entry.languages.join(" · ")}
              </span>
            )}
          </div>

          <section className="mb-10">
            <h2 className="text-sm uppercase tracking-wider text-slate-500 font-mono mb-3">
              What it detects
            </h2>
            <p className="text-slate-300 leading-relaxed whitespace-pre-line">
              {entry.description}
            </p>
          </section>

          {entry.remediation && (
            <section className="mb-10">
              <h2 className="text-sm uppercase tracking-wider text-slate-500 font-mono mb-3">
                Remediation
              </h2>
              <p className="text-slate-300 leading-relaxed whitespace-pre-line">
                {entry.remediation}
              </p>
            </section>
          )}

          <section className="mb-10">
            <h2 className="text-sm uppercase tracking-wider text-slate-500 font-mono mb-3">
              How it runs
            </h2>
            <p className="text-slate-300 leading-relaxed text-sm">{howItRuns(entry.layer)}</p>
          </section>

          <div className="pt-8 border-t border-slate-800/60 text-sm text-slate-500">
            <p>
              Found a false positive or want this rule tuned?{" "}
              <a
                href={`https://github.com/silviooerudon/triagerook/issues/new?title=${encodeURIComponent(`Rule feedback: ${entry.id}`)}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-amber-400 hover:underline"
              >
                File an issue
              </a>
              . You can also suppress per-repo via a{" "}
              <code className="text-amber-300 font-mono">.repoguardignore</code>{" "}
              line.
            </p>
          </div>
        </div>
      </main>
    </>
  )
}

function howItRuns(layer: string): string {
  switch (layer) {
    case "ast":
      return "Each file scanned is parsed with the TypeScript Compiler API (via ts-morph). This rule walks the AST looking for the call shape and user-input flow it describes. Skipped on files larger than 200 KB or that fail to parse."
    case "regex-code":
      return "Applied line-by-line via a tagged regex with language-specific gating. Comments are skipped. Designed for high-confidence patterns where AST parsing would be overkill."
    case "secret-regex":
      return "Run against every text file in the repo (with a binary-content filter and a `.repoguardignore` filter for fixtures). The matched value is masked before being persisted."
    case "sensitive-file":
      return "Path / basename / content-header match. No content body is stored — only the path."
    case "iac-dockerfile":
      return "Run against Dockerfiles detected by path or basename. Line-based checks with remediation guidance."
    case "iac-github-actions":
      return "Run against `.github/workflows/*.yml` files. Targets the published patterns behind real-world breaches (GhostAction, s1ngularity, tj-actions/changed-files)."
    case "iac-kubernetes":
      return "Run against YAML files that look like Kubernetes manifests (top-level `apiVersion:` + `kind:`). Line-based checks across multi-document files; Helm-templated lines are skipped."
    case "iac-iam":
      return "Run against JSON/YAML/source files. AWS IAM rules require a policy-document context (Statement + Effect); GCP primitive roles are matched anywhere. HCL is left to the Terraform layer."
    case "framework":
      return "Gated on framework detection: the repo's manifests (package.json, requirements.txt, pom.xml, Gemfile, composer.json) are read to identify the stack, and the rule only runs against matching-language files when its framework is present."
    case "business-logic":
      return "Applied line-by-line on JS/TS and Python files (comments skipped). Flags input flowing into a trust decision — an ORM write, a privilege attribute, a charge amount, or a primary-key lookup — where an authorization/ownership check should exist. Conservative by design: confirm whether the check is present nearby."
    case "ai-generated":
      return "Applied line-by-line across source files, INCLUDING comments (the disclaimers and TODO markers are the signal). Matches placeholder credential literals, deferred-security TODO/FIXME comments, \"not for production\" disclaimers, and swallowed exceptions. The detector's own rule prose is skipped so the scanner doesn't flag itself."
    default:
      return "Detection layer not documented."
  }
}
