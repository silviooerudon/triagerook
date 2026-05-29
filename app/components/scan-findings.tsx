import type {
  CodeFinding,
  DependencyFinding,
  IaCFinding,
  LicenseFinding,
  SecretFinding,
  SensitiveFileFinding,
  Severity,
} from "@/lib/types"
import type { PrioritizedFinding } from "@/lib/risk"
import type { AttackGraph } from "@/lib/attack-graph"
import { FindingCard } from "./finding-card"
import { CheckCircleIcon } from "./icons"

type SeverityBadge = { label: string; badge: string }

const SEVERITY_BADGES: Record<Severity | "moderate", SeverityBadge> = {
  critical: {
    label: "Critical",
    badge: "bg-red-500/10 border-red-500/20 text-red-400",
  },
  high: {
    label: "High",
    badge: "bg-orange-500/10 border-orange-500/20 text-orange-400",
  },
  medium: {
    label: "Medium",
    badge: "bg-yellow-500/10 border-yellow-500/20 text-yellow-400",
  },
  moderate: {
    label: "Moderate",
    badge: "bg-yellow-500/10 border-yellow-500/20 text-yellow-400",
  },
  low: {
    label: "Low",
    badge: "bg-slate-500/10 border-slate-500/30 text-slate-400",
  },
}

export function SeverityPill({ severity }: { severity: Severity | "moderate" }) {
  const cfg = SEVERITY_BADGES[severity] ?? SEVERITY_BADGES.medium
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border ${cfg.badge}`}>
      {cfg.label}
    </span>
  )
}

// Returns the Tailwind classes that paint the left-edge accent on a
// finding card. Critical/high get a thick saturated stripe and a faint
// tinted background; medium gets a thinner stripe; low is unaccented
// (no visual cost when the list is mostly low-severity noise).
//
// Used by FindingCard's CardShell (prioritized view) and by the legacy
// section cards in this file (group-by-detector view) so both surfaces
// triage the same way.
export function severityAccentClass(
  severity: Severity | "moderate",
): string {
  switch (severity) {
    case "critical":
      return "border-l-4 border-l-red-500 bg-red-500/[0.04]"
    case "high":
      return "border-l-4 border-l-orange-500 bg-orange-500/[0.04]"
    case "medium":
    case "moderate":
      return "border-l-2 border-l-yellow-500/70"
    case "low":
      return ""
    default:
      return ""
  }
}

export function BadgePill({
  label,
  tone = "neutral",
  title,
}: {
  label: string
  tone?: "neutral" | "warn"
  title?: string
}) {
  const cls =
    tone === "warn"
      ? "bg-slate-500/10 border-slate-500/30 text-slate-400"
      : "bg-amber-400/10 border-amber-400/20 text-amber-300"
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border ${cls}`} title={title}>
      {label}
    </span>
  )
}

// Liveness badge for a validated secret. Only renders for statuses worth
// showing: a confirmed-live credential (loud red) or a provider-rejected one
// (muted green = likely already revoked). `unverifiable`/`error`/`skipped`
// render nothing to avoid clutter.
export function ValidationBadge({
  status,
}: {
  status?: SecretFinding["validation"]
}) {
  if (status === "active") {
    return (
      <span
        className="text-xs px-2 py-0.5 rounded-full border bg-red-500/15 border-red-500/40 text-red-300 font-medium"
        title="The provider confirmed this credential is still live. Rotate it immediately."
      >
        ● live credential
      </span>
    )
  }
  if (status === "inactive") {
    return (
      <span
        className="text-xs px-2 py-0.5 rounded-full border bg-emerald-500/10 border-emerald-500/30 text-emerald-300"
        title="The provider rejected this credential — it appears already revoked or rotated."
      >
        revoked / inactive
      </span>
    )
  }
  return null
}

export type AllFindings = {
  secrets: SecretFinding[]
  historySecrets: SecretFinding[]
  sensitiveFiles: SensitiveFileFinding[]
  codeFindings: CodeFinding[]
  iacFindings: IaCFinding[]
  npmDependencies: DependencyFinding[]
  pythonDependencies: DependencyFinding[]
  goDependencies: DependencyFinding[]
  rubyDependencies: DependencyFinding[]
  licenseFindings: LicenseFinding[]
}

export function countBySeverity(all: AllFindings) {
  const buckets = { critical: 0, high: 0, medium: 0, low: 0 }
  const bump = (sev: Severity | "moderate") => {
    if (sev === "moderate") buckets.medium++
    else if (sev in buckets) buckets[sev as keyof typeof buckets]++
  }
  for (const f of all.secrets) if (!f.likelyTestFixture) bump(f.severity)
  for (const f of all.historySecrets) bump(f.severity)
  for (const f of all.sensitiveFiles) bump(f.severity)
  for (const f of all.codeFindings) if (!f.likelyTestFixture) bump(f.severity)
  for (const f of all.iacFindings) bump(f.severity)
  for (const f of all.npmDependencies) bump(f.severity)
  for (const f of all.pythonDependencies) bump(f.severity)
  for (const f of all.goDependencies) bump(f.severity)
  for (const f of all.rubyDependencies) bump(f.severity)
  for (const f of all.licenseFindings) bump(f.severity)
  return buckets
}

export function totalCount(all: AllFindings) {
  return (
    all.secrets.filter((f) => !f.likelyTestFixture).length +
    all.historySecrets.length +
    all.sensitiveFiles.length +
    all.codeFindings.filter((f) => !f.likelyTestFixture).length +
    all.iacFindings.length +
    all.npmDependencies.length +
    all.pythonDependencies.length +
    all.goDependencies.length +
    all.rubyDependencies.length +
    all.licenseFindings.length
  )
}

// Attack-path summary: the "so what" view that chains correlated findings
// (e.g. leaked cloud key → public bucket → data) into a single narrative.
// Rendered above the per-finding lists since it's the headline triage signal.
export function AttackPathsSection({ graph }: { graph?: AttackGraph }) {
  if (!graph || graph.paths.length === 0) return null
  return (
    <section className="space-y-3">
      <SectionHeader
        title="Attack paths"
        count={graph.paths.length}
        hint="Correlated, multi-hop reachability — not just individual findings."
      />
      {graph.paths.map((p) => (
        <article
          key={p.id}
          className={`bg-slate-900 border border-slate-800 rounded-xl p-5 ${severityAccentClass(p.severity)}`}
        >
          <header className="flex items-center gap-2 flex-wrap mb-3">
            <h3 className="font-semibold">{p.title}</h3>
            <SeverityPill severity={p.severity} />
            {p.liveCredential && (
              <span className="text-xs px-2 py-0.5 rounded-full border bg-red-500/15 border-red-500/40 text-red-300 font-medium">
                ● live credential
              </span>
            )}
          </header>
          <ol className="space-y-1.5">
            {p.steps.map((step, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-300">
                <span className="font-mono text-xs text-amber-400 mt-0.5 shrink-0">
                  {i === 0 ? "▶" : "└→"}
                </span>
                <span>{step}</span>
              </li>
            ))}
          </ol>
          {p.entry && (
            <p className="text-xs text-slate-500 mt-3 font-mono">
              entry: {p.entry.filePath}:{p.entry.lineNumber}
            </p>
          )}
        </article>
      ))}
    </section>
  )
}

function SectionHeader({
  title,
  count,
  hint,
}: {
  title: string
  count: number
  hint?: string
}) {
  return (
    <div className="flex items-center justify-between gap-3 flex-wrap">
      <h2 className="text-xl font-semibold">
        {title} <span className="text-slate-500 font-normal">({count})</span>
      </h2>
      {hint && <p className="text-xs text-slate-500">{hint}</p>}
    </div>
  )
}

export function SecretsSection({
  findings,
  sourceLabel,
}: {
  findings: SecretFinding[]
  sourceLabel: "tree" | "history"
}) {
  if (findings.length === 0) return null
  const sorted = [...findings].sort(
    (a, b) =>
      Number(a.likelyTestFixture ?? false) -
      Number(b.likelyTestFixture ?? false),
  )
  const title =
    sourceLabel === "tree"
      ? "Secrets in current code"
      : "Secrets in git history"
  const hint =
    sourceLabel === "history"
      ? "Even deleted / rotated secrets stay in history. Treat as compromised."
      : undefined
  return (
    <section className="space-y-3">
      <SectionHeader title={title} count={findings.length} hint={hint} />
      {sorted.map((f, i) => (
        <SecretCard key={i} finding={f} />
      ))}
    </section>
  )
}

function SecretCard({ finding }: { finding: SecretFinding }) {
  const isTest = finding.likelyTestFixture ?? false
  const isHistory = finding.source === "history"
  const accent = isTest ? "" : severityAccentClass(finding.severity)
  return (
    <article
      className={`bg-slate-900 border border-slate-800 rounded-xl p-5 ${accent} ${
        isTest ? "opacity-60" : ""
      }`}
    >
      <header className="flex items-center gap-2 flex-wrap mb-1">
        <h3 className="font-semibold">{finding.patternName}</h3>
        <SeverityPill severity={finding.severity} />
        <ValidationBadge status={finding.validation} />
        {isTest && (
          <BadgePill
            label="Test fixture"
            tone="warn"
            title="Path looks like tests/fixtures/mocks — probably a dummy value"
          />
        )}
        {isHistory && finding.commitSha && (
          <BadgePill
            label={`${finding.commitSha.slice(0, 7)} • ${
              finding.commitAuthor ?? "unknown"
            }`}
            title={finding.commitDate}
          />
        )}
      </header>
      <p className="text-sm text-slate-400 mb-3">{finding.description}</p>
      <pre className="font-mono text-xs bg-black/40 border border-slate-800 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">
        <code>
          <span className="text-slate-500 block mb-1">
            {finding.filePath}:{finding.lineNumber}
          </span>
          <span className="text-slate-300">{finding.lineContent}</span>
        </code>
      </pre>
    </article>
  )
}

export function SensitiveFilesSection({
  findings,
}: {
  findings: SensitiveFileFinding[]
}) {
  if (findings.length === 0) return null
  return (
    <section className="space-y-3">
      <SectionHeader
        title="Sensitive files committed to the repo"
        count={findings.length}
        hint="Filenames alone indicate secrets. Rotate and remove immediately."
      />
      {findings.map((f, i) => (
        <article
          key={i}
          className={`bg-slate-900 border border-slate-800 rounded-xl p-5 ${severityAccentClass(f.severity)}`}
        >
          <header className="flex items-center gap-2 flex-wrap mb-1">
            <h3 className="font-semibold">{f.name}</h3>
            <SeverityPill severity={f.severity} />
          </header>
          <p className="text-sm text-slate-400 mb-3">{f.description}</p>
          <pre className="font-mono text-xs bg-black/40 border border-slate-800 rounded-lg p-3 overflow-x-auto">
            <code className="text-slate-300">{f.filePath}</code>
          </pre>
          <p className="text-xs text-slate-500 mt-3">
            <span className="text-slate-400">Remediation:</span> {f.remediation}
          </p>
        </article>
      ))}
    </section>
  )
}

export function CodeFindingsSection({ findings }: { findings: CodeFinding[] }) {
  if (findings.length === 0) return null
  const sorted = [...findings].sort(
    (a, b) =>
      Number(a.likelyTestFixture ?? false) -
      Number(b.likelyTestFixture ?? false),
  )
  return (
    <section className="space-y-3">
      <SectionHeader
        title="Code vulnerabilities (SAST)"
        count={findings.length}
        hint="Injection, SSRF, XSS, weak crypto and similar runtime risks."
      />
      {sorted.map((f, i) => {
        const accent = f.likelyTestFixture
          ? ""
          : severityAccentClass(f.severity)
        return (
        <article
          key={i}
          className={`bg-slate-900 border border-slate-800 rounded-xl p-5 ${accent} ${
            f.likelyTestFixture ? "opacity-60" : ""
          }`}
        >
          <header className="flex items-center gap-2 flex-wrap mb-1">
            <h3 className="font-semibold">{f.ruleName}</h3>
            <SeverityPill severity={f.severity} />
            {f.cwe && <BadgePill label={f.cwe} />}
            {f.likelyTestFixture && (
              <BadgePill
                label="Test fixture"
                tone="warn"
                title="Path looks like tests/fixtures/mocks"
              />
            )}
          </header>
          <p className="text-sm text-slate-400 mb-3">{f.description}</p>
          <pre className="font-mono text-xs bg-black/40 border border-slate-800 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">
            <code>
              <span className="text-slate-500 block mb-1">
                {f.filePath}:{f.lineNumber}
              </span>
              <span className="text-slate-300">{f.lineContent}</span>
            </code>
          </pre>
        </article>
        )
      })}
    </section>
  )
}

function iacCategoryLabel(cat: IaCFinding["category"]): string {
  switch (cat) {
    case "dockerfile":
      return "Dockerfile"
    case "github-actions":
      return "GitHub Actions"
    case "terraform":
      return "Terraform"
    case "kubernetes":
      return "Kubernetes"
    case "iam-policy":
      return "Cloud IAM"
    case "npm-scripts":
      return "npm lifecycle"
    case "supply-chain":
      return "Supply chain"
  }
}

export function IaCFindingsSection({ findings }: { findings: IaCFinding[] }) {
  if (findings.length === 0) return null
  return (
    <section className="space-y-3">
      <SectionHeader
        title="CI / IaC / supply-chain issues"
        count={findings.length}
        hint="Build-time and workflow misconfigurations that widen the attack surface."
      />
      {findings.map((f, i) => (
        <article
          key={i}
          className={`bg-slate-900 border border-slate-800 rounded-xl p-5 ${
            f.likelyTestFixture ? "opacity-60" : severityAccentClass(f.severity)
          }`}
        >
          <header className="flex items-center gap-2 flex-wrap mb-1">
            <h3 className="font-semibold">{f.ruleName}</h3>
            <SeverityPill severity={f.severity} />
            <BadgePill label={iacCategoryLabel(f.category)} />
            {f.likelyTestFixture && (
              <BadgePill
                label="Test fixture"
                tone="warn"
                title="Path looks like tests/fixtures/examples — probably dummy infra"
              />
            )}
          </header>
          <p className="text-sm text-slate-400 mb-3">{f.description}</p>
          {(f.lineContent || f.lineNumber) && (
            <pre className="font-mono text-xs bg-black/40 border border-slate-800 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">
              <code>
                <span className="text-slate-500 block mb-1">
                  {f.filePath}
                  {f.lineNumber ? `:${f.lineNumber}` : ""}
                </span>
                {f.lineContent && (
                  <span className="text-slate-300">{f.lineContent}</span>
                )}
              </code>
            </pre>
          )}
          <p className="text-xs text-slate-500 mt-3">
            <span className="text-slate-400">Remediation:</span> {f.remediation}
          </p>
        </article>
      ))}
    </section>
  )
}

export function DependenciesSection({
  findings,
  label,
}: {
  findings: DependencyFinding[]
  label: string
}) {
  if (findings.length === 0) return null
  return (
    <section className="space-y-3">
      <SectionHeader
        title={`${label} dependencies with known vulnerabilities`}
        count={findings.length}
      />
      {findings.map((f, i) => (
        <article
          key={i}
          className={`bg-slate-900 border border-slate-800 rounded-xl p-5 ${severityAccentClass(f.severity)}`}
        >
          <header className="flex items-center gap-2 flex-wrap mb-1">
            <h3 className="font-semibold font-mono">
              {f.package}@{f.version}
            </h3>
            <SeverityPill severity={f.severity} />
            {f.isTransitive && (
              <BadgePill
                label="transitive"
                title="Introduced via another dependency, not directly declared"
              />
            )}
            {f.source && <BadgePill label={f.source} tone="warn" />}
          </header>
          <p className="text-sm text-slate-400 mb-3">{f.title}</p>
          <div className="text-xs space-y-1 bg-black/40 border border-slate-800 rounded-lg p-3">
            {f.ghsa && (
              <div className="text-slate-400">
                <span className="text-slate-500">Advisory:</span>{" "}
                <span className="font-mono">{f.ghsa}</span>
              </div>
            )}
            <div className="text-slate-400">
              <span className="text-slate-500">Vulnerable versions:</span>{" "}
              <span className="font-mono text-red-400">
                {f.vulnerable_versions}
              </span>
            </div>
            {f.cvss_score !== null && (
              <div className="text-slate-400">
                <span className="text-slate-500">CVSS score:</span>{" "}
                <span className="font-mono">{f.cvss_score}</span>
              </div>
            )}
            <a
              href={f.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-block text-amber-400 hover:underline mt-1"
            >
              View advisory →
            </a>
          </div>
        </article>
      ))}
    </section>
  )
}

const LICENSE_RISK_LABELS: Record<LicenseFinding["risk"], string> = {
  "copyleft-strong": "strong copyleft",
  "copyleft-weak": "weak copyleft",
  missing: "no license",
  "non-standard": "non-standard",
}

export function LicensesSection({ findings }: { findings: LicenseFinding[] }) {
  if (findings.length === 0) return null
  return (
    <section className="space-y-3">
      <SectionHeader
        title="Dependency license / compliance risks"
        count={findings.length}
      />
      {findings.map((f, i) => (
        <article
          key={i}
          className={`bg-slate-900 border border-slate-800 rounded-xl p-5 ${severityAccentClass(f.severity)}`}
        >
          <header className="flex items-center gap-2 flex-wrap mb-1">
            <h3 className="font-semibold font-mono">
              {f.package}@{f.version}
            </h3>
            <SeverityPill severity={f.severity} />
            <BadgePill label={LICENSE_RISK_LABELS[f.risk]} tone="warn" />
            {f.isTransitive && (
              <BadgePill
                label="transitive"
                title="Introduced via another dependency, not directly declared"
              />
            )}
          </header>
          <p className="text-sm text-slate-400 mb-3">{f.description}</p>
          <div className="text-xs space-y-1 bg-black/40 border border-slate-800 rounded-lg p-3">
            <div className="text-slate-400">
              <span className="text-slate-500">License:</span>{" "}
              <span className="font-mono text-amber-400">
                {f.license ?? "none declared"}
              </span>
            </div>
            <a
              href={f.url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-block text-amber-400 hover:underline mt-1"
            >
              License details →
            </a>
          </div>
        </article>
      ))}
    </section>
  )
}

export function PrioritizedList({
  findings,
  fixContext,
}: {
  findings: PrioritizedFinding[]
  fixContext?: { owner: string; repo: string }
}) {
  if (findings.length === 0) return <AllClear />
  return (
    <section className="space-y-3">
      {findings.map((f, i) => (
        <FindingCard key={i} finding={f} fixContext={fixContext} />
      ))}
    </section>
  )
}

export function AllClear() {
  return (
    <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-8">
      <div className="flex items-start gap-4">
        <CheckCircleIcon
          size={40}
          className="text-green-400 shrink-0"
          aria-hidden="true"
        />
        <div className="min-w-0">
          <p className="font-mono text-xs text-green-400/80 mb-1">
            {"// scan complete · exit 0"}
          </p>
          <h2 className="font-display text-xl md:text-2xl font-bold text-green-300 mb-2 tracking-tight">
            no findings.
          </h2>
          <p className="text-slate-300 text-sm leading-relaxed">
            Nine detectors ran across secrets, sensitive files, vulnerable
            dependencies, SAST, IaC and supply chain — none of them tripped.
            Clean repo.
          </p>
        </div>
      </div>
    </div>
  )
}

export function SummaryCard({
  label,
  value,
  tone,
}: {
  label: string
  value: string
  tone: "neutral" | "red" | "orange" | "yellow" | "gray"
}) {
  const colors: Record<typeof tone, string> = {
    neutral: "bg-slate-900 border-slate-800 text-slate-300",
    red: "bg-red-500/10 border-red-500/20 text-red-400",
    orange: "bg-orange-500/10 border-orange-500/20 text-orange-400",
    yellow: "bg-yellow-500/10 border-yellow-500/20 text-yellow-400",
    gray: "bg-slate-500/10 border-slate-500/30 text-slate-400",
  }
  return (
    <div className={`rounded-xl border p-4 ${colors[tone]}`}>
      <div className="text-xs uppercase tracking-wider opacity-70">{label}</div>
      <div className="text-2xl font-bold mt-1">{value}</div>
    </div>
  )
}
