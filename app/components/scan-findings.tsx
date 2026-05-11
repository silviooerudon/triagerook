import type {
  CodeFinding,
  DependencyFinding,
  IaCFinding,
  SecretFinding,
  SensitiveFileFinding,
  Severity,
} from "@/lib/types"
import type { PrioritizedFinding } from "@/lib/risk"
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
      : "bg-blue-500/10 border-blue-500/20 text-blue-300"
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border ${cls}`} title={title}>
      {label}
    </span>
  )
}

export type AllFindings = {
  secrets: SecretFinding[]
  historySecrets: SecretFinding[]
  sensitiveFiles: SensitiveFileFinding[]
  codeFindings: CodeFinding[]
  iacFindings: IaCFinding[]
  npmDependencies: DependencyFinding[]
  pythonDependencies: DependencyFinding[]
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
    all.pythonDependencies.length
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
  return (
    <article
      className={`bg-slate-900 border border-slate-800 rounded-xl p-5 ${
        isTest ? "opacity-60" : ""
      }`}
    >
      <header className="flex items-center gap-2 flex-wrap mb-1">
        <h3 className="font-semibold">{finding.patternName}</h3>
        <SeverityPill severity={finding.severity} />
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
          className="bg-slate-900 border border-slate-800 rounded-xl p-5"
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
      {sorted.map((f, i) => (
        <article
          key={i}
          className={`bg-slate-900 border border-slate-800 rounded-xl p-5 ${
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
      ))}
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
          className="bg-slate-900 border border-slate-800 rounded-xl p-5"
        >
          <header className="flex items-center gap-2 flex-wrap mb-1">
            <h3 className="font-semibold">{f.ruleName}</h3>
            <SeverityPill severity={f.severity} />
            <BadgePill label={iacCategoryLabel(f.category)} />
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
          className="bg-slate-900 border border-slate-800 rounded-xl p-5"
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
              className="inline-block text-blue-400 hover:underline mt-1"
            >
              View advisory →
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
    <div className="bg-green-500/10 border border-green-500/20 rounded-xl p-8 text-center">
      <CheckCircleIcon
        size={40}
        className="mx-auto mb-3 text-green-400"
        aria-hidden="true"
      />
      <h2 className="text-xl font-semibold text-green-400 mb-2">
        No issues found
      </h2>
      <p className="text-slate-400 text-sm max-w-md mx-auto">
        We scanned for exposed secrets, sensitive files, vulnerable
        dependencies, code-level issues and misconfigurations. Everything
        looks clean.
      </p>
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
