import type { PrioritizedFinding } from "@/lib/risk"
import type {
  CodeFinding,
  DependencyFinding,
  IaCFinding,
  SecretFinding,
  SensitiveFileFinding,
  Severity,
} from "@/lib/types"
import { SeverityPill, BadgePill, severityAccentClass } from "./scan-findings"
import { FixPrButton } from "./fix-pr-button"
import { SuppressButton } from "./suppress-button"
import { findingSupportsFix } from "@/lib/fix-engines"

type FixContext = { owner: string; repo: string }

const KIND_LABELS: Record<PrioritizedFinding["kind"], string> = {
  secret: "secret",
  code: "code",
  iac: "iac",
  "sensitive-file": "sensitive file",
  dependency: "dependency",
}

function KindBadge({ kind }: { kind: PrioritizedFinding["kind"] }) {
  return (
    <span className="text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-full border bg-slate-800/60 border-slate-700 text-slate-400">
      {KIND_LABELS[kind]}
    </span>
  )
}

function FixtureBadge() {
  return (
    <BadgePill
      label="Test fixture"
      tone="warn"
      title="Path looks like tests/fixtures/mocks — probably a dummy value"
    />
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
    case "npm-scripts":
      return "npm lifecycle"
    case "supply-chain":
      return "Supply chain"
  }
}

// Card shell with a left-edge accent stripe colored by severity. The base
// rounded-xl + slate-900 stays identical; the accent is an additional
// border-l plus a faint tinted background, so a list of findings reads
// triage-first (critical jumps out, low blends in).
function CardShell({
  dim,
  severity,
  children,
}: {
  dim?: boolean
  severity?: Severity | "moderate"
  children: React.ReactNode
}) {
  const accent = severity ? severityAccentClass(severity) : ""
  return (
    <article
      className={`bg-slate-900 border border-slate-800 rounded-xl p-5 ${accent} ${
        dim ? "opacity-60" : ""
      }`}
    >
      {children}
    </article>
  )
}

function SecretFindingCard({ data }: { data: SecretFinding }) {
  const isFixture = data.likelyTestFixture ?? false
  const isHistory = data.source === "history"
  return (
    <CardShell dim={isFixture} severity={isFixture ? undefined : data.severity}>
      <header className="flex items-center gap-2 flex-wrap mb-1">
        <h3 className="font-semibold">{data.patternName}</h3>
        <SeverityPill severity={data.severity} />
        <KindBadge kind="secret" />
        {isFixture && <FixtureBadge />}
        {isHistory && data.commitSha && (
          <BadgePill
            label={`${data.commitSha.slice(0, 7)} • ${
              data.commitAuthor ?? "unknown"
            }`}
            title={data.commitDate}
          />
        )}
        {data.source && (
          <BadgePill
            label={data.source === "history" ? "in git history" : "in tree"}
            tone="warn"
          />
        )}
      </header>
      <p className="text-sm text-slate-400 mb-3">{data.description}</p>
      <pre className="font-mono text-xs bg-black/40 border border-slate-800 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">
        <code>
          <span className="text-slate-500 block mb-1">
            {data.filePath}:{data.lineNumber}
          </span>
          <span className="text-slate-300">{data.lineContent}</span>
        </code>
      </pre>
    </CardShell>
  )
}

function CodeFindingCard({ data }: { data: CodeFinding }) {
  const isFixture = data.likelyTestFixture ?? false
  return (
    <CardShell dim={isFixture} severity={isFixture ? undefined : data.severity}>
      <header className="flex items-center gap-2 flex-wrap mb-1">
        <h3 className="font-semibold">{data.ruleName}</h3>
        <SeverityPill severity={data.severity} />
        <KindBadge kind="code" />
        {data.cwe && <BadgePill label={data.cwe} />}
        {isFixture && <FixtureBadge />}
      </header>
      <p className="text-sm text-slate-400 mb-3">{data.description}</p>
      <pre className="font-mono text-xs bg-black/40 border border-slate-800 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">
        <code>
          <span className="text-slate-500 block mb-1">
            {data.filePath}:{data.lineNumber}
          </span>
          <span className="text-slate-300">{data.lineContent}</span>
        </code>
      </pre>
    </CardShell>
  )
}

function IaCFindingCard({ data }: { data: IaCFinding }) {
  return (
    <CardShell severity={data.severity}>
      <header className="flex items-center gap-2 flex-wrap mb-1">
        <h3 className="font-semibold">{data.ruleName}</h3>
        <SeverityPill severity={data.severity} />
        <KindBadge kind="iac" />
        <BadgePill label={iacCategoryLabel(data.category)} />
      </header>
      <p className="text-sm text-slate-400 mb-3">{data.description}</p>
      {(data.lineContent || data.lineNumber) && (
        <pre className="font-mono text-xs bg-black/40 border border-slate-800 rounded-lg p-3 overflow-x-auto whitespace-pre-wrap">
          <code>
            <span className="text-slate-500 block mb-1">
              {data.filePath}
              {data.lineNumber ? `:${data.lineNumber}` : ""}
            </span>
            {data.lineContent && (
              <span className="text-slate-300">{data.lineContent}</span>
            )}
          </code>
        </pre>
      )}
      <p className="text-xs text-slate-500 mt-3">
        <span className="text-slate-400">Remediation:</span> {data.remediation}
      </p>
    </CardShell>
  )
}

function SensitiveFileFindingCard({ data }: { data: SensitiveFileFinding }) {
  return (
    <CardShell severity={data.severity}>
      <header className="flex items-center gap-2 flex-wrap mb-1">
        <h3 className="font-semibold">{data.name}</h3>
        <SeverityPill severity={data.severity} />
        <KindBadge kind="sensitive-file" />
      </header>
      <p className="text-sm text-slate-400 mb-3">{data.description}</p>
      <pre className="font-mono text-xs bg-black/40 border border-slate-800 rounded-lg p-3 overflow-x-auto">
        <code className="text-slate-300">{data.filePath}</code>
      </pre>
      <p className="text-xs text-slate-500 mt-3">
        <span className="text-slate-400">Remediation:</span> {data.remediation}
      </p>
    </CardShell>
  )
}

function DependencyFindingCard({ data }: { data: DependencyFinding }) {
  return (
    <CardShell severity={data.severity}>
      <header className="flex items-center gap-2 flex-wrap mb-1">
        <h3 className="font-semibold font-mono">
          {data.package}@{data.version}
        </h3>
        <SeverityPill severity={data.severity} />
        <KindBadge kind="dependency" />
        {data.isTransitive && (
          <BadgePill
            label="transitive"
            title="Introduced via another dependency, not directly declared"
          />
        )}
        {data.source && <BadgePill label={data.source} tone="warn" />}
      </header>
      <p className="text-sm text-slate-400 mb-3">{data.title}</p>
      <div className="text-xs space-y-1 bg-black/40 border border-slate-800 rounded-lg p-3">
        {data.ghsa && (
          <div className="text-slate-400">
            <span className="text-slate-500">Advisory:</span>{" "}
            <span className="font-mono">{data.ghsa}</span>
          </div>
        )}
        <div className="text-slate-400">
          <span className="text-slate-500">Vulnerable versions:</span>{" "}
          <span className="font-mono text-red-400">
            {data.vulnerable_versions}
          </span>
        </div>
        {data.cvss_score !== null && (
          <div className="text-slate-400">
            <span className="text-slate-500">CVSS score:</span>{" "}
            <span className="font-mono">{data.cvss_score}</span>
          </div>
        )}
        <a
          href={data.url}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-block text-amber-400 hover:underline mt-1"
        >
          View advisory →
        </a>
      </div>
    </CardShell>
  )
}

export function FindingCard({
  finding,
  fixContext,
}: {
  finding: PrioritizedFinding
  fixContext?: FixContext
}) {
  const showFixButton =
    fixContext !== undefined && findingSupportsFix(finding) !== null

  const card = (() => {
    switch (finding.kind) {
      case "secret":
        return <SecretFindingCard data={finding.data} />
      case "code":
        return <CodeFindingCard data={finding.data} />
      case "iac":
        return <IaCFindingCard data={finding.data} />
      case "sensitive-file":
        return <SensitiveFileFindingCard data={finding.data} />
      case "dependency":
        return <DependencyFindingCard data={finding.data} />
    }
  })()

  if (!fixContext) return card

  return (
    <div className="space-y-2">
      {card}
      <div className="flex justify-end gap-2">
        <SuppressButton
          owner={fixContext.owner}
          repo={fixContext.repo}
          finding={finding}
        />
        {showFixButton && (
          <FixPrButton
            owner={fixContext.owner}
            repo={fixContext.repo}
            finding={finding}
          />
        )}
      </div>
    </div>
  )
}

export default FindingCard
