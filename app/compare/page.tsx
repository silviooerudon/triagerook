import type { Metadata } from "next";
import Link from "next/link";
import { PublicNav } from "@/app/components/public-nav";

export const metadata: Metadata = {
  title: "Compare",
  description:
    "An honest comparison of TriageRook with GitHub native scanning, Snyk, and TruffleHog / Gitleaks. Where TriageRook wins, where it does not, and when to keep the tools you already run.",
  alternates: { canonical: "/compare" },
};

// Cell mark drives the small status label. "info" renders text only (no
// yes/no), used for rows like price where every tool has an answer.
type Mark = "yes" | "partial" | "no" | "info";

type Cell = { mark: Mark; text: string };

type Row = {
  capability: string;
  note?: string;
  triagerook: Cell;
  github: Cell;
  snyk: Cell;
  trufflehog: Cell;
};

const TOOLS = [
  { key: "triagerook", label: "TriageRook" },
  { key: "github", label: "GitHub native" },
  { key: "snyk", label: "Snyk" },
  { key: "trufflehog", label: "TruffleHog / Gitleaks" },
] as const;

// Every competitor cell is kept to claims defensible from their public
// docs/marketing. Where a competitor capability is ambiguous, the cell is
// softened to "partial" with a factual note rather than asserting absence.
const ROWS: Row[] = [
  {
    capability: "Zero setup - no install, no agent, no CI config",
    triagerook: { mark: "yes", text: "Paste a public repo URL, or sign in with GitHub." },
    github: { mark: "partial", text: "Built into GitHub, but enabled per repo; CodeQL runs as an Actions workflow." },
    snyk: { mark: "no", text: "Account plus a Git, CLI, or IDE integration." },
    trufflehog: { mark: "no", text: "Install the CLI, or add it as a CI step." },
  },
  {
    capability: "Hosted scan of a public repo with no login",
    triagerook: { mark: "yes", text: "Anonymous scan, rate-limited per IP and per repo." },
    github: { mark: "no", text: "Runs inside repos you already control." },
    snyk: { mark: "no", text: "Account required before any scan." },
    trufflehog: { mark: "no", text: "CLI runs locally against a clone." },
  },
  {
    capability: "Secrets detection",
    triagerook: { mark: "yes", text: "60+ patterns, entropy fallback for custom formats, always masked, plus a 30-commit history replay." },
    github: { mark: "yes", text: "Secret scanning and push protection, free on public repos." },
    snyk: { mark: "partial", text: "Not a dedicated secrets product; SCA / SAST / IaC are the focus." },
    trufflehog: { mark: "yes", text: "Core purpose - regex plus entropy across full git history." },
  },
  {
    capability: "Deep code analysis (SAST)",
    note: "If you already run CodeQL or Snyk Code, keep them - they go deeper on code analysis.",
    triagerook: { mark: "partial", text: "TypeScript / JavaScript AST (28 rules) plus regex for other languages. A fast first pass, shallower than a full dataflow engine." },
    github: { mark: "yes", text: "CodeQL - semantic dataflow analysis across many languages." },
    snyk: { mark: "yes", text: "Snyk Code - a dedicated SAST engine." },
    trufflehog: { mark: "no", text: "Secrets only, not a code analyzer." },
  },
  {
    capability: "Dependency / SCA scanning",
    triagerook: { mark: "yes", text: "npm advisories plus OSV.dev for PyPI, Go, RubyGems, Maven / Gradle, Composer; container OS-package CVEs via a committed Trivy SARIF." },
    github: { mark: "yes", text: "Dependabot across many package ecosystems." },
    snyk: { mark: "yes", text: "A core product, with the broadest ecosystem coverage of the four." },
    trufflehog: { mark: "no", text: "Not a dependency scanner." },
  },
  {
    capability: "Supply-chain heuristics (typosquatting, install hooks)",
    triagerook: { mark: "yes", text: "Damerau-Levenshtein typosquatting plus install-hook abuse detection (npm, PyPI)." },
    github: { mark: "partial", text: "Dependabot vulnerability alerts; no dedicated typosquatting or install-hook heuristic." },
    snyk: { mark: "partial", text: "Flags known malicious packages from its advisory database." },
    trufflehog: { mark: "no", text: "Not in scope." },
  },
  {
    capability: "GitHub OIDC trust and repo IAM posture",
    note: "Scoped to GitHub Actions OIDC trust and repo-level IAM posture. Cloud-IaC IAM (Terraform policy linting) is a different surface.",
    triagerook: { mark: "yes", text: "12 checks: OIDC trust misconfiguration, privilege-escalation paths, and admin-equivalent access." },
    github: { mark: "no", text: "Not offered as a static check." },
    snyk: { mark: "no", text: "No GitHub Actions OIDC trust analysis." },
    trufflehog: { mark: "no", text: "Not in scope." },
  },
  {
    capability: "Repo posture grade",
    triagerook: { mark: "yes", text: "An A-F grade across 17 signals: branch protection, CODEOWNERS, signed commits, Dependabot, secret scanning, least-privilege GITHUB_TOKEN, release provenance, and more." },
    github: { mark: "partial", text: "Individual signals appear in repo settings and the security overview; not rolled into a single score." },
    snyk: { mark: "no", text: "Not offered." },
    trufflehog: { mark: "no", text: "Not offered." },
  },
  {
    capability: "Price",
    triagerook: { mark: "info", text: "Free during the open beta." },
    github: { mark: "info", text: "Free: secret scanning, Dependabot, and CodeQL on public repos. GitHub Advanced Security is paid for private repos." },
    snyk: { mark: "info", text: "Free tier plus paid plans." },
    trufflehog: { mark: "info", text: "Free and open source." },
  },
];

const MARK_LABEL: Record<Mark, string> = {
  yes: "yes",
  partial: "partial",
  no: "no",
  info: "",
};

function markClass(mark: Mark): string {
  switch (mark) {
    case "yes":
      return "text-amber-400";
    case "partial":
      return "text-slate-300";
    case "no":
      return "text-slate-600";
    case "info":
      return "text-slate-500";
  }
}

function CellBody({ cell }: { cell: Cell }) {
  const label = MARK_LABEL[cell.mark];
  return (
    <div className="space-y-1.5">
      {label && (
        <div
          className={`font-mono text-[11px] uppercase tracking-wider ${markClass(
            cell.mark,
          )}`}
        >
          {label}
        </div>
      )}
      <p className="text-sm text-slate-400 leading-relaxed">{cell.text}</p>
    </div>
  );
}

export default function ComparePage() {
  return (
    <>
      <PublicNav />
      <article className="max-w-6xl mx-auto px-6 py-16">
        <div className="font-mono text-xs text-amber-400 mb-3">
          {"// compare"}
        </div>
        <h1 className="font-display text-3xl md:text-4xl font-bold tracking-tight mb-4">
          How TriageRook compares
        </h1>
        <p className="text-slate-400 max-w-2xl mb-8 leading-relaxed">
          The honest version. TriageRook is not trying to replace CodeQL, Snyk,
          or your existing CI scanners - it is the zero-setup first pass you can
          run on any public repo in one click, plus an IAM lens those tools do
          not offer. Here is where it wins and where it does not.
        </p>

        <aside
          role="note"
          className="mb-12 rounded-md border-l-[3px] border-l-sky-500 bg-slate-900/40 p-5"
        >
          <p className="font-mono text-xs text-sky-300 mb-1">
            {"// honesty policy"}
          </p>
          <p className="text-sm leading-relaxed text-slate-300">
            Every cell about another tool is kept to what their public docs
            state. If you spot a row that is wrong or out of date, that is a bug
            -{" "}
            <a
              href="https://github.com/silviooerudon/triagerook/issues"
              target="_blank"
              rel="noopener noreferrer"
              className="text-sky-300 hover:text-sky-200 border-b border-dashed border-sky-500/50 transition"
            >
              open an issue
            </a>{" "}
            and it gets fixed.
          </p>
        </aside>

        {/* DESKTOP TABLE */}
        <div className="hidden md:block border border-slate-800 rounded-lg overflow-hidden">
          <table className="w-full border-collapse">
            <thead>
              <tr className="bg-slate-900/40 text-left align-bottom">
                <th className="w-[22%] px-5 py-4 font-mono text-xs text-slate-500 uppercase tracking-wider font-medium">
                  capability
                </th>
                {TOOLS.map((tool) => (
                  <th
                    key={tool.key}
                    className={`w-[19.5%] px-5 py-4 align-bottom ${
                      tool.key === "triagerook"
                        ? "border-l-[3px] border-l-amber-400 bg-slate-900/40"
                        : ""
                    }`}
                  >
                    <span
                      className={`font-display text-sm font-bold tracking-tight ${
                        tool.key === "triagerook"
                          ? "text-amber-400"
                          : "text-slate-200"
                      }`}
                    >
                      {tool.label}
                    </span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {ROWS.map((row) => (
                <tr key={row.capability} className="align-top">
                  <th
                    scope="row"
                    className="px-5 py-5 text-left font-medium text-sm text-slate-200 leading-snug"
                  >
                    {row.capability}
                    {row.note && (
                      <span className="mt-2 block font-mono text-[11px] font-normal text-slate-500 leading-relaxed">
                        {row.note}
                      </span>
                    )}
                  </th>
                  <td className="px-5 py-5 border-l-[3px] border-l-amber-400 bg-slate-900/20">
                    <CellBody cell={row.triagerook} />
                  </td>
                  <td className="px-5 py-5">
                    <CellBody cell={row.github} />
                  </td>
                  <td className="px-5 py-5">
                    <CellBody cell={row.snyk} />
                  </td>
                  <td className="px-5 py-5">
                    <CellBody cell={row.trufflehog} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* MOBILE STACKED CARDS */}
        <div className="md:hidden space-y-5">
          {ROWS.map((row) => (
            <div
              key={row.capability}
              className="border border-slate-800 rounded-lg overflow-hidden"
            >
              <div className="bg-slate-900/40 px-4 py-3 border-b border-slate-800/60">
                <p className="text-sm font-medium text-slate-200 leading-snug">
                  {row.capability}
                </p>
                {row.note && (
                  <p className="mt-1.5 font-mono text-[11px] text-slate-500 leading-relaxed">
                    {row.note}
                  </p>
                )}
              </div>
              <div className="divide-y divide-slate-800/60">
                {TOOLS.map((tool) => (
                  <div
                    key={tool.key}
                    className={`px-4 py-3 ${
                      tool.key === "triagerook"
                        ? "border-l-[3px] border-l-amber-400 bg-slate-900/20"
                        : ""
                    }`}
                  >
                    <div
                      className={`font-mono text-[11px] mb-1.5 ${
                        tool.key === "triagerook"
                          ? "text-amber-400"
                          : "text-slate-400"
                      }`}
                    >
                      {tool.label}
                    </div>
                    <CellBody cell={row[tool.key]} />
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* LEGEND */}
        <div className="mt-6 flex flex-wrap items-center gap-x-6 gap-y-2 font-mono text-[11px] text-slate-500">
          <span>
            <span className="text-amber-400 uppercase tracking-wider">yes</span>{" "}
            supported
          </span>
          <span>
            <span className="text-slate-300 uppercase tracking-wider">
              partial
            </span>{" "}
            limited or not the tool&apos;s focus
          </span>
          <span>
            <span className="text-slate-600 uppercase tracking-wider">no</span>{" "}
            not offered
          </span>
        </div>

        {/* SAST HONESTY CALLOUT */}
        <aside className="mt-12 rounded-md border-l-[3px] border-l-amber-400 bg-slate-900/40 p-5">
          <p className="font-mono text-xs text-amber-400 mb-2">
            {"// on code analysis"}
          </p>
          <p className="text-sm leading-relaxed text-slate-300">
            TriageRook&apos;s SAST is a fast first pass - TypeScript / JavaScript
            AST rules plus targeted regex for other languages. It is not a
            replacement for a full semantic dataflow engine.{" "}
            <span className="text-slate-100">
              If you already run CodeQL or Snyk Code, keep them.
            </span>{" "}
            TriageRook earns its place on the secrets, dependency, supply-chain,
            IaC, and IAM surfaces - and on being the scan you will actually run
            because it takes one click.
          </p>
        </aside>

        {/* CTA */}
        <div className="mt-12 border-t border-slate-800/60 pt-10">
          <h2 className="font-display text-2xl font-bold tracking-tight mb-3">
            Try it on a repo you know.
          </h2>
          <p className="text-slate-400 text-sm mb-6 max-w-xl leading-relaxed">
            The fastest way to judge any of these claims is to run it. Scan a
            public repo - no login, no install.
          </p>
          <div className="flex flex-wrap items-center gap-4">
            <Link
              href="/"
              className="px-5 py-3 font-mono text-sm bg-amber-400 text-slate-950 hover:bg-amber-300 transition font-semibold"
            >
              scan a public repo
            </Link>
            <Link
              href="/signin"
              className="font-mono text-xs text-slate-500 hover:text-amber-400 transition"
            >
              → or sign in with github to scan your own repos
            </Link>
          </div>
        </div>
      </article>
    </>
  );
}
