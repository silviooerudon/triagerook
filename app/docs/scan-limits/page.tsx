import type { Metadata } from "next"
import { DocHeader, Section, Callout, Code } from "../_components/doc-ui"

export const metadata: Metadata = {
  title: "Scan limits",
  description:
    "Every per-run scan limit with its real value: 1000 files, a 55s time budget, 1 MB max file size, 30 commits of git history, 200 KB max patch. Plus the paths skipped by design and why each limit exists.",
}

// Values mirror the code exactly:
//   files / time     — lib/scan-budget.ts (DEFAULTS + LIMITS)
//   max file size    — lib/scan.ts (MAX_FILE_SIZE)
//   history depth    — lib/product-constants.ts (HISTORY_COMMIT_LIMIT)
//   max patch size   — lib/history.ts (MAX_PATCH_SIZE)
const LIMITS: {
  limit: string
  value: string
  ceiling: string
  source: string
}[] = [
  {
    limit: "Files scanned per run",
    value: "1,000",
    ceiling: "10,000",
    source: "SCAN_MAX_FILES",
  },
  {
    limit: "Wall-clock time budget",
    value: "55 seconds",
    ceiling: "290 seconds",
    source: "SCAN_MAX_TIME_MS",
  },
  {
    limit: "Max single file size",
    value: "1 MB",
    ceiling: "—",
    source: "MAX_FILE_SIZE",
  },
  {
    limit: "Git-history depth",
    value: "30 commits",
    ceiling: "—",
    source: "HISTORY_COMMIT_LIMIT",
  },
  {
    limit: "Max patch size per commit",
    value: "200 KB",
    ceiling: "—",
    source: "MAX_PATCH_SIZE",
  },
]

const SKIP_PATHS = [
  "node_modules/",
  ".next/",
  "dist/",
  "build/",
  "target/",
  "vendor/",
  ".git/",
  "coverage/",
  "out/",
  "*.min.js / *.min.css",
  "*.lock",
  "package-lock.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "*.map (sourcemaps)",
]

export default function ScanLimitsPage() {
  return (
    <div className="max-w-3xl">
      <DocHeader eyebrow="scanning" title="Scan limits">
        A scan is a single serverless request, so it runs against fixed budgets.
        Here is every limit with its real value, the paths skipped by design, and
        why each cap exists. When a scan hits a limit, the result is flagged as
        truncated so &ldquo;0 findings&rdquo; is never mistaken for &ldquo;actually
        clean.&rdquo;
      </DocHeader>

      <Section title="The limits">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-left">
                <th className="py-2 pr-4 font-mono text-xs uppercase tracking-wider text-slate-500">
                  Limit
                </th>
                <th className="py-2 pr-4 font-mono text-xs uppercase tracking-wider text-slate-500">
                  Default
                </th>
                <th className="py-2 pr-4 font-mono text-xs uppercase tracking-wider text-slate-500">
                  Max
                </th>
                <th className="py-2 font-mono text-xs uppercase tracking-wider text-slate-500">
                  Constant
                </th>
              </tr>
            </thead>
            <tbody>
              {LIMITS.map((l) => (
                <tr key={l.limit} className="border-b border-slate-800/60">
                  <td className="py-3 pr-4 font-medium text-slate-200">
                    {l.limit}
                  </td>
                  <td className="py-3 pr-4 whitespace-nowrap font-mono text-amber-300">
                    {l.value}
                  </td>
                  <td className="py-3 pr-4 whitespace-nowrap font-mono text-slate-400">
                    {l.ceiling}
                  </td>
                  <td className="py-3 font-mono text-xs text-slate-500">
                    {l.source}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-4 text-sm leading-relaxed text-slate-400">
          The file count and time budget are configurable via environment
          variables; the values above are the defaults the public deployment runs
          with. The <Code>Max</Code> column is the hard ceiling the code clamps to
          even if an env var asks for more.
        </p>
      </Section>

      <Section title="Why the file and time caps exist">
        <Callout variant="info" title="Serverless timeout">
          <p>
            A scan runs inside a single serverless function invocation. On Vercel
            Hobby that invocation is capped at 60 seconds, so the default
            55-second budget leaves a few seconds of headroom to finish post-loop
            work (the git-history pass and the posture / IAM checks) and return a
            response instead of being killed mid-flight. The 290-second ceiling
            exists for deployments on Vercel Pro, whose function limit is 300
            seconds.
          </p>
        </Callout>
        <p className="leading-relaxed text-slate-300">
          The 1,000-file default is the companion cap: it is the number of files
          that actually fits inside the time budget. Raising the time limit without
          raising the file limit would not let you feel the extra time, which is
          why the two move together. Files are fetched in batches and the time
          budget is checked between batches, so a scan stops cleanly at the
          boundary rather than being terminated.
        </p>
      </Section>

      <Section title="Which files get the budget">
        <p className="mb-4 leading-relaxed text-slate-300">
          Before the file cap is applied, candidate files are prioritized so the
          budget is spent on the code most likely to contain real findings: source
          files rank above tests, fixtures, examples, and docs. If the repo has
          more scannable files than the cap, the lowest-priority ones are skipped
          and the result is marked truncated.
        </p>
        <p className="leading-relaxed text-slate-300">
          Only text-based source files are eligible at all &mdash; common code,
          config, and infrastructure extensions, plus a few extensionless names
          (<Code>Dockerfile</Code>, <Code>Makefile</Code>, and{" "}
          <Code>.env</Code> files). A file that looks binary (more than 10% of its
          first 1,000 characters are non-printable) is skipped even if its
          extension matched.
        </p>
      </Section>

      <Section title="Paths skipped by design">
        <p className="mb-4 leading-relaxed text-slate-300">
          These paths are never scanned, regardless of the file cap. They are
          vendored code, build output, and lockfiles &mdash; noise that would
          waste the budget and produce findings you cannot act on:
        </p>
        <ul className="grid grid-cols-2 gap-x-6 gap-y-1.5 sm:grid-cols-3">
          {SKIP_PATHS.map((p) => (
            <li key={p} className="font-mono text-xs text-slate-400">
              {p}
            </li>
          ))}
        </ul>
        <p className="mt-4 text-sm leading-relaxed text-slate-400">
          Want to skip more (or re-include something)? That is what{" "}
          <Code>.repoguardignore</Code> is for &mdash; see{" "}
          <a href="/docs/suppressions" className="text-amber-400 hover:underline">
            Suppressions
          </a>
          .
        </p>
      </Section>

      <Section title="Git-history scan">
        <p className="leading-relaxed text-slate-300">
          On top of the current file tree, TriageRook replays the{" "}
          <strong>30 most recent commits</strong> looking for secrets that were
          added and later removed &mdash; a credential deleted in a follow-up
          commit is still in the history and still leaked. Any single commit patch
          larger than 200 KB is skipped to keep the history pass inside the time
          budget. The history scan is best-effort: if it hits a GitHub rate limit
          or errors, it is skipped and the scan reports that it was skipped rather
          than implying history is clean.
        </p>
      </Section>

      <Section title="Large monorepos">
        <p className="leading-relaxed text-slate-300">
          If a repository is too large for one pass, you can narrow a scan to a
          subfolder (for example <Code>packages/auth</Code>). The file cap is then
          spent entirely within that subtree, and the result header makes clear it
          was a narrow scan so a clean result for one package is not read as a clean
          result for the whole repo.
        </p>
      </Section>

      <div className="mt-12 border-t border-slate-800/60 pt-8 text-sm text-slate-500">
        <p>
          Hit a limit and think a repo of your size should fit?{" "}
          <a
            href="https://github.com/silviooerudon/triagerook/issues/new?title=Scan%20limits%20feedback"
            target="_blank"
            rel="noopener noreferrer"
            className="text-amber-400 hover:underline"
          >
            Tell us
          </a>
          .
        </p>
      </div>
    </div>
  )
}
