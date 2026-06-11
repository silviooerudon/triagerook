import Link from "next/link"
import type { Metadata } from "next"
import { DocHeader, Section, Callout, Code } from "../_components/doc-ui"

export const metadata: Metadata = {
  title: "Posture score",
  description:
    "How TriageRook grades repository posture: 17 signals across branch protection, documentation, dependency hygiene, and governance, with their real weights, the A–F scale, and why unknown signals are excluded from the math.",
}

// Mirrors the signal weights (W) and labels in lib/posture.ts exactly. The raw
// weights sum to 115, but the score is the percentage of *assessable* points
// earned, so it always lands on 0–100 (see "How the score is computed").
type Signal = {
  label: string
  weight: number
  note?: string
}
type Group = {
  id: string
  label: string
  total: number
  signals: Signal[]
}

const GROUPS: Group[] = [
  {
    id: "branch",
    label: "Branch protection",
    total: 30,
    signals: [
      { label: "Branch protection enabled on main", weight: 15 },
      {
        label: "Pull request review required",
        weight: 5,
        note: "unknown if details need admin and no ruleset resolves it",
      },
      {
        label: "Status checks required before merge",
        weight: 5,
        note: "unknown if details need admin and no ruleset resolves it",
      },
      {
        label: "Branch protection applied to admins",
        weight: 5,
        note: "unknown if details need admin and no ruleset resolves it",
      },
    ],
  },
  {
    id: "docs",
    label: "Documentation",
    total: 30,
    signals: [
      { label: "SECURITY.md present", weight: 10 },
      { label: "LICENSE file present", weight: 8 },
      { label: "CODEOWNERS file present", weight: 5 },
      { label: "README is substantial (>= 500 chars)", weight: 4 },
      { label: "README mentions security or SECURITY.md", weight: 3 },
    ],
  },
  {
    id: "deps",
    label: "Dependency hygiene",
    total: 25,
    signals: [
      { label: "Dependabot or Renovate configured", weight: 12 },
      { label: "Lockfile committed", weight: 8 },
      { label: ".gitignore covers node_modules and .env", weight: 5 },
    ],
  },
  {
    id: "governance",
    label: "Governance",
    total: 30,
    signals: [
      {
        label: "Recent commits are signed (verified)",
        weight: 10,
        note: "full at >= 80% verified, half at >= 50%; unknown if the ratio can't be read",
      },
      {
        label: "Two-factor enforcement on the organization",
        weight: 5,
        note: "unknown for user-owned repos or when read:org is not granted",
      },
      {
        label: "Secret scanning + push protection enabled",
        weight: 6,
        note: "unknown when the admin-only status isn't visible",
      },
      {
        label: "Default GITHUB_TOKEN permissions are read-only",
        weight: 5,
        note: "unknown when the admin-only setting isn't visible",
      },
      {
        label: "Releases are signed / publish build provenance",
        weight: 4,
        note: "unknown when there are no workflows to inspect",
      },
    ],
  },
]

const GRADES: { grade: string; range: string; cls: string }[] = [
  { grade: "A", range: ">= 90", cls: "text-emerald-300 border-emerald-500/30" },
  { grade: "B", range: "75 – 89", cls: "text-emerald-300 border-emerald-500/30" },
  { grade: "C", range: "60 – 74", cls: "text-yellow-300 border-yellow-500/30" },
  { grade: "D", range: "40 – 59", cls: "text-orange-300 border-orange-500/30" },
  { grade: "F", range: "< 40", cls: "text-red-300 border-red-500/30" },
]

export default function PostureScorePage() {
  return (
    <div className="max-w-3xl">
      <DocHeader eyebrow="reference" title="Posture score">
        Most detectors look for a specific finding. The posture score grades how
        the repository is <em>set up</em> &mdash; the governance and hardening that
        prevents whole classes of finding. It is 17 signals across four groups,
        rolled into a single A&ndash;F grade. This page lists every signal, its
        real weight, and exactly how the grade is computed.
      </DocHeader>

      <Section title="How the score is computed">
        <p className="leading-relaxed text-slate-300">
          Each signal is worth a fixed number of points. Your score is the{" "}
          <strong>percentage of assessable points you earned</strong> &mdash;
          earned points divided by the points of every signal that could actually
          be evaluated, times 100. That keeps the result on a clean 0&ndash;100
          scale regardless of how the underlying weights sum.
        </p>
        <Callout variant="info" title="Unknown signals are excluded, not failed">
          <p>
            When a signal can&apos;t be inspected &mdash; an admin-only setting on
            a public scan, org MFA without <Code>read:org</Code>, a repo with no
            workflows to check for provenance &mdash; it is marked{" "}
            <Code>unknown</Code> and dropped from <em>both</em> sides of that
            fraction. It neither earns points nor counts against you. A missing
            admin scope therefore cannot tank an otherwise-strong repo&apos;s
            grade.
          </p>
        </Callout>
        <p className="leading-relaxed text-slate-300">
          The breakdown also surfaces up to five <strong>quick wins</strong> &mdash;
          the highest-value signals you have not yet satisfied (and can act on).
          Unknown signals are never offered as quick wins, since we can&apos;t
          recommend fixing something we couldn&apos;t evaluate.
        </p>
      </Section>

      <Section title="Grade scale">
        <div className="flex flex-wrap gap-3">
          {GRADES.map((g) => (
            <div
              key={g.grade}
              className={`flex items-baseline gap-2 rounded-lg border bg-slate-900/40 px-4 py-2 ${g.cls}`}
            >
              <span className="font-display text-xl font-bold">{g.grade}</span>
              <span className="font-mono text-xs text-slate-400">{g.range}</span>
            </div>
          ))}
        </div>
      </Section>

      <Section title="The 17 signals">
        <div className="space-y-8">
          {GROUPS.map((group) => (
            <div key={group.id}>
              <div className="mb-2 flex items-baseline justify-between border-b border-slate-800 pb-1">
                <h3 className="font-medium text-slate-100">{group.label}</h3>
                <span className="font-mono text-xs text-slate-500">
                  {group.signals.length} signals &middot; {group.total} pts
                </span>
              </div>
              <ul className="divide-y divide-slate-800/60">
                {group.signals.map((s) => (
                  <li
                    key={s.label}
                    className="flex items-start justify-between gap-4 py-2.5"
                  >
                    <div className="min-w-0">
                      <p className="text-sm text-slate-300">{s.label}</p>
                      {s.note && (
                        <p className="mt-0.5 text-xs text-slate-500">{s.note}</p>
                      )}
                    </div>
                    <span className="shrink-0 font-mono text-xs text-amber-300">
                      {s.weight} pts
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
        <p className="mt-4 text-sm leading-relaxed text-slate-400">
          That is 17 signals. The raw weights sum to 115, but because the score is
          a percentage of <em>assessable</em> points, the absolute total never
          pushes a result above 100 &mdash; a repo that earns every assessable
          signal scores 100 and grades A.
        </p>
      </Section>

      <Section title="A note on signed commits">
        <p className="leading-relaxed text-slate-300">
          The signed-commits signal is graded on a ratio of the recent sampled
          commits: full points at 80% or more verified, half points at 50% or more,
          zero below that. If a branch ruleset enforces signing, the signal is
          satisfied outright. If the verification ratio can&apos;t be determined at
          all, the signal is <Code>unknown</Code> rather than zero.
        </p>
      </Section>

      <div className="mt-12 border-t border-slate-800/60 pt-8 text-sm text-slate-500">
        <p>
          See the posture score on a real repo by{" "}
          <Link href="/" className="text-amber-400 hover:underline">
            running a scan
          </Link>
          , or read how each underlying detector works in{" "}
          <Link href="/docs/detectors" className="text-amber-400 hover:underline">
            Detectors
          </Link>
          .
        </p>
      </div>
    </div>
  )
}
