import type { Metadata } from "next"
import { DocHeader } from "../_components/doc-ui"

export const metadata: Metadata = {
  title: "Changelog",
  description:
    "What shipped in TriageRook, by date — derived from merged pull requests. Detectors added, the rebrand from RepoGuard, and the documentation launch.",
}

// Each entry is derived from real merged PRs on main (no invented history).
// PR numbers are noted so anything here can be traced back to the diff.
type Entry = { date: string; title: string; items: string[]; prs: string }

const CHANGELOG: Entry[] = [
  {
    date: "2026-06-11",
    title: "Documentation hub",
    items: [
      "Launched /docs: a sidebar-navigated documentation section inside the product.",
      "Trust pages — security & data handling, scan limits, suppressions.",
      "Reference — detector overview and the 17-signal posture score.",
    ],
    prs: "#121, #122",
  },
  {
    date: "2026-06-10",
    title: "Landing & comparison honesty",
    items: [
      "One-click positioning hero and an honest /compare page (where TriageRook wins and where it doesn't).",
      "Marketing counts bound to the rule catalog at the source, so numbers can't drift.",
    ],
    prs: "#118, #119, #120",
  },
  {
    date: "2026-05-31",
    title: "Detection surface expansion",
    items: [
      "Container OS-package CVEs ingested from a committed Trivy SARIF report.",
      "Dedicated Helm values scanner and a hardcoded-secret-in-workflow-env rule.",
      "A round of detector gap-closing and false-positive fixes.",
    ],
    prs: "#107–#112",
  },
  {
    date: "2026-05-29",
    title: "New detectors",
    items: [
      "AI-generated insecure-code detector (placeholder creds, deferred-security TODOs, swallowed exceptions).",
      "Business-logic / broken-access-control scanner (IDOR, mass assignment, privilege escalation).",
      "License scanning for PyPI / Go / RubyGems via deps.dev.",
    ],
    prs: "#99–#101",
  },
  {
    date: "2026-05-28",
    title: "Major detector wave",
    items: [
      "Terraform and Kubernetes IaC misconfiguration scanners.",
      "Open-source license / compliance scanner.",
      "Cloud IAM-in-code scanner.",
      "Opt-in secret liveness validation.",
      "Context-aware (framework-gated) SAST.",
      "Blast-radius and attack-path correlation over findings.",
    ],
    prs: "#89–#95",
  },
  {
    date: "2026-05-22",
    title: "Rebrand to TriageRook",
    items: [
      "RepoGuard became TriageRook.",
      "Production moved to www.triagerook.com.",
    ],
    prs: "#80, #84",
  },
  {
    date: "2026-05-16",
    title: "Launch readiness",
    items: [
      "Tunable rate limits and structured scan-event logging.",
      "Server-side GitHub token to lift the anonymous-scan API quota under load.",
    ],
    prs: "#75",
  },
]

export default function ChangelogPage() {
  return (
    <div className="max-w-3xl">
      <DocHeader eyebrow="reference" title="Changelog">
        What shipped, by date &mdash; derived from merged pull requests, not a
        hand-written narrative. PR numbers are noted so any line here traces back
        to the actual diff on{" "}
        <a
          href="https://github.com/silviooerudon/triagerook/pulls?q=is%3Apr+is%3Amerged"
          target="_blank"
          rel="noopener noreferrer"
          className="text-amber-400 hover:underline"
        >
          GitHub
        </a>
        .
      </DocHeader>

      <div className="space-y-10">
        {CHANGELOG.map((entry) => (
          <section key={entry.date} className="border-l-[3px] border-slate-700 pl-5">
            <div className="mb-2 flex flex-wrap items-baseline gap-x-3">
              <time className="font-mono text-xs text-amber-400">{entry.date}</time>
              <h2 className="font-medium text-slate-100">{entry.title}</h2>
              <span className="font-mono text-xs text-slate-600">{entry.prs}</span>
            </div>
            <ul className="list-disc space-y-1 pl-5 text-sm leading-relaxed text-slate-300 marker:text-slate-600">
              {entry.items.map((it) => (
                <li key={it}>{it}</li>
              ))}
            </ul>
          </section>
        ))}
      </div>

      <div className="mt-12 border-t border-slate-800/60 pt-8 text-sm text-slate-500">
        <p>
          Earlier history (the initial detector set, secret patterns, SARIF export,
          and the public-scan path) predates this log &mdash; browse the full
          merged-PR history on GitHub for the complete record.
        </p>
      </div>
    </div>
  )
}
