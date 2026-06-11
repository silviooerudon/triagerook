import Link from "next/link"
import type { Metadata } from "next"
import { DOC_SECTIONS } from "./_nav"
import { DocHeader } from "./_components/doc-ui"

export const metadata: Metadata = {
  title: "Documentation",
  description:
    "How TriageRook works, what it stores, and what it checks for. Trust documentation for a public-repo security scanner: GitHub App permissions, data handling, scan limits, suppressions, and the full rule catalog.",
}

export default function DocsHubPage() {
  return (
    <div className="max-w-3xl">
      <DocHeader eyebrow="documentation" title="TriageRook documentation">
        TriageRook scans a public GitHub repo across ten independent detectors and
        returns a prioritized report in under a minute &mdash; no CLI, no config,
        no code execution. These docs exist to show their work: what we ask for,
        what we keep, and exactly how each check runs. Every number on these pages
        is read straight from the source.
      </DocHeader>

      <div className="space-y-10">
        {DOC_SECTIONS.map((section) => (
          <section key={section.title}>
            <h2 className="mb-4 font-mono text-sm uppercase tracking-wider text-slate-500">
              {section.title}
            </h2>
            <ul className="grid gap-3 sm:grid-cols-2">
              {section.links
                .filter((link) => link.href !== "/docs")
                .map((link) => (
                  <li key={link.href}>
                    <Link
                      href={link.href}
                      className="block h-full rounded-xl border border-slate-800 bg-slate-900 p-4 transition hover:border-slate-700"
                    >
                      <h3 className="mb-1.5 font-medium leading-tight text-slate-100">
                        {link.label}
                      </h3>
                      <p className="text-xs leading-relaxed text-slate-400">
                        {link.summary}
                      </p>
                    </Link>
                  </li>
                ))}
            </ul>
          </section>
        ))}
      </div>

      <div className="mt-16 border-t border-slate-800/60 pt-8 text-sm text-slate-500">
        <p>
          Source is on{" "}
          <a
            href="https://github.com/silviooerudon/triagerook"
            target="_blank"
            rel="noopener noreferrer"
            className="text-amber-400 hover:underline"
          >
            GitHub
          </a>
          . Found a claim on these pages that doesn&apos;t match the code?{" "}
          <a
            href="https://github.com/silviooerudon/triagerook/issues/new?title=Docs%20feedback"
            target="_blank"
            rel="noopener noreferrer"
            className="text-amber-400 hover:underline"
          >
            Open an issue
          </a>
          &mdash; that is a bug.
        </p>
      </div>
    </div>
  )
}
