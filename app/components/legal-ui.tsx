import type { ReactNode } from "react"
import { PublicNav } from "@/app/components/public-nav"

// Shared chrome for the long-form legal pages (/privacy, /terms). Keeps the
// same look as /security: readable line length, real heading hierarchy
// (h1 → h2 → h3) and an on-page table of contents for keyboard and
// screen-reader users who want to jump straight to a section.
export function LegalPage({
  eyebrow,
  title,
  intro,
  lastUpdated,
  toc,
  children,
}: {
  eyebrow: string
  title: string
  intro: ReactNode
  lastUpdated: string
  toc: { id: string; label: string }[]
  children: ReactNode
}) {
  return (
    <>
      <PublicNav />
      <main id="main" className="px-6 py-16">
        <article className="max-w-3xl mx-auto">
          <div className="font-mono text-xs text-amber-400 mb-3">{`// ${eyebrow}`}</div>
          <h1 className="font-display text-3xl md:text-4xl font-bold tracking-tight mb-3">
            {title}
          </h1>
          <p className="text-sm font-mono text-slate-400 mb-6">Last updated: {lastUpdated}</p>
          <div className="text-slate-300 leading-relaxed mb-10 space-y-3">{intro}</div>

          <nav
            aria-label="On this page"
            className="mb-12 border border-slate-800 rounded-lg p-5 bg-slate-900/40"
          >
            <h2 className="font-mono text-xs uppercase tracking-wider text-slate-400 mb-3">
              On this page
            </h2>
            <ol className="list-decimal pl-5 space-y-1 text-sm">
              {toc.map((t) => (
                <li key={t.id}>
                  <a href={`#${t.id}`} className="text-amber-400 hover:underline">
                    {t.label}
                  </a>
                </li>
              ))}
            </ol>
          </nav>

          {children}
        </article>
      </main>
    </>
  )
}

export function LegalSection({
  id,
  title,
  children,
}: {
  id: string
  title: string
  children: ReactNode
}) {
  return (
    <section id={id} aria-labelledby={`${id}-h`} className="mb-12 scroll-mt-20">
      <h2 id={`${id}-h`} className="text-xl font-semibold mb-3 text-slate-100">
        {title}
      </h2>
      <div className="text-slate-300 leading-relaxed space-y-3 [&_ul]:list-disc [&_ul]:pl-6 [&_ul]:space-y-1.5 [&_h3]:font-semibold [&_h3]:text-slate-100 [&_h3]:mt-5">
        {children}
      </div>
    </section>
  )
}

export function ExtLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="text-amber-400 hover:underline"
    >
      {children}
      <span className="sr-only"> (opens in a new tab)</span>
    </a>
  )
}
