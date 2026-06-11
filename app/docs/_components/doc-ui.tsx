import type { ReactNode } from "react"

// Shared presentational helpers for the docs pages. Server components — no
// client state. The visual language matches the landing/rules pages: neutral
// slate background, amber accent, font-display headings, font-mono labels.

// Callout: neutral background with a 3px colored left bar and a colored label.
// Deliberately NOT a light-green-on-dark-green block — the bar carries the
// semantics so the body text stays high-contrast slate.
const CALLOUT_VARIANTS = {
  info: { bar: "border-amber-400", label: "text-amber-300" },
  warn: { bar: "border-orange-400", label: "text-orange-300" },
  danger: { bar: "border-red-400", label: "text-red-300" },
  ok: { bar: "border-emerald-400", label: "text-emerald-300" },
} as const

export type CalloutVariant = keyof typeof CALLOUT_VARIANTS

export function Callout({
  variant = "info",
  title,
  children,
}: {
  variant?: CalloutVariant
  title?: string
  children: ReactNode
}) {
  const v = CALLOUT_VARIANTS[variant]
  return (
    <div
      className={`my-6 rounded-r-lg border-l-[3px] ${v.bar} bg-slate-900/40 px-5 py-4`}
    >
      {title && (
        <p
          className={`mb-2 font-mono text-xs uppercase tracking-wider ${v.label}`}
        >
          {title}
        </p>
      )}
      <div className="space-y-2 text-sm leading-relaxed text-slate-300">
        {children}
      </div>
    </div>
  )
}

// Page header: amber eyebrow label + display H1 + optional lead paragraph.
export function DocHeader({
  eyebrow,
  title,
  children,
}: {
  eyebrow: string
  title: string
  children?: ReactNode
}) {
  return (
    <header className="mb-10">
      <p className="mb-3 font-mono text-xs text-amber-400">{eyebrow}</p>
      <h1 className="mb-4 font-display text-3xl font-bold leading-tight tracking-tight md:text-4xl">
        {title}
      </h1>
      {children && (
        <p className="max-w-2xl text-base leading-relaxed text-slate-300">
          {children}
        </p>
      )}
    </header>
  )
}

// Section with the uppercase mono heading used across the docs.
export function Section({
  title,
  children,
}: {
  title: string
  children: ReactNode
}) {
  return (
    <section className="mb-10">
      <h2 className="mb-3 font-mono text-sm uppercase tracking-wider text-slate-500">
        {title}
      </h2>
      {children}
    </section>
  )
}

// Inline code chip matching the existing pages.
export function Code({ children }: { children: ReactNode }) {
  return <code className="font-mono text-amber-300">{children}</code>
}

// Preformatted code block matching the existing pages.
export function Pre({ children }: { children: ReactNode }) {
  return (
    <pre className="overflow-x-auto rounded-lg border border-slate-800 bg-slate-900/80 p-4 font-mono text-xs leading-relaxed text-slate-300">
      {children}
    </pre>
  )
}
