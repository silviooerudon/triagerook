"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { useState } from "react"
import { DOC_SECTIONS } from "../_nav"

// Docs sidebar. Sticky on desktop, collapses into a toggle on mobile.
// usePathname drives the active-link highlight, which is why this is a
// client component; the layout that renders it stays a server component.
export function DocSidebar() {
  const pathname = usePathname()
  const [open, setOpen] = useState(false)

  const nav = (
    <nav className="space-y-7">
      {DOC_SECTIONS.map((section) => (
        <div key={section.title}>
          <p className="font-mono text-[11px] uppercase tracking-wider text-slate-500 mb-2">
            {section.title}
          </p>
          <ul className="space-y-0.5">
            {section.links.map((link) => {
              const active = pathname === link.href
              return (
                <li key={link.href}>
                  <Link
                    href={link.href}
                    onClick={() => setOpen(false)}
                    aria-current={active ? "page" : undefined}
                    className={`block rounded-md border-l-2 px-2.5 py-1.5 text-sm transition ${
                      active
                        ? "border-amber-400 bg-slate-800/40 text-amber-300"
                        : "border-transparent text-slate-400 hover:bg-slate-800/30 hover:text-slate-100"
                    }`}
                  >
                    {link.label}
                  </Link>
                </li>
              )
            })}
          </ul>
        </div>
      ))}
    </nav>
  )

  return (
    <>
      {/* Mobile: collapsible menu */}
      <div className="md:hidden mb-8">
        <button
          type="button"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
          className="flex w-full items-center justify-between rounded-lg border border-slate-800 bg-slate-900/60 px-4 py-2.5 font-mono text-sm text-slate-300"
        >
          <span>Documentation menu</span>
          <span className={`transition-transform ${open ? "rotate-180" : ""}`}>
            ▾
          </span>
        </button>
        {open && (
          <div className="mt-3 rounded-lg border border-slate-800 bg-slate-900/40 p-4">
            {nav}
          </div>
        )}
      </div>

      {/* Desktop: sticky sidebar */}
      <aside className="hidden w-56 shrink-0 md:block">
        <div className="sticky top-20">{nav}</div>
      </aside>
    </>
  )
}
