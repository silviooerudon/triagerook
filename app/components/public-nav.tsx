import Link from "next/link"
import { Brand } from "@/app/components/brand"

// Public-side nav for /scan-public and other unauthenticated pages.
// Same chrome and aesthetic as the landing nav so a visitor arriving
// from HN to /scan-public/owner/repo never breaks out of the brand.
export function PublicNav() {
  return (
    <nav className="border-b border-slate-800/60 bg-slate-950/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
        <Brand href="/" />
        <div className="flex items-center gap-5 text-xs font-mono text-slate-400">
          <Link
            href="/docs"
            className="hidden md:inline hover:text-slate-100 transition"
          >
            docs
          </Link>
          <Link
            href="/compare"
            className="hidden md:inline hover:text-slate-100 transition"
          >
            compare
          </Link>
          <Link
            href="/about"
            className="hidden md:inline hover:text-slate-100 transition"
          >
            about
          </Link>
          <Link
            href="/security"
            className="hidden md:inline hover:text-slate-100 transition"
          >
            security
          </Link>
          <a
            href="https://github.com/silviooerudon/triagerook"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden md:inline hover:text-slate-100 transition"
          >
            github ↗
          </a>
          <Link
            href="/signin"
            className="px-3 py-1.5 border border-amber-400/40 text-amber-300 hover:bg-amber-400 hover:text-slate-950 transition"
          >
            sign in
          </Link>
        </div>
      </div>
    </nav>
  )
}
