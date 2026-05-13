import Link from "next/link"

// Canonical brand mark. Shared between the public landing nav and every
// authenticated page so the visitor never lands on a screen that visually
// reads as a different product. The `[R/]` glyph + lowercase mono name is
// the one to use — `Repo<span class="text-blue">Guard</span>` was the old
// dashboard variant and should not exist anywhere now.
export function Brand({ href = "/", className = "" }: { href?: string; className?: string }) {
  return (
    <Link href={href} className={`flex items-center gap-2.5 group ${className}`}>
      <span className="font-mono text-amber-400 text-sm">[R/]</span>
      <span className="font-mono text-sm tracking-tight text-slate-100 group-hover:text-amber-400 transition">
        repoguard
      </span>
    </Link>
  )
}
