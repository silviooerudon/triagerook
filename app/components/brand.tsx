import Link from "next/link"
import Image from "next/image"

// Canonical brand mark. Shared between the public landing nav and every
// authenticated page so the visitor never lands on a screen that visually
// reads as a different product. The shield/rook logo sits to the left of
// the lowercase mono wordmark.
export function Brand({ href = "/", className = "" }: { href?: string; className?: string }) {
  return (
    <Link href={href} className={`flex items-center gap-2 group ${className}`}>
      <Image
        src="/logo.png"
        alt=""
        width={24}
        height={24}
        priority
        className="shrink-0"
      />
      <span className="font-mono text-sm tracking-tight text-slate-100 group-hover:text-amber-400 transition">
        triagerook
      </span>
    </Link>
  )
}
