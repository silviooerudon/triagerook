import type { ReactNode } from "react"
import { PublicNav } from "@/app/components/public-nav"
import { DocSidebar } from "./_components/doc-sidebar"

// Shared chrome for every /docs page: the public nav, a sticky sidebar
// (collapsible on mobile), and the content column. Pages under /docs render
// only their content — they must NOT render PublicNav themselves.
export default function DocsLayout({ children }: { children: ReactNode }) {
  return (
    <>
      <PublicNav />
      <div className="mx-auto max-w-6xl px-6 py-10 md:flex md:gap-12">
        <DocSidebar />
        <main className="min-w-0 flex-1">{children}</main>
      </div>
    </>
  )
}
