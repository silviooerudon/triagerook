import Link from "next/link"
import { Brand } from "@/app/components/brand"
import { MobileMenu } from "@/app/components/mobile-menu"
import { SignOutForm } from "@/app/components/sign-out-form"

type AppNavProps = {
  userName?: string | null
  userImage?: string | null
}

// Persistent navigation for every authenticated page. Built to look and
// feel identical to the public landing nav (sticky, slate-950/80 backdrop,
// mono links, amber accent) so signing in does not feel like entering a
// different product.
//
// Layout splits at md: above md we render the full link list inline,
// below md we collapse everything except the brand mark into a
// MobileMenu dropdown so phone-width screens are not stuck with a row
// of vertically-stacked links permanently visible.
export function AppNav({ userName, userImage }: AppNavProps) {
  return (
    <nav className="border-b border-slate-800/60 bg-slate-950/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
        <Brand href="/dashboard" />

        {/* Desktop (md+) — inline link list + avatar + sign-out form. */}
        <div className="hidden md:flex items-center gap-5 text-xs font-mono text-slate-400">
          <Link href="/dashboard" className="hover:text-slate-100 transition">
            repos
          </Link>
          <Link
            href="/dashboard/history"
            className="hover:text-slate-100 transition"
          >
            history
          </Link>
          <Link
            href="/dashboard/suppressions"
            className="hover:text-slate-100 transition"
          >
            suppressions
          </Link>
          <Link href="/security" className="hover:text-slate-100 transition">
            security
          </Link>

          <div className="flex items-center gap-2.5 pl-4 ml-1 border-l border-slate-800/60">
            {userImage && (
              // eslint-disable-next-line @next/next/no-img-element
              <img
                src={userImage}
                alt={userName ?? "User"}
                className="w-6 h-6 rounded-full border border-slate-700"
              />
            )}
            <span className="text-slate-500">{userName}</span>
            <SignOutForm />
          </div>
        </div>

        {/* Mobile (< md) — hamburger that opens a slide-down panel.
            Sign-out is a server-action form, so we pass it as a slot
            because MobileMenu itself is a client component. */}
        <MobileMenu
          userName={userName}
          userImage={userImage}
          signOutSlot={<SignOutForm />}
        />
      </div>
    </nav>
  )
}
