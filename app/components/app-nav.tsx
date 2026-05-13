import Link from "next/link"
import { signOut } from "@/auth"
import { Brand } from "@/app/components/brand"

type AppNavProps = {
  userName?: string | null
  userImage?: string | null
}

// Persistent navigation for every authenticated page. Built to look and
// feel identical to the public landing nav (sticky, slate-950/80 backdrop,
// mono links, amber accent) so signing in does not feel like entering a
// different product. Suppressions and History are surfaced here because
// they were previously discoverable only via the dashboard or not at all.
export function AppNav({ userName, userImage }: AppNavProps) {
  return (
    <nav className="border-b border-slate-800/60 bg-slate-950/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
        <Brand href="/dashboard" />

        <div className="flex items-center gap-5 text-xs font-mono text-slate-400">
          <Link
            href="/dashboard"
            className="hidden sm:inline hover:text-slate-100 transition"
          >
            repos
          </Link>
          <Link
            href="/dashboard/history"
            className="hidden sm:inline hover:text-slate-100 transition"
          >
            history
          </Link>
          <Link
            href="/dashboard/suppressions"
            className="hidden md:inline hover:text-slate-100 transition"
          >
            suppressions
          </Link>
          <Link
            href="/security"
            className="hidden md:inline hover:text-slate-100 transition"
          >
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
            <span className="hidden sm:inline text-slate-500">{userName}</span>
            <form
              action={async () => {
                "use server"
                await signOut({ redirectTo: "/" })
              }}
            >
              <button
                type="submit"
                className="hover:text-amber-400 transition"
                aria-label="Sign out"
              >
                sign out
              </button>
            </form>
          </div>
        </div>
      </div>
    </nav>
  )
}
