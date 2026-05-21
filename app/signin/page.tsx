import Link from "next/link"
import type { Metadata } from "next"
import { auth, signIn } from "@/auth"
import { redirect } from "next/navigation"
import { PublicNav } from "@/app/components/public-nav"

export const metadata: Metadata = {
  title: "Sign in",
  description:
    "Sign in to TriageRook with the TriageRook Security GitHub App. Public repos, no code stored.",
  robots: { index: false, follow: false },
}

// Pre-OAuth consent screen. Snyk / Aqua / Socket all surface one — and
// for a 1-maker security tool the buyer wants to read the scope before
// being yanked into GitHub's flow. The actual sign-in is a server action
// (form below) so the click-to-redirect remains a single POST.
export default async function SignInPage({
  searchParams,
}: {
  searchParams?: Promise<{ next?: string }>
}) {
  // Already signed in? skip the consent screen.
  const session = await auth()
  if (session) {
    redirect("/dashboard")
  }

  const { next } = (await searchParams) ?? {}
  const redirectTo = isSafeRelativePath(next) ? next! : "/dashboard"

  return (
    <>
      <PublicNav />
      <main className="px-6 py-20">
        <div className="max-w-md mx-auto">
          <div className="font-mono text-xs text-amber-400 mb-6 flex items-center gap-2.5">
            <span className="inline-block w-1.5 h-1.5 bg-amber-400 animate-pulse" />
            sign in
          </div>

          <h1 className="font-display text-3xl md:text-4xl font-bold tracking-tight mb-3">
            Continue with GitHub
          </h1>
          <p className="text-slate-400 text-sm mb-8 leading-relaxed">
            Sign-in is handled by the{" "}
            <span className="font-mono text-slate-200">TriageRook Security</span>{" "}
            GitHub App — not a legacy OAuth scope. Read what we access before
            you authorise.
          </p>

          <ul className="space-y-3 mb-10 text-sm">
            <Bullet
              title="We read your public repositories"
              body="To list them on the dashboard and fetch file contents during a scan. No private repo access today."
            />
            <Bullet
              title="We don't store your code"
              body="Files are fetched from the GitHub API during a scan and discarded immediately. Only findings (path, line, masked preview) persist."
            />
            <Bullet
              title="Write access is opt-in per repo"
              body="The auto-fix PR feature requires you to install the App on the target repo, which scopes Contents/Pull-Requests write to that single repo."
            />
            <Bullet
              title="Revoke any time"
              body={
                <>
                  GitHub →{" "}
                  <a
                    href="https://github.com/settings/applications"
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-amber-400 hover:underline"
                  >
                    Settings → Applications
                  </a>{" "}
                  → find TriageRook Security → Revoke.
                </>
              }
            />
          </ul>

          <form
            action={async () => {
              "use server"
              await signIn("github", { redirectTo })
            }}
          >
            <button
              type="submit"
              className="w-full px-6 py-3 rounded-lg bg-amber-400 hover:bg-amber-300 transition text-slate-950 font-medium inline-flex items-center justify-center gap-2"
            >
              <GitHubIcon />
              Continue with GitHub
            </button>
          </form>

          <p className="text-xs text-slate-500 mt-6 text-center font-mono">
            By continuing you agree to the{" "}
            <Link href="/security" className="text-slate-400 hover:text-amber-400 underline-offset-2 hover:underline">
              security policy
            </Link>
            .
          </p>

          <div className="mt-12 text-center">
            <Link
              href="/"
              className="text-xs font-mono text-slate-500 hover:text-amber-400 transition"
            >
              ← back to home
            </Link>
          </div>
        </div>
      </main>
    </>
  )
}

// Accept-list for the `?next=` redirect target. Anything that doesn't
// match this is silently rewritten to /dashboard so an attacker can't
// craft a sign-in link that bounces a user to an attacker-controlled URL
// after auth.
function isSafeRelativePath(value: string | undefined): boolean {
  if (!value) return false
  if (!value.startsWith("/")) return false
  if (value.startsWith("//")) return false // protocol-relative
  if (value.includes("\\")) return false
  return true
}

function Bullet({
  title,
  body,
}: {
  title: string
  body: React.ReactNode
}) {
  return (
    <li className="flex gap-3">
      <span
        aria-hidden="true"
        className="font-mono text-amber-400 text-sm leading-tight pt-0.5 shrink-0"
      >
        ✓
      </span>
      <div>
        <p className="text-slate-100 text-sm font-medium leading-tight">
          {title}
        </p>
        <p className="text-slate-400 text-xs mt-1 leading-relaxed">{body}</p>
      </div>
    </li>
  )
}

function GitHubIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      width="18"
      height="18"
      fill="currentColor"
      aria-hidden="true"
    >
      <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.4 3-.405 1.02.005 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
    </svg>
  )
}
