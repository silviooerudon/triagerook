import type { Metadata } from "next"
import Link from "next/link"
import { redirect } from "next/navigation"
import { auth, getAccessToken, signOut } from "@/auth"
import { getUserId } from "@/lib/auth-utils"
import { deleteUserData, getAccountSummary, revokeGitHubGrant } from "@/lib/account"
import { LEGAL } from "@/lib/legal"

export const metadata: Metadata = {
  title: "Your data",
  robots: { index: false, follow: false },
}

export const dynamic = "force-dynamic"

// Exact phrase the user must type. Deliberately not "yes"/"ok": typing it
// is a conscious act, so erasure can't happen by an accidental click.
const CONFIRM_PHRASE = "delete my data"

// Server action. Next.js server actions reject cross-origin POSTs (Origin
// must match Host), so this cannot be triggered by a third-party page.
// The user id is read from the session — never from the form — so a user
// can only ever erase their own data.
async function deleteAccountAction(formData: FormData) {
  "use server"
  const session = await auth()
  const userId = getUserId(session)
  if (!userId) redirect("/signin")

  const typed = String(formData.get("confirm") ?? "").trim().toLowerCase()
  if (typed !== CONFIRM_PHRASE) {
    redirect("/dashboard/account?error=confirm")
  }

  // Read the GitHub token BEFORE signing out — afterwards the cookie is gone.
  const accessToken = await getAccessToken()

  try {
    await deleteUserData(userId)
  } catch (err) {
    console.error("[account] erasure failed:", err instanceof Error ? err.message : err)
    redirect("/dashboard/account?error=failed")
  }

  const revoked = await revokeGitHubGrant(accessToken)
  await signOut({ redirectTo: `/account-deleted${revoked ? "" : "?revoke=manual"}` })
}

export default async function AccountPage({
  searchParams,
}: {
  searchParams?: Promise<{ error?: string }>
}) {
  const session = await auth()
  const userId = getUserId(session)
  if (!userId) redirect("/signin?next=/dashboard/account")

  const { error } = (await searchParams) ?? {}

  let summary: Awaited<ReturnType<typeof getAccountSummary>> | null = null
  try {
    summary = await getAccountSummary(userId)
  } catch (err) {
    console.error("[account] summary failed:", err instanceof Error ? err.message : err)
  }

  return (
    <main id="main" className="px-6 py-12">
      <div className="max-w-3xl mx-auto">
        <div className="font-mono text-xs text-amber-400 mb-3">{"// your data"}</div>
        <h1 className="font-display text-3xl md:text-4xl font-bold tracking-tight mb-2">
          Your data
        </h1>
        <p className="text-slate-400 text-sm mb-10 leading-relaxed">
          Everything TriageRook stores about your account, how to download it, and how
          to erase it. See the{" "}
          <Link href="/privacy" className="text-amber-400 hover:underline">
            privacy policy
          </Link>{" "}
          for the full picture.
        </p>

        <section aria-labelledby="stored-heading" className="mb-10">
          <h2 id="stored-heading" className="text-xl font-semibold mb-3">
            What we store
          </h2>
          {summary ? (
            <dl className="grid grid-cols-2 gap-4 max-w-md">
              <Stat label="Saved scans" value={summary.scans} />
              <Stat label="Suppressions" value={summary.suppressions} />
            </dl>
          ) : (
            <p role="status" className="text-sm text-red-300">
              Could not load your data summary right now. Export and erasure still work.
            </p>
          )}
          <p className="text-sm text-slate-400 mt-4 leading-relaxed">
            Rows are keyed to your GitHub numeric user id. We do not store your source
            code, your GitHub access token, or full secret values.
          </p>
        </section>

        <section aria-labelledby="export-heading" className="mb-10">
          <h2 id="export-heading" className="text-xl font-semibold mb-3">
            Download your data
          </h2>
          <p className="text-sm text-slate-400 mb-4 leading-relaxed">
            A JSON file with every scan and suppression saved under your account.
          </p>
          <a
            href="/api/account/export"
            download
            className="inline-flex items-center px-4 py-2.5 font-mono text-sm border border-amber-400/40 text-amber-300 hover:bg-amber-400 hover:text-slate-950 transition"
          >
            download my data (.json)
          </a>
        </section>

        <section
          aria-labelledby="delete-heading"
          className="border border-red-500/30 bg-red-500/5 rounded-lg p-6"
        >
          <h2 id="delete-heading" className="text-xl font-semibold mb-3 text-red-200">
            Delete your data
          </h2>
          <p className="text-sm text-slate-300 mb-3 leading-relaxed">
            Permanently erases all your saved scans and suppressions, revokes
            TriageRook&apos;s authorization on your GitHub account, and signs you out.
            This cannot be undone. Signing in again later starts a fresh, empty account.
          </p>
          <p className="text-sm text-slate-400 mb-5 leading-relaxed">
            If you installed the TriageRook Security App on any repository for fix
            PRs, uninstall it from{" "}
            <a
              href="https://github.com/settings/installations"
              target="_blank"
              rel="noopener noreferrer"
              className="text-amber-400 hover:underline"
            >
              GitHub → Settings → Applications<span className="sr-only"> (opens in a new tab)</span>
            </a>
            .
          </p>

          {error === "confirm" && (
            <p role="alert" className="text-sm text-red-300 mb-4">
              The confirmation phrase did not match. Nothing was deleted.
            </p>
          )}
          {error === "failed" && (
            <p role="alert" className="text-sm text-red-300 mb-4">
              Deletion failed and you are still signed in. Please try again, or email{" "}
              <a href={`mailto:${LEGAL.privacyEmail}`} className="underline">
                {LEGAL.privacyEmail}
              </a>
              .
            </p>
          )}

          <form action={deleteAccountAction} className="space-y-3">
            <label htmlFor="confirm" className="block text-sm text-slate-300">
              Type <span className="font-mono text-red-200">{CONFIRM_PHRASE}</span> to
              confirm
            </label>
            <input
              id="confirm"
              name="confirm"
              type="text"
              required
              autoComplete="off"
              spellCheck={false}
              pattern={CONFIRM_PHRASE}
              aria-describedby="delete-heading"
              className="w-full max-w-sm px-3 py-2.5 bg-slate-950 border border-slate-700 focus:border-red-400 font-mono text-sm text-slate-100"
            />
            <div>
              <button
                type="submit"
                className="px-4 py-2.5 font-mono text-sm bg-red-600 text-white hover:bg-red-700 transition font-semibold"
              >
                permanently delete my data
              </button>
            </div>
          </form>
        </section>
      </div>
    </main>
  )
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="border border-slate-800 rounded-lg p-4 bg-slate-900/40">
      <dt className="text-xs font-mono text-slate-400">{label}</dt>
      <dd className="font-display text-2xl font-bold text-slate-100 mt-1">{value}</dd>
    </div>
  )
}
