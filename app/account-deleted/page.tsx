import type { Metadata } from "next"
import Link from "next/link"
import { PublicNav } from "@/app/components/public-nav"

export const metadata: Metadata = {
  title: "Data deleted",
  robots: { index: false, follow: false },
}

export default async function AccountDeletedPage({
  searchParams,
}: {
  searchParams?: Promise<{ revoke?: string }>
}) {
  const { revoke } = (await searchParams) ?? {}
  const manualRevoke = revoke === "manual"

  return (
    <>
      <PublicNav />
      <main id="main" className="px-6 py-20">
        <div className="max-w-md mx-auto">
          <h1 className="font-display text-3xl font-bold tracking-tight mb-4">
            Your data has been deleted
          </h1>
          <p className="text-slate-300 leading-relaxed mb-4">
            All saved scans and suppressions for your account were permanently erased,
            and you have been signed out.
          </p>
          {manualRevoke ? (
            <p role="status" className="text-sm text-amber-200 leading-relaxed mb-8">
              We could not revoke TriageRook&apos;s GitHub authorization automatically.
              To finish, open{" "}
              <a
                href="https://github.com/settings/apps/authorizations"
                target="_blank"
                rel="noopener noreferrer"
                className="text-amber-400 underline"
              >
                GitHub → Authorized GitHub Apps
                <span className="sr-only"> (opens in a new tab)</span>
              </a>{" "}
              and revoke <strong>TriageRook Security</strong>.
            </p>
          ) : (
            <p className="text-sm text-slate-400 leading-relaxed mb-8">
              TriageRook&apos;s authorization on your GitHub account was revoked too.
            </p>
          )}
          <Link href="/" className="font-mono text-sm text-amber-400 hover:underline">
            ← back to home
          </Link>
        </div>
      </main>
    </>
  )
}
