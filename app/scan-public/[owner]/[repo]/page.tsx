import { redirect } from "next/navigation"
import { auth } from "@/auth"
import { isSafeOwnerRepo } from "@/lib/path-validation"
import PublicScanContent from "./public-scan-content"

type PageProps = {
  params: Promise<{ owner: string; repo: string }>
  searchParams: Promise<{ branch?: string; path?: string }>
}

// Server wrapper around the public-scan client component. If the visitor
// is already authenticated we redirect them to the authenticated path so
// the scan rides their personal GitHub token quota (5000 req/hr) instead
// of the shared anonymous pool that /api/scan-public uses (60 req/hr,
// global to all anonymous visitors). Without this redirect, a logged-in
// user who clicks a /scan-public/<x>/<y> link from somewhere (an email,
// a tweet, a Show HN comment) hits the rate-limited anonymous flow even
// though they didn't have to — confusing and product-broken.
//
// Anonymous visitors keep the existing behavior: the client component
// renders below and POSTs to /api/scan-public.
export default async function PublicScanPage({
  params,
  searchParams,
}: PageProps) {
  const session = await auth()
  if (session) {
    const { owner, repo } = await params
    if (isSafeOwnerRepo(owner) && isSafeOwnerRepo(repo)) {
      const { branch, path } = await searchParams
      const params = new URLSearchParams()
      if (branch) params.set("branch", branch)
      if (path) params.set("path", path)
      const qs = params.toString()
      redirect(`/dashboard/scan/${owner}/${repo}${qs ? `?${qs}` : ""}`)
    }
    // Falls through to the anonymous flow if owner/repo fail the safety
    // gate — let the client component / API handler emit the proper
    // validation error rather than redirecting somewhere unsafe.
  }
  return <PublicScanContent params={params} searchParams={searchParams} />
}
