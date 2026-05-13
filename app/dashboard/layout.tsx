import { auth } from "@/auth"
import { redirect } from "next/navigation"
import { AppNav } from "@/app/components/app-nav"

// Server layout shared by every /dashboard/* route. Gates unauthenticated
// access (single redirect site-wide instead of per-page) and renders the
// persistent app nav so the brand mark, user avatar, and primary links
// are present on every authed screen.
export default async function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const session = await auth()
  if (!session) {
    redirect("/")
  }

  return (
    <>
      <AppNav
        userName={session.user?.name}
        userImage={session.user?.image}
      />
      {children}
    </>
  )
}
