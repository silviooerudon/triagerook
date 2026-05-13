import { PublicNav } from "@/app/components/public-nav"

// Public nav wrapping anonymous scan pages so a visitor arriving from
// HN or Product Hunt sees the same sticky brand chrome as the landing.
export default function PublicScanLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <>
      <PublicNav />
      {children}
    </>
  )
}
