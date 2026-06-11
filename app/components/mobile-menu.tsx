"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { useEffect, useState, type ReactNode } from "react"

type NavLink = { href: string; label: string }

const LINKS: NavLink[] = [
  { href: "/dashboard", label: "repos" },
  { href: "/dashboard/history", label: "history" },
  { href: "/dashboard/suppressions", label: "suppressions" },
  { href: "/security", label: "security" },
  { href: "/docs", label: "docs" },
]

// Mobile-only hamburger menu for the authenticated nav. Sits inside
// the AppNav and replaces the inline link list at < md. Opens a
// slide-down panel anchored to the nav bar with the same link set
// plus the sign-out form.
//
// `signOutSlot` is rendered as a server-component slot because the
// sign-out flow uses an inline server action and client components
// cannot define those. The parent server nav passes the slot.
export function MobileMenu({
  userName,
  userImage,
  signOutSlot,
}: {
  userName?: string | null
  userImage?: string | null
  signOutSlot: ReactNode
}) {
  const [open, setOpen] = useState(false)
  const pathname = usePathname()

  // Auto-close when the user navigates. Without this, the panel stays
  // open after tapping a link (the same component instance survives
  // the route change because AppNav is in the layout). The cascading
  // render is intentional — `pathname` is exactly the external state
  // we want to sync the menu's open flag to.
  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- sync open-state to route change
    setOpen(false)
  }, [pathname])

  // Esc closes the panel and an overflow-hidden lock prevents the
  // background from scrolling while the user has the menu open.
  useEffect(() => {
    if (!open) return
    function handler(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false)
    }
    document.addEventListener("keydown", handler)
    document.body.style.overflow = "hidden"
    return () => {
      document.removeEventListener("keydown", handler)
      document.body.style.overflow = ""
    }
  }, [open])

  return (
    <div className="md:hidden flex items-center gap-3">
      {userImage && (
        // eslint-disable-next-line @next/next/no-img-element
        <img
          src={userImage}
          alt={userName ?? "User"}
          className="w-6 h-6 rounded-full border border-slate-700"
        />
      )}
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-label={open ? "Close menu" : "Open menu"}
        aria-expanded={open}
        aria-controls="mobile-nav-panel"
        className="p-1.5 -mr-1.5 text-slate-300 hover:text-amber-400 transition"
      >
        {open ? <CloseIcon /> : <HamburgerIcon />}
      </button>

      {open && (
        <>
          {/* Click-outside scrim. Sits under the panel; tapping it
              closes the menu. Skips the nav itself so the toggle
              button still works. */}
          <button
            type="button"
            aria-label="Close menu"
            tabIndex={-1}
            onClick={() => setOpen(false)}
            className="fixed inset-0 top-14 z-40 bg-slate-950/60 backdrop-blur-sm"
          />
          <div
            id="mobile-nav-panel"
            role="menu"
            className="fixed left-0 right-0 top-14 z-50 border-b border-slate-800/60 bg-slate-950/95 backdrop-blur"
          >
            <ul className="max-w-6xl mx-auto px-6 py-4 flex flex-col gap-1 font-mono text-sm">
              {LINKS.map((link) => {
                const isActive =
                  link.href === pathname ||
                  (link.href !== "/dashboard" && pathname.startsWith(link.href))
                return (
                  <li key={link.href}>
                    <Link
                      href={link.href}
                      role="menuitem"
                      className={`block px-3 py-2.5 rounded ${
                        isActive
                          ? "text-amber-300 bg-amber-400/5"
                          : "text-slate-300 hover:text-amber-400 hover:bg-slate-900/60"
                      }`}
                    >
                      <span className="text-slate-600">→ </span>
                      {link.label}
                    </Link>
                  </li>
                )
              })}
              <li className="pt-3 mt-2 border-t border-slate-800/60 flex items-center justify-between gap-3 px-3">
                {userName && (
                  <span className="text-xs text-slate-500 truncate">
                    {userName}
                  </span>
                )}
                <div className="ml-auto text-xs text-slate-400">
                  {signOutSlot}
                </div>
              </li>
            </ul>
          </div>
        </>
      )}
    </div>
  )
}

function HamburgerIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="22"
      height="22"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <line x1="3" y1="7" x2="21" y2="7" />
      <line x1="3" y1="12" x2="21" y2="12" />
      <line x1="3" y1="17" x2="21" y2="17" />
    </svg>
  )
}

function CloseIcon() {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width="22"
      height="22"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  )
}
