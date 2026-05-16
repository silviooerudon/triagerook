import { signOut } from "@/auth"

// Server component wrapping the sign-out form. Extracted so both the
// desktop AppNav and the mobile dropdown menu can render the same
// server-action form — client components can't define inline
// "use server" actions, but they CAN render server components passed
// as children/props, which is how this gets injected into MobileMenu.
export function SignOutForm({
  className = "hover:text-amber-400 transition",
}: {
  className?: string
}) {
  return (
    <form
      action={async () => {
        "use server"
        await signOut({ redirectTo: "/" })
      }}
    >
      <button type="submit" className={className} aria-label="Sign out">
        sign out
      </button>
    </form>
  )
}
