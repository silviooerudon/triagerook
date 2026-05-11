import "next-auth"
import "next-auth/jwt"

// Module augmentation so the GitHub provider account ID (a stable numeric
// string) and the GitHub access token survive on the session/JWT in a
// typed way. Replaces the trio of @ts-expect-error pragmas previously
// scattered across auth.ts, app/api/scan/[owner]/[repo]/route.ts, and
// app/dashboard/page.tsx.
declare module "next-auth" {
  interface Session {
    accessToken?: string
    user?: {
      id?: string
      name?: string | null
      email?: string | null
      image?: string | null
    }
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    accessToken?: string
    githubId?: string
  }
}
