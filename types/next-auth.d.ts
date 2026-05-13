import "next-auth"
import "next-auth/jwt"

// Module augmentation so the GitHub provider account ID (a stable numeric
// string) survives on the session in a typed way, and the GitHub access
// token stays typed on the JWT cookie payload.
//
// SECURITY: `accessToken` is intentionally NOT on Session — NextAuth
// exposes Session via /api/auth/session and we never want the GitHub
// token to cross the server/client boundary. Server-side callers read
// the token via `getAccessToken()` exported from auth.ts, which decrypts
// the JWT cookie directly.
declare module "next-auth" {
  interface Session {
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
