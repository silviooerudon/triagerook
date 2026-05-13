import NextAuth from "next-auth"
import GitHub from "next-auth/providers/github"
import { getToken } from "next-auth/jwt"
import { headers as nextHeaders } from "next/headers"

// Auth is backed by the "RepoGuard Security" GitHub App, not a legacy OAuth
// App. Permissions are declared on the App itself (Contents: read+write,
// Pull requests: write, Email: read, Metadata: read), so no `scope` param
// here — passing one would be ignored by GitHub App user flows anyway.
//
// Env vars are namespaced AUTH_GITHUB_APP_* to make the source of truth
// obvious and to leave AUTH_GITHUB_ID/SECRET unset (the OAuth App can be
// fully deleted from GitHub once this deploy is verified in prod).
export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    GitHub({
      clientId: process.env.AUTH_GITHUB_APP_CLIENT_ID,
      clientSecret: process.env.AUTH_GITHUB_APP_CLIENT_SECRET,
    }),
  ],
  pages: {
    signIn: "/",
  },
  callbacks: {
    async jwt({ token, account }) {
      if (account) {
        token.accessToken = account.access_token
        // providerAccountId is the GitHub numeric user id — stable, unique,
        // and unaffected by display-name changes. This is the source of
        // truth for user identity in RepoGuard; never use session.user.name
        // (mutable, non-unique) as a key into the scans table.
        if (account.providerAccountId) {
          token.githubId = account.providerAccountId
        }
      }
      return token
    },
    async session({ session, token }) {
      // SECURITY: do NOT set session.accessToken here. NextAuth exposes the
      // session object as JSON via /api/auth/session to any same-origin
      // script — a successful XSS could then exfiltrate the GitHub access
      // token. The token lives on the encrypted JWT cookie only; server
      // code reads it via getAccessToken() below.
      if (session.user && token.githubId) {
        session.user.id = token.githubId
      }
      return session
    },
  },
})

// Reads the GitHub access token from the encrypted JWT cookie. SERVER-ONLY.
//
// Pass `req` from route handlers (the NextRequest you already have).
// Server components / server actions: omit `req` and we reconstruct the
// request from next/headers cookies.
//
// SECURITY: never call this on the client side and never include the
// returned value in any client-bound response body. The token must stay
// on the server.
export async function getAccessToken(
  req?: Request | { headers: Headers },
): Promise<string | undefined> {
  const secureCookie = process.env.NODE_ENV === "production"
  const cookieName = secureCookie
    ? "__Secure-authjs.session-token"
    : "authjs.session-token"

  const requestLike: { headers: Headers } = req
    ? { headers: req.headers }
    : { headers: await nextHeaders() }

  const decoded = await getToken({
    req: requestLike,
    secret: process.env.AUTH_SECRET,
    cookieName,
    secureCookie,
  })
  return decoded?.accessToken
}