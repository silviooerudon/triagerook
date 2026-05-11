import NextAuth from "next-auth"
import GitHub from "next-auth/providers/github"

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
      session.accessToken = token.accessToken
      if (session.user && token.githubId) {
        session.user.id = token.githubId
      }
      return session
    },
  },
})