import type { Session } from "next-auth"

// Returns the stable GitHub numeric user id from a NextAuth session, or
// null if the session is missing or the id was not persisted (which can
// only happen for sessions issued before the auth.ts change that started
// stashing account.providerAccountId in the JWT — those sessions need a
// fresh sign-in).
//
// Never fall back to display name or email here. Display names are
// mutable and non-unique; using them as a key into the scans table
// causes cross-user data leakage when two GitHub users share a name and
// pools all unauthenticated traffic into a single 'unknown' bucket.
export function getUserId(session: Session | null): string | null {
  return session?.user?.id ?? null
}
