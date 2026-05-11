-- Migration 007: stabilize user_id to GitHub numeric provider id.
--
-- Background
--   Pre-fix, every authenticated route derived user_id from
--     session.user?.name ?? session.user?.email ?? "unknown"
--   Display names are mutable (a user can rename), non-unique (two
--   distinct GitHub users can share a display name), and the "unknown"
--   fallback pooled every session that lost name+email into one bucket.
--   Combined with no Supabase RLS, this was a cross-user data-leak
--   waiting to happen at first sign of distribution.
--
--   The auth.ts callback now stashes account.providerAccountId (GitHub
--   numeric user id, stable + unique) in the JWT, and the routes look
--   it up via getUserId(session). Old scan rows still carry the legacy
--   display-name user_id and would be invisible to the new derivation.
--
-- This migration backfills the one known pre-distribution user (Silvio,
-- providerAccountId 227823977) from his display-name user_id. Other
-- legacy rows (e.g. user_id = 'unknown' or display names of any other
-- people who happened to sign in during the pre-distribution period)
-- are intentionally left in place so they remain auditable but are no
-- longer reachable through the dashboard. They do not represent active
-- accounts and there are no live ones besides Silvio.
--
-- Confirmed via baseline metrics in docs/baseline-metrics.md (kept
-- locally, not in the public repo) that active-user count is 1 and the
-- only display-name id present is 'silviooerudon'.

UPDATE scans
SET user_id = '227823977'
WHERE user_id = 'silviooerudon';
