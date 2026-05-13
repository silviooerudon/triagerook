-- Migration 010: Row-Level Security policies — defense-in-depth safety net.
--
-- Background (audit S4)
--   Application code uses the Supabase service-role key, which always
--   bypasses RLS. So this migration is NOT the primary line of defence
--   for cross-user access — that role is filled by the user_id check
--   shipped in #28 (every authenticated route reads getUserId(session)
--   and joins on it).
--
--   What this migration does add: a safety net. Every table now has
--   restrictive policies that deny anon-key access unless the JWT
--   request.jwt.claim.sub matches the row's user_id. If a future code
--   path accidentally falls back to the anon key (e.g. a refactor
--   forgets to import the service-role client), it will be denied
--   instead of silently leaking data.
--
--   Full Option B from the audit — moving read paths to anon-key +
--   custom JWT — remains tracked as S4 phase 2. That's a code refactor
--   touching every read route, deferred until there's signal warranting
--   the effort.
--
-- Notes
--   - public_scan_rate_limits gets RLS too. Anon key would never have
--     a request.jwt.claim.sub set, so all access is denied. Only the
--     service-role pipeline reads/writes it today.
--   - We use FOR ALL with a single USING clause that doubles as the
--     WITH CHECK for inserts/updates. PostgreSQL accepts a missing
--     WITH CHECK to mean "same as USING".
--   - The `current_setting(..., true)` form returns NULL when the
--     setting is absent rather than erroring; the NULL = user_id
--     comparison is then false-y and access is denied. Safe default.
--   - All policies are idempotent via DROP POLICY IF EXISTS first so
--     this migration can be re-run safely.

-- scans -----------------------------------------------------------------
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;

-- Drop legacy permissive placeholders (created via Supabase dashboard
-- UI before this project started shipping migration files). Both were
-- effectively open:
--   "Users can insert own scans"   INSERT, qual=null + no WITH CHECK
--   "Users can view own scans"     SELECT, qual="(auth.uid()::text = user_id) OR true"
-- Postgres ORs permissive policies together, so leaving them in place
-- would invalidate the restrictive replacement below.
DROP POLICY IF EXISTS "Users can insert own scans" ON public.scans;
DROP POLICY IF EXISTS "Users can view own scans" ON public.scans;

DROP POLICY IF EXISTS "scans owner can do all" ON public.scans;

CREATE POLICY "scans owner can do all"
  ON public.scans
  FOR ALL
  USING (
    user_id = current_setting('request.jwt.claim.sub', true)
  );

-- suppressions ---------------------------------------------------------
ALTER TABLE public.suppressions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "suppressions owner can do all" ON public.suppressions;

CREATE POLICY "suppressions owner can do all"
  ON public.suppressions
  FOR ALL
  USING (
    user_id = current_setting('request.jwt.claim.sub', true)
  );

-- public_scan_rate_limits ----------------------------------------------
-- This table is per-IP, not per-user. The right policy for anon access
-- is "always denied"; only the service-role pipeline touches it. We
-- enable RLS without any permissive policy, which is the same as the
-- previous state (no policies + no RLS) for the service-role caller
-- but flips anon-key callers from "implicit allow" to "explicit deny".
ALTER TABLE public.public_scan_rate_limits ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "rate limits service-role only" ON public.public_scan_rate_limits;
-- No CREATE POLICY — denies everything except service-role (which
-- bypasses RLS unconditionally).
