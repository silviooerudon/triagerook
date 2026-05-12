-- Migration 008: per-IP rate limiting for /api/scan-public.
--
-- The public scan endpoint is unauthenticated and burns GitHub's anon
-- API quota (60 req/hr per source IP) plus runs ~6 detectors in
-- parallel. Pre-fix, a hostile crawler could DoS the site or use it
-- as a GitHub-API request laundromat. This table stores a per-IP
-- rolling counter; the route checks and increments it before kicking
-- off a scan.
--
-- Schema:
--   ip                  text PRIMARY KEY — caller IP (best-effort from
--                       x-forwarded-for; ipv6 is stored verbatim)
--   scan_count          integer — scans started in the current window
--   window_started_at   timestamptz — when the current window began;
--                       lib/rate-limit.ts resets the counter once
--                       this is older than the configured window.
--
-- This is a best-effort counter — there is a small race where two
-- simultaneous requests both read scan_count = N-1 and both decide
-- they're allowed. Acceptable for MVP because the limit (10/hr) is
-- generous enough that the race window doesn't matter. A future
-- migration could move to an atomic increment via a PostgreSQL
-- function if abuse patterns warrant it.

CREATE TABLE IF NOT EXISTS public_scan_rate_limits (
  ip                text PRIMARY KEY,
  scan_count        integer NOT NULL DEFAULT 0,
  window_started_at timestamptz NOT NULL DEFAULT NOW()
);

-- Cleanup index for periodic vacuum of stale rows. Not strictly
-- needed for correctness (lib/rate-limit.ts also resets on read), but
-- keeps the table from growing unbounded for IPs that show up once
-- and never return.
CREATE INDEX IF NOT EXISTS public_scan_rate_limits_window_idx
  ON public_scan_rate_limits (window_started_at);
