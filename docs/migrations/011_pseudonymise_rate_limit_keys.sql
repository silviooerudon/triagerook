-- Migration 011: stop storing raw IP addresses in public_scan_rate_limits.
--
-- Background
--   Until now the per-IP anonymous-scan counter used the caller's raw IP
--   address as the primary key. An IP address is personal data under the
--   GDPR (CJEU C-582/14, Breyer) and the LGPD. From this release the app
--   writes `ip:<HMAC-SHA256(secret, ip)>` instead (lib/rate-limit.ts,
--   ipRateLimitKey), and opportunistically purges counters older than 2h.
--
-- What this migration does
--   1. Deletes every legacy row whose key is a raw IP — i.e. anything that
--      is not already an `ip:` hash or a `repo:` counter. The only effect is
--      that in-flight per-IP counters restart from zero once.
--   2. Deletes any counter older than 2 hours (the window is 1 hour), so
--      nothing older than needed survives the deploy.
--   3. Documents the column's new meaning.
--
-- Deploy order: ship the application change first, then run this. Running
-- it again later is safe (idempotent).

DELETE FROM public.public_scan_rate_limits
WHERE ip NOT LIKE 'ip:%'
  AND ip NOT LIKE 'repo:%';

DELETE FROM public.public_scan_rate_limits
WHERE window_started_at < NOW() - INTERVAL '2 hours';

COMMENT ON COLUMN public.public_scan_rate_limits.ip IS
  'Opaque rate-limit key: ip:<hmac-sha256 hex> or repo:<owner>/<repo>. Never a raw IP address.';
