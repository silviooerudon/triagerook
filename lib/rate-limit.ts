// Per-key fixed-window rate limiter. Used by /api/scan-public to cap
// anonymous scan trigger rate and protect GitHub's anon API quota
// from abuse.
//
// Design notes:
//   - Fixed window (vs sliding) for simplicity; a fixed window may
//     allow short bursts at the boundary, which is fine for our limit
//     of 10 scans/hour.
//   - Storage interface is injected so tests can run in-memory without
//     standing up Supabase. The production export uses the Supabase
//     `public_scan_rate_limits` table (migration 008).
//   - Storage failure: defaults to fail-open (allow the request,
//     log a warning) for backwards compatibility. Callers protecting
//     abuse-sensitive endpoints should pass `failClosed: true` so a
//     Supabase outage cannot be used to bypass throttling. failClosed
//     applies to BOTH the get and the upsert paths — a successful read
//     followed by a failed write would otherwise leave the counter
//     stale and let an abuser hammer the endpoint until storage
//     recovers. /api/scan-public uses fail-closed because the scan
//     itself depends on Supabase anyway — if storage is down, the
//     user-visible 503 from rate-limit is no worse than a downstream
//     failure.
//   - Race window: two simultaneous requests can both read N-1 and
//     both decide they're allowed at N. Acceptable for the 10/hr
//     limit; if abuse warrants it, the get+upsert becomes a single
//     atomic SQL function call.

import { createHmac } from "node:crypto"

// Turns a caller IP into the opaque key stored in public_scan_rate_limits.
//
// Data minimisation (GDPR Art. 5(1)(c) / LGPD Art. 6, III): the raw IP is
// never persisted. A plain SHA-256 would not be enough — the whole IPv4
// space can be hashed in minutes, so an unkeyed hash is trivially
// reversible. A keyed HMAC is not reversible without the server secret.
// The fixed prefix domain-separates this use of the secret from any other.
//
// The secret is RATE_LIMIT_HASH_SECRET when set, otherwise AUTH_SECRET
// (always present — the app cannot boot without it). Rotating the secret
// simply resets every per-IP counter, which is harmless.
export function ipRateLimitKey(
  ip: string,
  secret: string | undefined = process.env.RATE_LIMIT_HASH_SECRET || process.env.AUTH_SECRET,
): string {
  if (!secret) {
    throw new Error("[rate-limit] no secret configured for IP pseudonymisation")
  }
  const digest = createHmac("sha256", secret)
    .update(`triagerook:rate-limit:ip:v1:${ip}`)
    .digest("hex")
  // 128 bits is far beyond collision risk for this table.
  return `ip:${digest.slice(0, 32)}`
}

// Counters older than this are useless (every window is 1h) and are
// purged opportunistically so pseudonymised IPs are not kept longer than
// needed (storage limitation, GDPR Art. 5(1)(e) / LGPD Art. 15-16).
const STALE_AFTER_MS = 2 * 60 * 60 * 1000
const PURGE_PROBABILITY = 0.02

export type RateLimitPolicy = {
  limit: number
  windowMs: number
}

export type RateLimitRecord = {
  scanCount: number
  windowStartedAt: Date
}

export interface RateLimitStorage {
  get(key: string): Promise<RateLimitRecord | null>
  upsert(key: string, record: RateLimitRecord): Promise<void>
}

export type RateLimitResult = {
  allowed: boolean
  remaining: number
  retryAfterSeconds: number
}

export type CheckOptions = {
  storage?: RateLimitStorage
  now?: Date
  // When true, deny the request if storage is unavailable. Callers that
  // protect abuse-sensitive endpoints (anonymous scans) should set this.
  // Default false preserves the legacy fail-open behavior other callers
  // may depend on.
  failClosed?: boolean
}

export async function checkAndIncrement(
  key: string,
  policy: RateLimitPolicy,
  options: CheckOptions = {},
): Promise<RateLimitResult> {
  const storage = options.storage ?? supabaseStorage
  const now = options.now ?? new Date()

  let existing: RateLimitRecord | null
  try {
    existing = await storage.get(key)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    if (options.failClosed) {
      console.warn("[rate-limit] storage.get failed; failing CLOSED:", msg)
      // Retry-After of one window is conservative — the caller surfaces
      // it as 503 / Retry-After so abusive automation actually backs off.
      return {
        allowed: false,
        remaining: 0,
        retryAfterSeconds: Math.ceil(policy.windowMs / 1000),
      }
    }
    console.warn("[rate-limit] storage.get failed; failing open:", msg)
    return { allowed: true, remaining: policy.limit - 1, retryAfterSeconds: 0 }
  }

  const inCurrentWindow =
    existing !== null &&
    now.getTime() - existing.windowStartedAt.getTime() < policy.windowMs

  const next: RateLimitRecord = inCurrentWindow
    ? { scanCount: existing!.scanCount + 1, windowStartedAt: existing!.windowStartedAt }
    : { scanCount: 1, windowStartedAt: now }

  if (next.scanCount > policy.limit) {
    const windowExpiresAt = next.windowStartedAt.getTime() + policy.windowMs
    const retryAfterSeconds = Math.max(
      1,
      Math.ceil((windowExpiresAt - now.getTime()) / 1000),
    )
    return { allowed: false, remaining: 0, retryAfterSeconds }
  }

  try {
    await storage.upsert(key, next)
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    if (options.failClosed) {
      // Symmetric with the storage.get fail-closed branch above. If we
      // can't persist the counter, a follow-up request inside the same
      // window would read the old value and re-allow — that's exactly
      // the "rotate during a Supabase outage" bypass the failClosed
      // option exists to prevent.
      console.warn("[rate-limit] storage.upsert failed; failing CLOSED:", msg)
      return {
        allowed: false,
        remaining: 0,
        retryAfterSeconds: Math.ceil(policy.windowMs / 1000),
      }
    }
    console.warn("[rate-limit] storage.upsert failed; allowing this request:", msg)
  }

  return {
    allowed: true,
    remaining: Math.max(0, policy.limit - next.scanCount),
    retryAfterSeconds: 0,
  }
}

// Supabase-backed storage used in production. Reads and writes the
// `public_scan_rate_limits` table (migration 008). Despite the column
// name `ip`, it holds an opaque key: `ip:<hmac>` (see ipRateLimitKey) or
// `repo:<owner>/<repo>` — never a raw IP address (migration 011). Returns null when
// no row exists for this key.
//
// The Supabase client is imported lazily inside each method so that
// unit tests can pass `inMemoryStorage()` and never touch the real
// client (which throws at import-time on missing env vars).
const supabaseStorage: RateLimitStorage = {
  async get(key) {
    const { supabase } = await import("./supabase")
    const { data, error } = await supabase
      .from("public_scan_rate_limits")
      .select("scan_count, window_started_at")
      .eq("ip", key)
      .maybeSingle<{ scan_count: number; window_started_at: string }>()
    if (error) throw new Error(error.message)
    if (!data) return null
    return {
      scanCount: data.scan_count,
      windowStartedAt: new Date(data.window_started_at),
    }
  },
  async upsert(key, record) {
    const { supabase } = await import("./supabase")
    const { error } = await supabase
      .from("public_scan_rate_limits")
      .upsert(
        {
          ip: key,
          scan_count: record.scanCount,
          window_started_at: record.windowStartedAt.toISOString(),
        },
        { onConflict: "ip" },
      )
    if (error) throw new Error(error.message)

    // Opportunistic retention sweep on ~2% of writes. Works on any
    // Supabase plan (no pg_cron needed). Best-effort: a failed purge must
    // never fail the request that triggered it.
    if (Math.random() < PURGE_PROBABILITY) {
      const cutoff = new Date(Date.now() - STALE_AFTER_MS).toISOString()
      const { error: purgeError } = await supabase
        .from("public_scan_rate_limits")
        .delete()
        .lt("window_started_at", cutoff)
      if (purgeError) {
        console.warn("[rate-limit] stale-row purge failed:", purgeError.message)
      }
    }
  },
}

// Pre-baked policy for /api/scan-public. Default 10 anonymous scans
// per hour per source IP — generous for an evaluator clicking around,
// restrictive enough to stop automated abuse fast. The limit can be
// raised via PUBLIC_SCAN_LIMIT_PER_IP for short windows (e.g. the
// hours surrounding a Show HN front-page event) without redeploying
// code; setting the env var on Vercel and triggering a redeploy is
// enough. Values <1 fall back to the safe default.
export const PUBLIC_SCAN_POLICY: RateLimitPolicy = {
  limit: parsePositiveInt(process.env.PUBLIC_SCAN_LIMIT_PER_IP, 10),
  windowMs: 60 * 60 * 1000,
}

// Secondary throttle scoped to owner/repo, regardless of caller IP.
// Stops "rotate the IP to keep scanning the same repo" abuse and caps
// total GitHub API spend per target. Default 5/hour — fine in steady
// state but a hard ceiling for a Show HN spike where hundreds of
// visitors try the same featured repo. Override with
// PUBLIC_SCAN_LIMIT_PER_REPO when expecting a surge.
export const PUBLIC_SCAN_PER_REPO_POLICY: RateLimitPolicy = {
  limit: parsePositiveInt(process.env.PUBLIC_SCAN_LIMIT_PER_REPO, 5),
  windowMs: 60 * 60 * 1000,
}

function parsePositiveInt(value: string | undefined, fallback: number): number {
  if (!value) return fallback
  const n = Number.parseInt(value, 10)
  return Number.isFinite(n) && n > 0 ? n : fallback
}
