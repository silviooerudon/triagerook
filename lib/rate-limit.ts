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
//   - Fail-open semantics: if storage.get throws, we let the request
//     through. A rate limiter that fails closed could take the whole
//     site down on a Supabase blip; failing open keeps the site up
//     and just temporarily loses the limit. Logged so we notice.
//   - Race window: two simultaneous requests can both read N-1 and
//     both decide they're allowed at N. Acceptable for the 10/hr
//     limit; if abuse warrants it, the get+upsert becomes a single
//     atomic SQL function call.

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
    console.warn(
      "[rate-limit] storage.get failed; failing open:",
      err instanceof Error ? err.message : String(err),
    )
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
    console.warn(
      "[rate-limit] storage.upsert failed; allowing this request:",
      err instanceof Error ? err.message : String(err),
    )
  }

  return {
    allowed: true,
    remaining: Math.max(0, policy.limit - next.scanCount),
    retryAfterSeconds: 0,
  }
}

// Supabase-backed storage used in production. Reads and writes the
// `public_scan_rate_limits` table (migration 008). Returns null when
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
  },
}

// Pre-baked policy for /api/scan-public. 10 anonymous scans per hour
// per source IP — generous enough that an evaluator clicking around
// won't trip it, restrictive enough that automated abuse stops fast.
export const PUBLIC_SCAN_POLICY: RateLimitPolicy = {
  limit: 10,
  windowMs: 60 * 60 * 1000,
}
