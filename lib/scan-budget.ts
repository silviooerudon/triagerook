// Scan budget — per-run caps on files inspected and wall-clock time.
//
// Both numbers default to safe Vercel Hobby values (60s function
// timeout) and can be raised via environment variables when running on
// a plan with a higher function timeout (Vercel Pro = 300s):
//
//   SCAN_MAX_FILES      — integer, default 1000, capped at 10000
//   SCAN_MAX_TIME_MS    — integer (milliseconds), default 55000, capped at 290000
//
// We resolve at module load so the values are stable for the lifetime
// of a cold-start instance. Changing an env var on Vercel triggers a
// redeploy / new instance anyway, so re-reading per request would just
// be wasted work.
//
// Why getter functions instead of bare consts? So tests can swap
// process.env and call the getter to verify parsing without mocking
// module state. Production callers use them once at the top of
// scanRepo() and store the result locally.

const DEFAULT_MAX_FILES = 1000
const ABSOLUTE_MAX_FILES = 10000
const DEFAULT_MAX_TIME_MS = 55_000
// 290000 leaves 10s of headroom below the 300s Vercel Pro limit so
// post-loop work (history scan, posture/IAM checks) can still finish.
const ABSOLUTE_MAX_TIME_MS = 290_000

export function parsePositiveIntInRange(
  raw: string | undefined,
  defaultValue: number,
  absMax: number,
): number {
  if (!raw) return defaultValue
  const n = Number.parseInt(raw, 10)
  if (!Number.isFinite(n) || n <= 0) return defaultValue
  return Math.min(n, absMax)
}

export function getMaxFilesToScan(): number {
  return parsePositiveIntInRange(
    process.env.SCAN_MAX_FILES,
    DEFAULT_MAX_FILES,
    ABSOLUTE_MAX_FILES,
  )
}

export function getMaxScanTimeMs(): number {
  return parsePositiveIntInRange(
    process.env.SCAN_MAX_TIME_MS,
    DEFAULT_MAX_TIME_MS,
    ABSOLUTE_MAX_TIME_MS,
  )
}

// Re-exported so callers / tests can compare against the documented
// defaults without re-reading the file. Don't import in tests that
// want to verify env behaviour — set process.env and call the getter.
export const DEFAULTS = {
  files: DEFAULT_MAX_FILES,
  timeMs: DEFAULT_MAX_TIME_MS,
} as const

export const LIMITS = {
  files: ABSOLUTE_MAX_FILES,
  timeMs: ABSOLUTE_MAX_TIME_MS,
} as const
