import type { SecretFinding } from "./types"

// Secret validation engine.
//
// Goal: given a secret we detected, decide whether it is STILL ACTIVE without
// ever exposing or storing the value. An inactive (revoked/rotated) secret is
// far lower priority than a live one, so validation slashes false-positive
// triage noise and lets us boost confirmed-live secrets to the top.
//
// SAFETY / PRIVACY (read before extending):
//   • Off by default. The capability is gated behind ENABLE_SECRET_VALIDATION
//     AND a per-call flag, so it NEVER runs on the anonymous public-scan path
//     (which scans arbitrary repos — we must not fire third-party API calls
//     with strangers' leaked credentials from there).
//   • Read-only. Every validator makes a single minimal GET to the provider's
//     identity/balance endpoint. No mutations, no message sends.
//   • The raw secret value lives only in memory for the duration of the call.
//     It is never logged, never returned, and never written to the finding —
//     only the resulting status string is.
//   • Short timeout + bounded concurrency so a scan can't hang on a slow
//     provider or hammer one.

export type ValidationStatus =
  | "active" // provider confirmed the credential works
  | "inactive" // provider rejected it (revoked / rotated / invalid)
  | "unverifiable" // no safe read-only check exists for this secret type
  | "error" // network/timeout — we genuinely don't know
  | "skipped" // validation disabled or not attempted

export type FetchLike = (
  url: string,
  init?: RequestInit,
) => Promise<{ status: number }>

type Validator = {
  // Pull the bare token out of the raw regex match (which may include
  // surrounding context like `_authToken=` or quotes).
  extract: (raw: string) => string | null
  // Perform the read-only check. MUST NOT log or return the token.
  check: (token: string, fetchImpl: FetchLike) => Promise<ValidationStatus>
}

const DEFAULT_TIMEOUT_MS = 5000

// A small helper: GET `url` with `headers`, map status codes to a verdict.
// 2xx → active; 401/403 → inactive; anything else → error. Times out safely.
async function probe(
  url: string,
  headers: Record<string, string>,
  fetchImpl: FetchLike,
  timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<ValidationStatus> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetchImpl(url, {
      method: "GET",
      headers,
      signal: controller.signal,
      // Never cache a credential probe.
      cache: "no-store",
    } as RequestInit)
    if (res.status >= 200 && res.status < 300) return "active"
    if (res.status === 401 || res.status === 403) return "inactive"
    return "error"
  } catch {
    return "error"
  } finally {
    clearTimeout(timer)
  }
}

const FIRST = (re: RegExp) => (raw: string): string | null => {
  const m = raw.match(re)
  return m ? m[0] : null
}

// Mapping from secret patternId → validator. Patterns not listed here are
// `unverifiable` (e.g. AWS needs both key halves + SigV4 signing; Slack
// webhooks can only be tested by posting a message).
const VALIDATORS: Record<string, Validator> = {
  // ── GitHub tokens — GET /user echoes the authenticated identity ──
  ...mapMany(
    ["github-pat", "github-oauth", "github-user-to-server", "github-server-to-server"],
    {
      extract: FIRST(/gh[posu]_[A-Za-z0-9]{36,}/),
      check: (t, f) =>
        probe("https://api.github.com/user", { Authorization: `token ${t}`, "User-Agent": "triagerook" }, f),
    },
  ),
  "github-fine-grained-pat": {
    extract: FIRST(/github_pat_[A-Za-z0-9_]{22,}/),
    check: (t, f) =>
      probe("https://api.github.com/user", { Authorization: `Bearer ${t}`, "User-Agent": "triagerook" }, f),
  },
  "gitlab-pat": {
    extract: FIRST(/glpat-[A-Za-z0-9_-]{20,}/),
    check: (t, f) => probe("https://gitlab.com/api/v4/user", { "PRIVATE-TOKEN": t }, f),
  },
  // ── AI providers ──
  "anthropic-api-key": {
    extract: FIRST(/sk-ant-[A-Za-z0-9_-]{20,}/),
    check: (t, f) =>
      probe("https://api.anthropic.com/v1/models", { "x-api-key": t, "anthropic-version": "2023-06-01" }, f),
  },
  ...mapMany(["openai-api-key", "openai-legacy-key"], {
    extract: FIRST(/sk-[A-Za-z0-9_-]{20,}/),
    check: (t, f) => probe("https://api.openai.com/v1/models", { Authorization: `Bearer ${t}` }, f),
  }),
  // ── Payments ──
  ...mapMany(["stripe-live-secret", "stripe-restricted-live", "stripe-test-secret"], {
    extract: FIRST(/(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}/),
    check: (t, f) => probe("https://api.stripe.com/v1/balance", { Authorization: `Bearer ${t}` }, f),
  }),
  // ── Comms / email ──
  "sendgrid-key": {
    extract: FIRST(/SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/),
    check: (t, f) => probe("https://api.sendgrid.com/v3/scopes", { Authorization: `Bearer ${t}` }, f),
  },
  "slack-token": {
    extract: FIRST(/xox[baprs]-[A-Za-z0-9-]{10,}/),
    check: (t, f) => probe("https://slack.com/api/auth.test", { Authorization: `Bearer ${t}` }, f),
  },
  // ── Package registries ──
  ...mapMany(["npm-access-token", "npmrc-authtoken"], {
    extract: FIRST(/npm_[A-Za-z0-9]{36}/),
    check: (t, f) =>
      probe("https://registry.npmjs.org/-/npm/v1/user", { Authorization: `Bearer ${t}` }, f),
  }),
}

function mapMany(ids: string[], v: Validator): Record<string, Validator> {
  return Object.fromEntries(ids.map((id) => [id, v]))
}

/** True when the secret-validation capability is enabled for this deployment. */
export function isSecretValidationEnabled(): boolean {
  return process.env.ENABLE_SECRET_VALIDATION === "true"
}

/** Whether a given secret type has a validator (i.e. is verifiable at all). */
export function isVerifiable(patternId: string): boolean {
  return patternId in VALIDATORS
}

// One detected secret paired with its raw value. This pairing is transient —
// callers keep it in local scope only and never persist the rawValue.
export type SecretWithValue = {
  finding: SecretFinding
  rawValue: string
}

export type ValidateOptions = {
  // Per-call gate. The authenticated path may pass true; the anonymous
  // public path MUST pass false. Combined with isSecretValidationEnabled().
  enabled: boolean
  concurrency?: number
  fetchImpl?: FetchLike
}

/**
 * Validate a batch of detected secrets in place: sets `finding.validation`
 * on each. Returns the same findings for convenience. Raw values are consumed
 * here and never leave this function.
 *
 * No-ops (marks everything "skipped") unless BOTH the deployment flag and the
 * per-call flag are set.
 */
export async function validateSecrets(
  secrets: SecretWithValue[],
  options: ValidateOptions,
): Promise<void> {
  const active = options.enabled && isSecretValidationEnabled()
  if (!active) {
    for (const s of secrets) s.finding.validation = "skipped"
    return
  }

  const fetchImpl: FetchLike =
    options.fetchImpl ?? ((url, init) => fetch(url, init))
  const concurrency = Math.max(1, options.concurrency ?? 5)

  const queue = [...secrets]
  async function worker() {
    for (;;) {
      const item = queue.shift()
      if (!item) return
      item.finding.validation = await validateOne(item, fetchImpl)
    }
  }
  await Promise.all(
    Array.from({ length: Math.min(concurrency, queue.length) }, () => worker()),
  )
}

async function validateOne(
  item: SecretWithValue,
  fetchImpl: FetchLike,
): Promise<ValidationStatus> {
  const validator = VALIDATORS[item.finding.patternId]
  if (!validator) return "unverifiable"
  const token = validator.extract(item.rawValue)
  if (!token) return "unverifiable"
  return validator.check(token, fetchImpl)
}
