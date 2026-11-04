// Data-subject rights for signed-in users: access/portability (GDPR Art. 15
// and 20, LGPD Art. 18 II and V) and erasure (GDPR Art. 17, LGPD Art. 18 VI).
//
// Every function here is keyed on the stable GitHub numeric user id from
// getUserId(session) — never on a value supplied by the request — so a user
// can only ever export or erase their own rows.
//
// SERVER-ONLY: imports the service-role Supabase client.

import { supabase } from "@/lib/supabase"

// Tables that hold rows keyed by user_id. If a migration adds another
// user-owned table, it MUST be added here or erasure is incomplete.
export const USER_OWNED_TABLES = ["scans", "suppressions"] as const

const PAGE_SIZE = 200
// Hard ceiling so a pathological account can't turn an export into an
// unbounded memory spike. Far above any real account today (the history
// page only ever shows 50 scans).
const MAX_ROWS_PER_TABLE = 5000

export type AccountSummary = Record<(typeof USER_OWNED_TABLES)[number], number>

export async function getAccountSummary(userId: string): Promise<AccountSummary> {
  const summary = {} as AccountSummary
  for (const table of USER_OWNED_TABLES) {
    const { count, error } = await supabase
      .from(table)
      .select("id", { count: "exact", head: true })
      .eq("user_id", userId)
    if (error) throw new Error(`[account] count ${table} failed: ${error.message}`)
    summary[table] = count ?? 0
  }
  return summary
}

export type AccountExport = {
  exportedAt: string
  userId: string
  notice: string
  data: Record<(typeof USER_OWNED_TABLES)[number], unknown[]>
}

export async function exportUserData(userId: string): Promise<AccountExport> {
  const data = {} as AccountExport["data"]
  for (const table of USER_OWNED_TABLES) {
    const rows: unknown[] = []
    for (let from = 0; from < MAX_ROWS_PER_TABLE; from += PAGE_SIZE) {
      const { data: page, error } = await supabase
        .from(table)
        .select("*")
        .eq("user_id", userId)
        .order("id", { ascending: true })
        .range(from, from + PAGE_SIZE - 1)
      if (error) throw new Error(`[account] export ${table} failed: ${error.message}`)
      if (!page || page.length === 0) break
      rows.push(...page)
      if (page.length < PAGE_SIZE) break
    }
    data[table] = rows
  }
  return {
    exportedAt: new Date().toISOString(),
    userId,
    notice:
      "All personal data TriageRook stores about this GitHub account. Secret values inside scan results were masked at detection time and were never stored in full.",
    data,
  }
}

// Permanently deletes every row the user owns. Suppressions go first so a
// partial failure never leaves suppressions pointing at deleted scans.
export async function deleteUserData(userId: string): Promise<void> {
  if (!userId) throw new Error("[account] refusing to delete without a user id")
  for (const table of ["suppressions", "scans"] as const) {
    const { error } = await supabase.from(table).delete().eq("user_id", userId)
    if (error) throw new Error(`[account] delete ${table} failed: ${error.message}`)
  }
}

// Best-effort revocation of the user's GitHub App authorization, so erasing
// the account also removes TriageRook from the user's "Authorized GitHub
// Apps" list. Uses GitHub's documented
// DELETE /applications/{client_id}/grant endpoint, authenticated with the
// App's client credentials. Never throws: a failure here must not undo or
// block the data erasure that already succeeded — the user is told to
// revoke manually instead.
export async function revokeGitHubGrant(accessToken: string | undefined): Promise<boolean> {
  const clientId = process.env.AUTH_GITHUB_APP_CLIENT_ID
  const clientSecret = process.env.AUTH_GITHUB_APP_CLIENT_SECRET
  if (!accessToken || !clientId || !clientSecret) return false
  try {
    const res = await fetch(
      `https://api.github.com/applications/${encodeURIComponent(clientId)}/grant`,
      {
        method: "DELETE",
        headers: {
          Accept: "application/vnd.github+json",
          Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`,
          "Content-Type": "application/json",
          "X-GitHub-Api-Version": "2022-11-28",
        },
        body: JSON.stringify({ access_token: accessToken }),
        signal: AbortSignal.timeout(5000),
      },
    )
    // 204 = revoked; 404/422 = already gone. Either way nothing remains.
    return res.status === 204 || res.status === 404 || res.status === 422
  } catch (err) {
    console.warn(
      "[account] GitHub grant revocation failed:",
      err instanceof Error ? err.message : String(err),
    )
    return false
  }
}
