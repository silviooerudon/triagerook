import { supabase } from "./supabase"
import type { Suppression } from "./suppressions"

// Per-user, per-repo suppressions stored in Postgres (migration 009).
// Complements the in-repo `.repoguardignore` file by letting a user mute
// findings without committing anything. The scan flow loads both sources
// and unions them.

export type DbSuppression = {
  id: string
  user_id: string
  owner: string
  repo: string
  path_glob: string
  rule_glob: string | null
  reason: string | null
  expires_at: string | null
  created_at: string
}

export type CreateSuppressionInput = {
  userId: string
  owner: string
  repo: string
  pathGlob: string
  ruleGlob?: string | null
  reason?: string | null
  expiresAt?: string | null // ISO date 'YYYY-MM-DD' or full timestamp
}

// List all suppressions a user has created for a given repo. Returns rows
// in insert order so the dashboard renders newest-first when sorted.
export async function listSuppressions(
  userId: string,
  owner: string,
  repo: string,
): Promise<DbSuppression[]> {
  const { data, error } = await supabase
    .from("suppressions")
    .select("id, user_id, owner, repo, path_glob, rule_glob, reason, expires_at, created_at")
    .eq("user_id", userId)
    .eq("owner", owner)
    .eq("repo", repo)
    .order("created_at", { ascending: false })

  if (error) throw new Error(error.message)
  return (data ?? []) as DbSuppression[]
}

// All suppressions for the user, across all their repos. Powers the
// global /dashboard/suppressions view.
export async function listAllUserSuppressions(
  userId: string,
): Promise<DbSuppression[]> {
  const { data, error } = await supabase
    .from("suppressions")
    .select("id, user_id, owner, repo, path_glob, rule_glob, reason, expires_at, created_at")
    .eq("user_id", userId)
    .order("created_at", { ascending: false })
  if (error) throw new Error(error.message)
  return (data ?? []) as DbSuppression[]
}

export async function createSuppression(
  input: CreateSuppressionInput,
): Promise<DbSuppression> {
  const row = {
    user_id: input.userId,
    owner: input.owner,
    repo: input.repo,
    path_glob: input.pathGlob,
    rule_glob: input.ruleGlob ?? null,
    reason: input.reason ?? null,
    expires_at: input.expiresAt ?? null,
  }
  const { data, error } = await supabase
    .from("suppressions")
    .insert(row)
    .select("id, user_id, owner, repo, path_glob, rule_glob, reason, expires_at, created_at")
    .single<DbSuppression>()
  if (error || !data) throw new Error(error?.message ?? "Failed to insert suppression")
  return data
}

// Delete is per-id, gated on user ownership so a malicious caller with
// another user's id can't wipe their suppressions.
export async function deleteSuppression(
  userId: string,
  id: string,
): Promise<boolean> {
  const { data, error } = await supabase
    .from("suppressions")
    .delete()
    .eq("id", id)
    .eq("user_id", userId)
    .select("id")
    .maybeSingle<{ id: string }>()
  if (error) throw new Error(error.message)
  return data !== null
}

// Adapter from DB row shape into the in-memory Suppression type that
// applySuppressions() consumes. sourceLine is synthesised — DB rows
// don't have one, so we encode the id in the high digits as a stable
// tag that the UI can use to display a "Suppressed via dashboard" badge
// when relevant (current dashboard doesn't surface this yet; future
// work).
export function toRuntimeSuppression(row: DbSuppression, index: number): Suppression {
  const s: Suppression = {
    pathGlob: row.path_glob,
    sourceLine: 100000 + index, // distinct namespace from file-line numbers
  }
  if (row.rule_glob) s.ruleGlob = row.rule_glob
  if (row.reason) s.reason = row.reason
  if (row.expires_at) {
    // Store accepts a full ISO timestamp; the Suppression.expires field is
    // an ISO date string ("YYYY-MM-DD"). Truncate to the date component.
    s.expires = row.expires_at.slice(0, 10)
  }
  return s
}
