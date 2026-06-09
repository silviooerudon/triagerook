# Validation-round instrumentation plan

Context: 14-day validation round. We want to measure "pull" = an authenticated
user who scans 2+ distinct repos on their own initiative. This doc is the
briefing for that work and records the investigation conclusion that shaped it.

## Goal

One PR that:

- (a) ships a read-only "pull" metric query (`scripts/pull-metric.sql`);
- (b) guarantees a tester can scan multiple repos — but only if a cap is
  actually blocking that today.

## Step 1 - Investigation: is a "1 repo free" cap enforced?

Question: on the authenticated scan path (`/api/scan/[owner]/[repo]`), is there
a real per-user repo limit that would stop a tester from scanning a second
repo?

Where a limit would have to live, and what is actually there:

- `app/api/scan/[owner]/[repo]/route.ts` (the authenticated POST handler) -
  the full path is: `auth()` -> resolve `getUserId` -> require access token ->
  validate owner/repo/branch shape -> `assertPublicRepo` -> `runFullScan` ->
  `supabase.from("scans").insert(...)` -> return JSON. There is **no** count
  of prior scans, no distinct-repo check, no quota lookup, no entitlement
  gate anywhere in that handler.
- `lib/rate-limit.ts` - the only usage-limiting code in the repo. It is wired
  **exclusively** to the anonymous `/api/scan-public` path (per-IP and
  per-repo fixed-window throttles, backed by the `public_scan_rate_limits`
  table from migration 008). It is never imported by the authenticated path.
- `app/pricing/page.tsx` - lists "One repository" under the Free tier. This is
  marketing copy only. The same page carries a "Beta - free for everyone"
  banner, and nothing reads these constants at scan time.

Data check (Supabase, `scans` table) confirms it empirically: the single user
present today (`user_id = 227823977`, GitHub login `silviooerudon`) has scanned
**14 distinct repos** across 11 distinct owners with no obstruction.

**Conclusion: NOT enforced.** No per-user "1 repo free" cap exists on the
authenticated scan path. Testers can already scan unlimited distinct repos.

## Step 2 - Conditional: allowlist flag

Because Step 1 concluded the cap is **not enforced**, no flag is built. There
is no limit to bypass, so an allowlist table would be dead code. No schema
migration is introduced by this PR. (Had a cap existed, the plan was a minimal
server-side `test_unlimited(github_user_id, note, created_at)` allowlist
checked at the cap site, migration committed before the code that reads it.)

## Step 3 - Pull metric query

`scripts/pull-metric.sql` - read-only, runs in the Supabase SQL editor.

Schema it targets (verified against the live `scans` table before writing):

- `user_id` (text) - stable GitHub numeric user id, written from
  `account.providerAccountId` in `auth.ts`. This is the identity key.
- `owner` (text), `repo` (text) - the scanned repository.
- `scanned_at` (timestamptz) - when the scan ran.

What it reports:

- Per authenticated user: count of distinct repos, first scan, last scan.
- Headline: number of users with >= 2 distinct repos (the "pull" count).

Exclusion: Silvio's own account is filtered out. His scans are the only ones in
the DB today and would otherwise dominate the metric. He is excluded by GitHub
numeric id (`227823977`) and, defensively, by login (`silviooerudon`) in case
any legacy rows stored the login form in `user_id`.

Validation: confirmed via `SELECT`, not via an HTTP 200.

## Workflow record

- `git pull --rebase` before starting; branch even with `main`.
- This plan doc committed before any code.
- Feature branch `claude/triagerook-pull-metric-id8ctl`, signed commits.
- `npm run build` before each commit.
- No schema migration (no flag, per Step 2).
- PR opened, Vercel preview awaited, merged via "Create a merge commit"
  (never squash/rebase).
- Branch cleanup is the last step, after merge is confirmed on `main`.

## Post-round cleanup

Nothing to remove from the running app: this PR adds only a SQL script and
docs, no schema and no runtime code. After the round, `scripts/pull-metric.sql`
and this plan doc can be kept as historical record or deleted; neither affects
the application.
