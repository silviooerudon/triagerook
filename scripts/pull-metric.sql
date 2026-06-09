-- Pull metric for the 14-day validation round.
--
-- "Pull" = an authenticated user who scanned 2+ DISTINCT repos on their own
-- initiative. This script is read-only and is meant to be pasted into the
-- Supabase SQL editor (Studio). It does not write, create, or alter anything.
--
-- Identity model (verified against the live `scans` table):
--   - scans.user_id (text) holds the stable GitHub numeric user id, written
--     from account.providerAccountId in auth.ts. It is the identity key.
--   - a "repo" is the owner/repo pair (scans.owner || '/' || scans.repo).
--   - scans.scanned_at (timestamptz) is when the scan ran.
--
-- Silvio's own account is excluded: his scans are the only ones in the DB
-- today and would otherwise dominate the metric. He is filtered by GitHub
-- numeric id (227823977) and, defensively, by login (silviooerudon) in case
-- any legacy row stored the login form in user_id.

-- ---------------------------------------------------------------------------
-- Query 1 - HEADLINE: number of users with >= 2 distinct repos (the "pull").
-- ---------------------------------------------------------------------------
select count(*) as pull_users_2plus_repos
from (
  select user_id
  from scans
  where user_id not in ('227823977', 'silviooerudon')
  group by user_id
  having count(distinct owner || '/' || repo) >= 2
) t;

-- ---------------------------------------------------------------------------
-- Query 2 - PER-USER breakdown: distinct repos, first scan, last scan.
-- Sorted so the multi-repo "pull" users surface at the top.
-- ---------------------------------------------------------------------------
select
  user_id,
  count(distinct owner || '/' || repo) as distinct_repos,
  count(*)                              as total_scans,
  min(scanned_at)                       as first_scan,
  max(scanned_at)                       as last_scan
from scans
where user_id not in ('227823977', 'silviooerudon')
group by user_id
order by distinct_repos desc, last_scan desc;
