-- Migration 009: user-scoped per-repo suppressions.
--
-- Background
--   So far `.repoguardignore` (a file committed to the repo) is the only
--   way to mute a finding. That works for team-wide, code-reviewed
--   suppressions but is friction for the "I just want to mute this one
--   finding from my own dashboard" case — every suppression needs a
--   commit + push, and a private/personal scan repo may not even have
--   a place to commit one.
--
--   This migration adds a per-(user, repo) suppression store. The
--   /api/scan flow loads them alongside the in-repo .repoguardignore
--   and unions both into a single Suppression[] before applying.
--
-- Schema:
--   id          uuid PRIMARY KEY
--   user_id     text   — same scheme as scans.user_id (GitHub provider id)
--   owner       text   — repo owner (case-sensitive)
--   repo        text   — repo name (case-sensitive)
--   path_glob   text   — first token (no spaces); matches getFindingPaths()
--   rule_glob   text NULL — null = path-only suppression
--   reason      text NULL
--   expires_at  timestamptz NULL
--   created_at  timestamptz default now()
--
-- An owner/repo pair plus (path_glob, rule_glob) is the natural key —
-- but uniqueness is intentionally soft (no unique constraint) so that
-- two near-duplicate entries with different reasons/expires can coexist
-- without the API throwing. The reader just picks the most specific
-- match like applySuppressions() already does.

CREATE TABLE IF NOT EXISTS suppressions (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     text NOT NULL,
  owner       text NOT NULL,
  repo        text NOT NULL,
  path_glob   text NOT NULL,
  rule_glob   text,
  reason      text,
  expires_at  timestamptz,
  created_at  timestamptz NOT NULL DEFAULT NOW()
);

-- Reads always filter by user + owner + repo. Compound index covers
-- the hottest path (loading every active suppression for a given
-- scan).
CREATE INDEX IF NOT EXISTS suppressions_user_owner_repo_idx
  ON suppressions (user_id, owner, repo);
