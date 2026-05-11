-- Migration 006: persist computed risk breakdown + prioritized findings + missing
-- count fields so reads from /api/scans/[id] don't have to re-derive them from
-- the raw JSONB on every request.
--
-- Why this matters:
--   • Re-deriving causes score *drift* whenever detector rules change: a scan
--     stored at t0 with rule-set v1 is silently re-scored under rule-set v2
--     when viewed at t1. Persisting locks the score to what the user saw.
--   • Without persisted prioritized_findings, scan-to-scan diff (next feature)
--     can't compare two scans cheaply — every diff would re-flatten and
--     re-score on the fly.
--   • iam.filesScanned and supplyChain.scanned were never persisted, so the
--     view page footers show "across 0 files" for legacy scans. These columns
--     fix that going forward.
--
-- All columns are nullable and added with IF NOT EXISTS for safety. Legacy
-- scans (pre-this-migration) leave them NULL; the read path falls back to
-- the existing re-derive logic when they're absent.

ALTER TABLE scans
ADD COLUMN IF NOT EXISTS risk_breakdown JSONB,
ADD COLUMN IF NOT EXISTS prioritized_findings JSONB,
ADD COLUMN IF NOT EXISTS iam_files_scanned INTEGER,
ADD COLUMN IF NOT EXISTS supply_chain_scanned JSONB;
