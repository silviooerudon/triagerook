ALTER TABLE scans
ADD COLUMN IF NOT EXISTS supply_chain_score INTEGER,
ADD COLUMN IF NOT EXISTS supply_chain_level TEXT,
ADD COLUMN IF NOT EXISTS supply_chain_breakdown JSONB,
ADD COLUMN IF NOT EXISTS supply_chain_findings JSONB;
