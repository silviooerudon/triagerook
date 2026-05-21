import type { Severity } from "./types"

// Detector inputs (npm audit, OSV.dev, GHSA) historically used "moderate"
// for what TriageRook internally calls "medium". To keep one canonical
// severity vocabulary, every detector boundary should pass the raw
// string through normalizeSeverity before constructing a Finding.
//
// Old scans persisted before this normalizer existed may still carry
// "moderate" in their stored JSONB; consumer code (risk.ts, scan-findings.tsx,
// the diff page) still accepts both shapes to keep historical data
// rendering. New scans never produce "moderate".
export function normalizeSeverity(raw: string | null | undefined): Severity {
  if (!raw) return "low"
  const lower = raw.toLowerCase()
  if (lower === "critical") return "critical"
  if (lower === "high") return "high"
  if (lower === "medium" || lower === "moderate") return "medium"
  if (lower === "low") return "low"
  return "low"
}
