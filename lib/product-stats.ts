// Single source of truth for the product counts quoted in marketing copy
// (landing stat bar, /compare cells, detector blurbs). Centralised here so a
// number is declared once and cannot drift between pages the way the landing
// rule count silently did (172 -> 235).
//
// Counts that live in the rule catalog are DERIVED from it - the same catalog
// the /docs/rules pages render - so adding a rule updates the copy automatically.
// Counts owned by separate detectors (posture, IAM lens) are not catalog rules,
// so they are kept here as documented constants verified against their source.
import { getRuleCatalog } from "@/lib/rule-catalog";

const catalog = getRuleCatalog();

// Total documented rules - matches the count rendered on /docs/rules.
export const RULE_COUNT = catalog.length;

// AST-based SAST rules (TypeScript/JavaScript), tagged layer "ast" in the catalog.
export const AST_RULE_COUNT = catalog.filter((e) => e.layer === "ast").length;

// Repo posture signals graded A-F. Source: the signal weights in lib/posture.ts.
export const POSTURE_SIGNAL_COUNT = 17;

// IAM lens checks: 4 OIDC trust (lib/iam.ts) + 5 privilege-escalation
// (lib/iam-privesc.ts) + 3 admin-equivalent (lib/iam-admin.ts).
export const IAM_CHECK_COUNT = 12;

// Conservative floor advertised for secret patterns; the real
// SECRET_PATTERNS list (lib/secret-patterns.ts) is larger, so "60+" only ever
// understates and never drifts wrong.
export const SECRET_PATTERN_FLOOR = 60;

// Commits replayed in the git-history secret pass. Source: HISTORY_COMMIT_LIMIT
// in lib/history.ts.
export const HISTORY_COMMIT_COUNT = 30;
