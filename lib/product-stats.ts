// Single source of truth for the product counts quoted in marketing copy
// (landing stat bar, /compare cells, detector blurbs). Catalog-backed counts
// are DERIVED here - the same catalog the /docs/rules pages render - so adding
// a rule updates the copy automatically. The rest are re-exported from the
// dependency-free lib/product-constants so every surface reads one declaration.
//
// Server-only: this module imports the rule catalog, so it must not be pulled
// into client components. Client UI imports the literals from lib/product-constants
// directly instead.
import { getRuleCatalog, type DetectorLayer } from "@/lib/rule-catalog";

export {
  HISTORY_COMMIT_LIMIT as HISTORY_COMMIT_COUNT,
  SECRET_PATTERN_FLOOR,
  POSTURE_SIGNAL_COUNT,
  IAM_CHECK_COUNT,
} from "@/lib/product-constants";

// Typed against the catalog's union so renaming the "ast" layer is a compile
// error here, not a silent zero count.
const AST_LAYER: DetectorLayer = "ast";

const catalog = getRuleCatalog();

// Total documented rules - matches the count rendered on /docs/rules.
export const RULE_COUNT = catalog.length;

// AST-based SAST rules (TypeScript/JavaScript), tagged layer "ast" in the catalog.
export const AST_RULE_COUNT = catalog.filter(
  (e) => e.layer === AST_LAYER,
).length;
