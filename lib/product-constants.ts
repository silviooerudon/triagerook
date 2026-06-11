// Dependency-free product counts shared between scan behavior (lib/history.ts),
// the marketing pages, and client UI (scan-progress). Declared once here so a
// number cannot drift across surfaces. This module MUST stay import-free so it
// is safe to pull into client components without dragging server code along.

// Git-history secret replay depth. Imported by lib/history.ts (the actual
// behavior) and quoted in marketing copy, so the advertised number always
// equals what the scanner does.
export const HISTORY_COMMIT_LIMIT = 30;

// Conservative advertised floor for secret patterns. The real SECRET_PATTERNS
// list (lib/secret-patterns.ts) is larger, so "60+" only ever understates and
// never reads wrong.
export const SECRET_PATTERN_FLOOR = 60;

// Repo posture signals graded A-F. Source: the signal weights in lib/posture.ts.
// Not derivable yet - the signals are built from runtime data inside
// computeScore - so this is hand-maintained and verified against source.
export const POSTURE_SIGNAL_COUNT = 17;

// IAM lens checks: 4 OIDC trust (lib/iam.ts) + 5 privilege-escalation
// (lib/iam-privesc.ts) + 3 admin-equivalent (lib/iam-admin.ts). These are
// imperative detectors, not an enumerable rule list, so the count is
// hand-maintained and verified against source.
export const IAM_CHECK_COUNT = 12;
