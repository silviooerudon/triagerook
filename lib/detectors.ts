// Single source of truth for the canonical set of TriageRook detectors:
// their count, order, and identity. The marketing landing page
// (app/page.tsx) and the /docs/detectors reference page each render their own
// presentation-specific copy, but both key that copy off DETECTOR_SLUGS via a
// Record<DetectorSlug, …>. That makes the TypeScript compiler enforce that
// every surface covers exactly these eleven detectors, in this order — add,
// remove, or rename one here and both pages fail to type-check until they're
// updated in lockstep. README + STAT_BAR cite DETECTOR_COUNT-as-prose
// ("eleven"); keep them in sync by hand (there's a test guarding the count).
export const DETECTOR_SLUGS = [
  "secret-scanner",
  "sensitive-files",
  "entropy",
  "git-history",
  "code-sast",
  "deps",
  "supply-chain",
  "ci-iac",
  "posture",
  "iam-risk",
  "license",
] as const

export type DetectorSlug = (typeof DETECTOR_SLUGS)[number]

export const DETECTOR_COUNT = DETECTOR_SLUGS.length
