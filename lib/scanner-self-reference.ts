// Heuristics that recognise when a regex match is the literal that
// DEFINES the detector itself — not real exploit material. Without
// this, RepoGuard scanning RepoGuard (and any other project with
// regex literals or property-style rule definitions) flags its own
// rule library as critical findings.
//
// Two complementary checks, both intentionally conservative:
//
//   1. The match is inside a JS regex literal — `/.../flags` on the
//      same line, with the match between the two delimiters.
//   2. The match is preceded on the same line by a property marker
//      like `regex:`, `pattern:`, `matcher:`, `test:`, or `rule:` —
//      the shape every detector definition uses.
//
// Bias is hard toward false negatives. A false negative here is a
// noisy finding the user can suppress in one click. A false positive
// (silently skipping a real exploit because the line happens to look
// like detector code) would be a security regression. So both
// helpers err on the side of NOT skipping.
//
// What this does NOT cover: prose in markdown describing a pattern,
// product copy on the landing page describing what the SAST detector
// looks for, etc. Those are best handled with `.repoguardignore`
// because there's no robust syntactic signal to distinguish "FAQ
// answer mentioning `rejectUnauthorized: false`" from real code
// that disables TLS verification.

const DETECTOR_DEFINITION_MARKER = /\b(?:regex|pattern|matcher|test|rule)\s*:\s*/i

/**
 * Returns true if `matchOffset` appears to sit inside a JS regex
 * literal `/.../` on the same line. Walks back for the nearest
 * unescaped `/` and forward for the nearest unescaped `/`.
 *
 * Rejects when either delimiter is preceded by `\` (escaped slash)
 * or when the candidate left delimiter is actually the start of a
 * `//` or `/*` comment.
 */
export function isInsideRegexLiteral(
  line: string,
  matchOffset: number,
): boolean {
  // Walk back for the nearest non-escaped '/'
  let left = -1
  for (let i = matchOffset - 1; i >= 0; i--) {
    if (line[i] !== "/") continue
    if (i > 0 && line[i - 1] === "\\") continue
    // Not a regex literal if this slash starts a comment
    if (line[i + 1] === "/") return false
    if (line[i + 1] === "*") return false
    left = i
    break
  }
  if (left === -1) return false

  // Walk forward for the nearest non-escaped '/'
  let right = -1
  for (let i = matchOffset + 1; i < line.length; i++) {
    if (line[i] !== "/") continue
    if (line[i - 1] === "\\") continue
    right = i
    break
  }
  if (right === -1) return false

  return true
}

/**
 * Returns true if the line declares a detector pattern via a
 * property assignment shape (`regex: /.../`, `pattern: "..."`, etc.)
 * and the match sits AFTER that marker on the same line.
 */
export function isLikelyDetectorDefinition(
  line: string,
  matchOffset: number,
): boolean {
  const before = line.slice(0, matchOffset)
  return DETECTOR_DEFINITION_MARKER.test(before)
}

/**
 * Combined check. `line` is the SINGLE line containing the match;
 * `matchOffset` is the 0-indexed character position of the match
 * within that line.
 *
 * Callers that work over multi-line content (the file scanner) must
 * convert their global match index to a per-line offset before
 * calling this helper.
 */
export function isLikelyScannerSelfReference(
  line: string,
  matchOffset: number,
): boolean {
  return (
    isInsideRegexLiteral(line, matchOffset) ||
    isLikelyDetectorDefinition(line, matchOffset)
  )
}
