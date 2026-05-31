import type { IaCFinding } from "@/lib/types"

// Auto-fix engine for the `gha-permissions-write-all` finding: replace a
// blanket `permissions: write-all` with the least-privilege default
// `permissions:\n  contents: read`. Indentation of the original line is
// preserved so the block stays valid whether it was top-level or job-level.
//
// Pure text transform — no network. `contents: read` is the secure default;
// workflows that genuinely need a write scope will surface it in review and
// the author adds the specific grant.

export type GhaPermissionsInput = {
  finding: IaCFinding
  fileContent: string
}

export type GhaPermissionsResult = {
  patches: { path: string; content: string }[]
}

const WRITE_ALL = /^(\s*)permissions\s*:\s*write-all\s*$/i

export function applyGhaPermissionsFix(
  input: GhaPermissionsInput,
): GhaPermissionsResult {
  const lines = input.fileContent.split("\n")
  let idx = input.finding.lineNumber ? input.finding.lineNumber - 1 : -1
  if (!WRITE_ALL.test(lines[idx] ?? "")) {
    idx = lines.findIndex((l) => WRITE_ALL.test(l))
  }
  if (idx < 0) {
    throw new Error("gha-permissions-fix: no `permissions: write-all` line found")
  }
  const indent = lines[idx].match(/^(\s*)/)![1]
  lines.splice(idx, 1, `${indent}permissions:`, `${indent}  contents: read`)
  return {
    patches: [{ path: input.finding.filePath, content: lines.join("\n") }],
  }
}
