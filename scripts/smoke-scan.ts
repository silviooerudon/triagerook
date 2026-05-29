// scripts/smoke-scan.ts
// End-to-end smoke test for the full scan pipeline against a real public repo.
// Exercises GitHub API → every detector → flatten → risk → attack graph,
// without needing the UI / Supabase / OAuth.
//
// Run: GH_SCAN_TOKEN=$(gh auth token) npx tsx scripts/smoke-scan.ts <owner> <repo>

import { runFullScan } from "../lib/scan-pipeline"
import type { AnyFinding } from "../lib/risk"

const [owner, repo] = process.argv.slice(2)
const token = process.env.GH_SCAN_TOKEN ?? null

if (!owner || !repo) {
  console.error("usage: npx tsx scripts/smoke-scan.ts <owner> <repo>")
  process.exit(1)
}

function countKind(findings: AnyFinding[], kind: string): number {
  return findings.filter((f) => f.kind === kind).length
}

async function main() {
  console.log(`\n=== scanning ${owner}/${repo} ===`)
  const t0 = Date.now()
  const { fullResult, assessment } = await runFullScan(token, owner, repo)
  const ms = Date.now() - t0
  const p = assessment.prioritized

  console.log(`health ${100 - assessment.score}/100 · ${fullResult.filesScanned} files · ${(ms / 1000).toFixed(1)}s\n`)

  console.log("findings by kind:")
  console.log("  secret      ", countKind(p, "secret"))
  console.log("  code/SAST   ", countKind(p, "code"), "(includes framework-aware rules)")
  console.log("  dependency  ", countKind(p, "dependency"))
  console.log("  license     ", countKind(p, "license"))
  console.log("  sensitive   ", countKind(p, "sensitive-file"))
  console.log("  iac         ", fullResult.iacFindings?.length ?? 0)

  // Per-category IaC breakdown — this is where terraform / kubernetes /
  // iam-policy / dockerfile / github-actions show up.
  const iacByCat = new Map<string, number>()
  for (const f of fullResult.iacFindings ?? []) {
    iacByCat.set(f.category, (iacByCat.get(f.category) ?? 0) + 1)
  }
  if (iacByCat.size) {
    console.log("  iac by category:", Object.fromEntries(iacByCat))
  }

  // Framework-aware SAST rules carry ids like "django-debug-true".
  const fwRules = p
    .filter((f) => f.kind === "code")
    .map((f) => (f.data as { ruleId: string }).ruleId)
    .filter((id) => /^(django|flask|fastapi|express|nestjs|spring|laravel|rails)-/.test(id))
  if (fwRules.length) console.log("  framework rules hit:", [...new Set(fwRules)])

  // License risk classes.
  const licByRisk = new Map<string, number>()
  for (const f of p) {
    if (f.kind === "license") {
      const r = (f.data as { risk: string }).risk
      licByRisk.set(r, (licByRisk.get(r) ?? 0) + 1)
    }
  }
  if (licByRisk.size) console.log("  license by risk:", Object.fromEntries(licByRisk))

  // Attack graph.
  const paths = fullResult.attackGraph?.paths ?? []
  console.log(`\nattack paths: ${paths.length}`)
  for (const path of paths.slice(0, 5)) {
    console.log(`  [${path.severity}] ${path.title}`)
    for (const step of path.steps) console.log(`      → ${step}`)
  }
}

main().catch((err) => {
  console.error("SCAN FAILED:", err instanceof Error ? err.message : err)
  process.exit(1)
})
