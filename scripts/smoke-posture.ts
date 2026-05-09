import { assessPosture, type PostureResult } from "../lib/posture"

function summarize(label: string, r: PostureResult): void {
  console.log(`\n--- ${label} ---`)
  console.log(`Score:    ${r.score}/100  Grade: ${r.grade}  Degraded: ${r.degraded}`)
  for (const cat of r.breakdown) {
    console.log(`  [${cat.id}] ${cat.pointsEarned}/${cat.pointsMax}  ${cat.label}`)
    for (const sig of cat.signals) {
      const flag = sig.unknown ? "?" : sig.satisfied ? "+" : "-"
      console.log(`    ${flag} ${sig.id} (${sig.pointsEarned}/${sig.pointsMax})`)
    }
  }
  if (r.bypassFindings.length > 0) {
    console.log(`  Bypass findings: ${r.bypassFindings.length}`)
    for (const f of r.bypassFindings) {
      console.log(`    [${f.severity}] ${f.ruleId}: ${f.description}`)
    }
  } else {
    console.log(`  Bypass findings: 0`)
  }
  if (r.quickWins.length > 0) {
    console.log(`  Quick wins:`)
    for (const qw of r.quickWins) {
      console.log(`    -> ${qw.label}`)
    }
  }
}

function findSignal(r: PostureResult, id: string) {
  for (const cat of r.breakdown) {
    for (const sig of cat.signals) {
      if (sig.id === id) return sig
    }
  }
  return null
}

async function run(label: string, owner: string, repo: string, token: string | null) {
  console.log(`\n=== ${label} (${owner}/${repo}) ===`)
  try {
    const r = await assessPosture(owner, repo, token)
    summarize(label, r)
    return r
  } catch (err) {
    console.error("FAILED:", err)
    process.exitCode = 1
    return null
  }
}

async function main() {
  const token = process.env.GITHUB_TOKEN ?? null
  if (!token) {
    console.warn("[warn] GITHUB_TOKEN not set; first scan will run anonymously and may hit rate limits.")
  }

  // Self-scan: this repo uses a Ruleset to protect main. Pre-Bloco-J the
  // branch-protection signal returned satisfied=false because the classic
  // /branches endpoint reports protected=true while the /protection endpoint
  // 404s on Ruleset-only repos. Post-fix we expect satisfied=true.
  const self = await run("self (with token)", "silviooerudon", "repoguard", token)

  // Public reference repo with no protection at all - sanity baseline.
  await run("baseline (no token, no protection)", "octocat", "Hello-World", null)

  // Regression gate: the Bloco J fix is meaningless if self-scan branch
  // protection still misses. Fail loudly so CI/manual run flags it.
  if (self) {
    const bp = findSignal(self, "branch-protection")
    if (!bp || !bp.satisfied) {
      console.error("\nREGRESSION: branch-protection signal not satisfied on self-scan; Bloco J Ruleset path broken.")
      process.exitCode = 1
    } else {
      console.log("\n[gate] branch-protection signal satisfied via Ruleset path -> OK")
    }
  }
}

main().catch((e) => { console.error(e); process.exit(1) })
