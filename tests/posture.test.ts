import { describe, it, expect } from "vitest"
import { computeScore } from "@/lib/posture"

// A repo that satisfies every assessable signal. Branch protection + ruleset
// left as a fully-protected classic config so all sub-signals resolve.
function perfectRaw() {
  return {
    branchProtected: true,
    branchProtectionDetails: {
      prRequired: true,
      statusChecksRequired: true,
      enforceAdmins: true,
    },
    hasSecurityMd: true,
    hasLicense: true,
    hasCodeowners: true,
    readmeContent: "x".repeat(600) + " security SECURITY.md",
    hasDependabotOrRenovate: true,
    hasLockfile: true,
    gitignoreContent: "node_modules\n.env\n",
    signedCommitsRatio: 1,
    mfaState: "enforced" as const,
    secretScanning: "enabled" as const,
    workflowPerms: "read" as const,
    releaseProvenance: "present" as const,
    rulesetSignals: null,
    degraded: false,
  }
}

describe("posture computeScore — new signals", () => {
  it("a fully-configured repo scores 100 / grade A", () => {
    const r = computeScore(perfectRaw())
    expect(r.score).toBe(100)
    expect(r.grade).toBe("A")
  })

  it("includes the three new governance signals", () => {
    const gov = computeScore(perfectRaw()).breakdown.find((c) => c.id === "governance")!
    const ids = gov.signals.map((s) => s.id)
    expect(ids).toContain("secret-scanning")
    expect(ids).toContain("workflow-permissions")
    expect(ids).toContain("release-provenance")
  })

  it("unknown admin-only signals do NOT penalize the score (excluded from denominator)", () => {
    const raw = perfectRaw()
    raw.secretScanning = "unknown"
    raw.workflowPerms = "unknown"
    raw.releaseProvenance = "unknown"
    const r = computeScore(raw)
    // Everything else is perfect, so percent-of-assessable stays 100.
    expect(r.score).toBe(100)
  })

  it("a disabled signal lowers the score and surfaces a quick win", () => {
    const raw = perfectRaw()
    raw.secretScanning = "disabled"
    const r = computeScore(raw)
    expect(r.score).toBeLessThan(100)
    expect(r.quickWins.map((q) => q.signalId)).toContain("secret-scanning")
  })

  it("write-default workflow permissions is a quick win; read is not", () => {
    const raw = perfectRaw()
    raw.workflowPerms = "write"
    const wins = computeScore(raw).quickWins.map((q) => q.signalId)
    expect(wins).toContain("workflow-permissions")

    raw.workflowPerms = "read"
    expect(computeScore(raw).quickWins.map((q) => q.signalId)).not.toContain(
      "workflow-permissions",
    )
  })

  it("release provenance absent is a quick win; unknown is not", () => {
    const raw = perfectRaw()
    raw.releaseProvenance = "absent"
    expect(computeScore(raw).quickWins.map((q) => q.signalId)).toContain("release-provenance")

    raw.releaseProvenance = "unknown"
    expect(computeScore(raw).quickWins.map((q) => q.signalId)).not.toContain(
      "release-provenance",
    )
  })
})
