# RepoGuard - Handoff Notes

## Active debt (post-2026-05-09 session)

### mfa-org signal returns unknown (5pts)

Posture self-scan now shows `mfa-org` signal as `unknown` (returns 0/5 pts). The `assessPosture` flow calls `fetchMfaState` which requires `read:org` scope and reads `two_factor_requirement_enabled` on the org. When token lacks scope or repo is user-owned, falls back to `unknown`. silviooerudon is a user account (not org), so this is structurally `na-user-repo` rather than enforced/not-enforced. Currently both states map to `unknown=true` in computeScore.

Fix: split the two cases. `na-user-repo` should be treated as full credit (5/5) since there is no org-level MFA to enforce - personal repos shouldn't be penalized for lacking an org-level concept. `unknown` (org with missing scope) stays as 0 and stays out of quick wins. Small surgical patch in `lib/posture.ts` computeScore section. Pushes self-scan from A(95) to A(100).

### Bug: Status check name match in Ruleset

The Ruleset requires a status check named exactly `Vercel`. If a future PR shows "Required Vercel - Waiting for status to be reported" while Vercel deploy is already green, edit the Ruleset and rename the required check to whatever name actually appears in the PR Checks tab.

### Lint warning (deferred)

`app/dashboard/page.tsx:41` uses `<img>` instead of `next/image`. Refactor requires width/height props and possible layout adjustments. Defer to a UI polish session.

### Postcss CVE remaining

Self-scan still shows 2 Moderate findings (`postcss@8.4.31` and `8.5.9`, GHSA-qx2v-qp2m-jg93). Postcss is a transitive dep via tailwindcss. Not picked up by Dependabot bumps so far. Force update via `npm update postcss` or pin to `>=8.5.10` in `overrides` field of package.json.

### Next-auth v5 beta.31 (PR #5 still open, deliberately not merged)

PR #5 bumps next-auth from beta.30 to beta.31. Auth changes in betas can be silently breaking. Treat as a dedicated session: read full beta.31 changelog, test sign-in flow end-to-end on Vercel preview, only then merge. Never merge auth bumps without explicit testing.

## Recently closed (this session, 2026-05-09)

### Bloco J - Rulesets API in posture detector (PR #13)

Fixed the under-reporting bug from the previous handoff. Self-scan went **C(70) -> A(95)** in a single PR.

Changes:
- New `lib/posture-rulesets.ts` reads `/repos/.../rules/branches/{branch}` and per-ruleset details from `/repos/.../rulesets/{id}` (or `/orgs/.../rulesets/{id}` for org-level).
- `lib/posture.ts` unions classic + ruleset signals per-signal: `branch-protection`, `branch-pr-required`, `branch-status-checks`, `branch-enforce-admins` (via `noBypassActors`), and `signed-commits` (ruleset config trumps behaviour ratio).
- `lib/types.ts` adds `RulesetBypassFinding` matching existing detector finding shape.
- `scripts/smoke-posture.ts` extended with per-signal print + regression gate that fails exit code if self-scan branch-protection signal not satisfied.

Decisions baked in:
1. Union per signal (either source satisfies counts).
2. Active rules with non-empty bypass actors still count as satisfied; bypass surfaces as low-severity informational finding.
3. Only `enforcement: "active"` counts; `evaluate` is dry-run.

Out of scope (deferred):
- Enterprise rulesets (GHEC-only path skipped).
- Real-fixture smoke for org-level rulesets (currently hits live API only).

6 GPG-signed commits preserved via "Create a merge commit" merge strategy.

## Self-scan delta (start vs end of session)

| Metric | Session start (b634d33) | Session end (c79dd69) | Delta |
|--------|-------------------------|------------------------|-------|
| Risk score | 90/100 (Excellent) | 90/100 (Excellent) | unchanged |
| Posture | C (70) | **A (95)** | **+25** |
| Branch protection | 15/30 | 30/30 | +15 |
| - branch-protection | unsatisfied | satisfied (Ruleset path) | -- |
| - branch-pr-required | 0/5 | 5/5 | +5 |
| - branch-status-checks | 0/5 | 5/5 | +5 |
| - branch-enforce-admins | 0/5 | 5/5 | +5 |
| Signed commits | 0/10 | 10/10 | +10 |
| Bypass findings | n/a | 0 | -- |
| IAM | 100 | 100 | unchanged |
| Supply Chain | 100 | 100 | unchanged |
| mfa-org | unknown | unknown | unchanged (separate fix) |

## Process started in parallel - STILL TODO

Validators recruitment NOT YET STARTED. Required for Bloco I to deliver useful output.

Outreach plan:
- 3 close friends (DM/whatever)
- 5 friends-of-friends (LinkedIn / network)
- 3 strangers (Discord dev communities, r/devops, r/programming, indie hackers)

Validation script:
- "Run repoguard on 1-2 of your public repos."
- Request 2-3 min screen recording or short call
- 5 fixed post-use questions (see plan-h1.md)

Threshold for I4 fixes: only fix what surfaces in 3+ independent feedbacks.

Collection in `docs/feedback-validacao.md` (private, do not commit if real names appear).

GPG key offline backup STILL NOT DONE. Backup files remain at `C:\Users\Silvio\Documents\gpg-backup-repoguard\`. Move to USB pen drive + private cloud.

Show HN evidence screenshots STILL TODO. Now is a good moment - new self-scan A(95) is the strongest visual yet (full breakdown with ruleset signals all green).

## Next sessions roadmap

- **mfa-org fix (small):** split `na-user-repo` from `unknown` in computeScore. ~30 min. Pushes self-scan to A(100). Good warmup session.
- **Bloco I, Sessao I1:** License scan G1 (lib/license.ts, ~150 LOC, smoke test) -- briefing first as `docs/plan-bloco-i1.md`
- **Bloco I, Sessao I2:** Dependency expansion (Maven/Gradle/Go modules) G2
- **Bloco I, Sessao I3:** IaC expansion (Kubernetes, Helm) G3
- **Bloco I, Sessao I4:** Cleanup based on validator feedback
- **Bloco J restante:** unified risk score (consolida findings em score por categoria) + scan-to-scan diffing ("new since last scan") + pricing section unhide.
- **Bloco K:** Show HN landing polish + thread/post draft.
