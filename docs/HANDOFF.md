# RepoGuard - Handoff Notes

## Active debt (post-2026-05-08 session)

### Bug: Rulesets API in posture detector (HIGH PRIORITY for Bloco J)

`lib/posture.ts` reads only the **classic** branch protection endpoint (`/repos/:owner/:repo/branches/:branch/protection`) and ignores the modern Rulesets API (`/repos/:owner/:repo/rules/branches/:branch`). When a repo uses Rulesets instead of classic protection, multiple Posture signals under-report:

- **Branch protection signal:** stuck at 15/30 even with full Ruleset.
- **Signed commits signal:** stuck at 0/10 even with `Require signed commits` enabled in Ruleset and verified commits in main.

Same root cause = both signals affected. Fixing this single endpoint integration likely pushes self-scan from C (70) to A or A- automatically.

Plan: fix in Bloco J as part of Pro tier readiness. Small, isolated change in `lib/posture.ts` + smoke test update.

### Bug: Status check name match in Ruleset

The Ruleset requires a status check named exactly `Vercel`. If a future PR shows "Required Vercel - Waiting for status to be reported" while Vercel deploy is already green, edit the Ruleset and rename the required check to whatever name actually appears in the PR Checks tab.

### Lint warning (deferred)

`app/dashboard/page.tsx:41` uses `<img>` instead of `next/image`. Refactor requires width/height props and possible layout adjustments. Defer to a UI polish session.

### Postcss CVE remaining

Self-scan still shows 2 Moderate findings (`postcss@8.4.31` and `8.5.9`, GHSA-qx2v-qp2m-jg93). Postcss is a transitive dep via tailwindcss. Not picked up by Dependabot bumps so far. Force update via `npm update postcss` or pin to `>=8.5.10` in `overrides` field of package.json.

### Next-auth v5 beta.31 (PR #5 still open, deliberately not merged)

PR #5 bumps next-auth from beta.30 to beta.31. Auth changes in betas can be silently breaking. Treat as a dedicated session: read full beta.31 changelog, test sign-in flow end-to-end on Vercel preview, only then merge. Never merge auth bumps without explicit testing.

## Recently closed (this session, 2026-05-08)

### Repo credibility pass (H1)

- `SECURITY.md` (private vuln reporting via GitHub Security Advisories)
- `LICENSE` (MIT, 2026 Silvio Gazzoli)
- `CONTRIBUTING.md` (full dev setup + conventional commits)
- `.github/dependabot.yml` (npm + github-actions, weekly Monday 06:00 Europe/Dublin)
- `.github/CODEOWNERS` (default `* @silviooerudon`)
- README badges (license, status, Next.js, TypeScript, live demo) + sections 8 (Posture) and 9 (IAM)
- Branch protection via Ruleset `Protect main` (require PR, status checks, signed commits, restrict deletions, block force pushes, empty bypass)

### GPG signing infrastructure

- Gpg4win 2.5.18 installed via winget
- RSA 4096 key, expires 2028-05-07
- Fingerprint: `25A5E2EC66832BC469EA17CA27423F0D84D68B5F`
- Signing email: `227823977+silviooerudon@users.noreply.github.com`
- Public key registered on GitHub
- Repo-local config: `commit.gpgsign=true`, `tag.gpgsign=true`, `gpg.program=C:\Program Files\GnuPG\bin\gpg.exe`
- Backup at `C:\Users\Silvio\Documents\gpg-backup-repoguard\` -- COPY OFFLINE TO PEN DRIVE + PRIVATE CLOUD
- Revocation cert: `C:\Users\Silvio\AppData\Roaming\gnupg\openpgp-revocs.d\25A5E2EC66832BC469EA17CA27423F0D84D68B5F.rev`

### Suppressions infrastructure (proven via self-scan)

- `.repoguardignore` created with 5 path+rule scoped suppressions
- Suppressed 12 of 14 self-scan findings, all confirmed false positives (detector self-detection of pattern catalog and SAST rule descriptions, plus 1 test fixture)
- Risk score went from 0/100 (Critical) to 90/100 (Excellent)
- Each suppression has `reason` field for audit trail
- Suppressed findings are still listed in UI for transparency

### Security patches (Dependabot batch)

- **PR #3** prod-deps group: next 16.2.3 -> 16.2.6 (closes 7 HIGH + 4 MODERATE + 2 LOW security advisories), supabase-js 2.103 -> 2.105, react/react-dom 19.2.4 -> 19.2.6
- **PR #4** dev-deps group (3 updates)
- **PR #6** eslint 9.39.4 -> 10.3.0 (after lint cleanup PR #11)
- **PR #7** @types/node 20.19.39 -> 25.6.2

### Lint cleanup (PR #11)

- Replaced `any` with `FindingLike` interface in `lib/suppressions.ts` (3 occurrences). Interface uses `string | null` etc to handle nullable fields in `AnyFinding.data`.
- Escaped apostrophe in JSX text in `suppressed-findings-section.tsx`
- Removed unused `severityRank` function from `iam-card.tsx` (supply-chain-card has its own copy that is used)
- Lint state: 0 errors, 1 warning (the `<img>` debt above)

### PR #2 closed without merge

PR #2 was a stale Claude session attempting `repoguard:ignore-file` directive approach. Superseded by `.repoguardignore` (PR #10) which uses path+rule scoping, expiration, and the existing `lib/suppressions.ts` infrastructure.

## Self-scan delta (start vs end of session)

| Metric | Session start | Session end | Delta |
|--------|---------------|-------------|-------|
| Risk score | 0/100 (Critical) | 90/100 (Excellent) | **+90** |
| Total findings | 14 | 2 (postcss only) | -12 |
| Critical findings | 3 | 0 | -3 |
| High findings | 8 | 0 | -8 |
| Posture | F (20) | C (70) | +50 |
| IAM | n/a | 100 (Excellent) | -- |
| Supply Chain | n/a | 100 (Excellent) | -- |
| Branch protection | none | Ruleset Active, no bypass | -- |
| Signed commits | none | RSA 4096 active | -- |
| Eslint version | 9.39.4 | 10.3.0 | major bump |
| Next.js version | 16.2.3 | 16.2.6 | +13 security advisories closed |
| Suppressions infra | unused | proven (12 FPs documented) | -- |

## Process started in parallel (per H1 briefing) - STILL TODO

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

## Next sessions roadmap

- **Bloco I, Sessao I1:** License scan G1 (lib/license.ts, ~150 LOC, smoke test) -- briefing first as `docs/plan-bloco-i1.md`
- **Bloco I, Sessao I2:** Dependency expansion (Maven/Gradle/Go modules) G2
- **Bloco I, Sessao I3:** IaC expansion (Kubernetes, Helm) G3
- **Bloco I, Sessao I4:** Cleanup based on validator feedback
- **Bloco J:** Pro tier readiness. First priority: fix Rulesets API bug in lib/posture.ts. Then unified risk score + scan diffing.
- **Bloco K:** Show HN landing polish + thread/post draft.