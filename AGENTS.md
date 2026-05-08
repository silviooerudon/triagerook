<!-- BEGIN:nextjs-agent-rules -->
# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` before writing any code. Heed deprecation notices.
<!-- END:nextjs-agent-rules -->

---

# RepoGuard — Agent guide

This file is the source of truth for any agent working on RepoGuard. Read it fully before starting work. If a decision below conflicts with a request from Silvio, surface the conflict instead of silently overriding.

## Current phase: pre-distribution

**Status as of 2026-05-01:** RepoGuard is live but not yet distributed. Active users in the last 30 days: **1 (Silvio himself)**. Baseline numbers are frozen in [`docs/baseline-metrics.md`](docs/baseline-metrics.md); manual analytics queries live in [`docs/analytics-queries.md`](docs/analytics-queries.md).

**The current focus is distribution and acquisition, NOT monetization.**

**Implications for agents:**

- **Do NOT propose, design, or implement** any billing, paywall, Stripe, subscription, usage-gating, plan-tiering, or pricing-page work without first re-reading this section and the thresholds in `docs/baseline-metrics.md`.
- The billing approach has already been designed and **explicitly parked** until user count crosses the thresholds documented in `docs/baseline-metrics.md`. Re-opening that work without crossing the threshold is wasted effort the user has pre-rejected.
- "Free tier" / "Pro tier" / "$9/mo" copy and limits are pre-decided but **not to be shipped yet**. Do not pre-bake UI for them.
- Work that IS in scope right now: distribution-supporting features (better landing page, shareable scan results, Show HN-readiness, SARIF export, GitHub Code Scanning integration, public-repo scan UX polish), product depth (more detectors, better findings UX), and observability (extending the manual queries in `docs/analytics-queries.md`).
- If Silvio asks for billing work, reply by surfacing this section and asking him to confirm the threshold has been crossed. Do not silently proceed.

**Exit criteria for this phase:** ≥10 distinct users with ≥1 scan in the trailing 30 days, measured via the queries in `docs/analytics-queries.md`. When that holds, this section gets updated and billing work resumes per the parked plan.

## What this project is

RepoGuard is a **micro-SaaS** GitHub security scanner targeted at solo devs and small teams who skip security tooling because Snyk/GitGuardian price them out. Built in public. Live at https://repoguard-chi.vercel.app. See `README.md` for the full product description and detector list.

**Business model context:** This is a **side income project**. Silvio's day job is SailPoint IAM at Euronext. Decisions should favor:
- Low operational cost (free tiers when possible)
- Low ongoing maintenance burden (Silvio works on this nights/weekends)
- Realistic monetization path (free tier + paid tier with public-facing limits)
- Shipping over perfecting

## Author / collaboration context

You're working with **Silvio Gazzoli** — senior IAM/IGA professional, ~10 years experience, Brazilian based in Dublin. He is **technical but not a career developer**: comfortable reading and debugging code, less so writing complex code from scratch. He prefers:

- Direct, pragmatic communication in **Brazilian Portuguese (informal)** for chat
- English for code comments, commit messages, docs, and product copy
- You doing the heavy lifting on implementation, him doing review and product/strategy decisions
- Concrete recommendations over open-ended options

## Tech stack (locked in — don't propose alternatives without strong reason)

- **Framework:** Next.js 16 (App Router) + TypeScript + Tailwind
- **Auth:** NextAuth v5 with GitHub OAuth (`public_repo` scope)
- **Database:** Supabase (Postgres + JSONB), EU region
- **Hosting:** Vercel
- **External APIs:** GitHub REST v3, npm audit bulk API, OSV.dev batch API

### Next.js 16 specifics already resolved (don't re-debug these)

- Middleware was renamed to **`proxy`** in Next 16 — use `proxy.ts`, not `middleware.ts`
- Route handler `params` are **async** — `await params` before destructuring
- PowerShell + npx has quirks; prefer direct `npm run` scripts over `npx` invocations when possible

## Architectural decisions already made

These are **decided**. Do not re-litigate without explicit request from Silvio.

### Privacy & data

- **Never store:** source code, GitHub access tokens (use only at scan time), full secret values
- **Store only:** scan metadata (owner/repo, timestamp, counts), findings (paths, line numbers, pattern IDs, masked previews)
- All data in Supabase EU region — GDPR is a feature, not a chore

### Detection strategy

- 9 detectors run in parallel (see `README.md` for the full list)
- Bias toward **high-confidence regex** for secrets — false positives erode trust faster than false negatives
- Entropy fallback for `.env`/config files where regex can't help
- SAST rules are **conservative** and tied to CWE identifiers — actionable findings only
- Git history scan limited to **30 recent commits** (rate limit + cost balance)

### UX principles

- One-click scanning — no CLI, no config files, no pipelines
- Findings are **prioritized**, not dumped — severity sort, dedup, masked previews
- Sign in with GitHub OR paste a public URL — never require both
- Time to first result < 1 minute on a typical repo

## Code conventions

- **TypeScript strict mode** — no `any` unless explicitly justified in a comment
- **Server Components by default** — only use `"use client"` when interactivity actually requires it
- **No new external dependencies without checking bundle impact** — this is a Vercel free-tier project, payload matters
- **Error handling:** never silently swallow GitHub/Supabase errors — log and surface them, even if degraded UX
- **Naming:** detectors live in `lib/detectors/<name>.ts` and export a function returning `Finding[]`

## Working style — when to act, when to consult, when to ask

This is the most important section. The goal is to **minimize Silvio acting as a messenger** between agents and chat-Claude.

### Just do it (don't ask)

- Bug fixes and syntax errors
- TypeScript type fixes
- Refactoring within an existing file with no behavior change
- Adding a new detector pattern that follows the existing structure in `lib/detectors/`
- Updating dependencies for security patches
- Any change explicitly requested by Silvio with no ambiguity
- Stylistic/CSS choices when no specific design was given

### Decide and document

For decisions inside the existing architecture, **decide based on this guide + README**, then briefly note your choice in the response (one line: "I went with X because Y"). Examples:

- Choosing between two equivalent libraries for the same task → pick the one already used or with smaller bundle
- Naming a new detector → follow the convention in `lib/detectors/`
- Choosing where to put a new utility → mirror existing patterns

### Ask Silvio (in the chat where you were invoked)

Only escalate to Silvio when:

- The decision affects **product positioning or pricing** (free vs paid tier boundaries, what to monetize)
- The decision affects **roadmap order** (next priority among multiple roadmap items)
- A new external service/dependency would add ongoing cost or maintenance burden
- A change requires a destructive migration of existing scans/users
- Two reasonable paths exist with substantively different long-term implications

When asking, give Silvio a **recommendation + tradeoff**, not an open question. Bad: "Stripe Checkout or Payment Links?". Good: "Recommend Stripe Checkout because faster setup and we don't need PaymentLinks' flexibility yet — only downside is less control over the checkout UI. Confirm?"

### Use HANDOFF.md for cross-session strategy

If Silvio brings a strategic question that needs deep thinking and the chat agent (this Claude Code session) isn't the right fit, write the question into `HANDOFF.md` in a structured format (template at the bottom of that file) and tell Silvio: "Coloquei a pergunta no HANDOFF.md, cola lá no chat advisor pra responder." This way Silvio is a dumb relay, not a translator.

## Things Silvio will likely ask you to build (be ready)

These are on the radar — when one comes up, you'll have context:

- **Billing / paid tier** — Stripe, public pricing limits, free tier with N scans/month
- **Go and Ruby dependency scanning** — extend the dependency detector
- **Terraform + CloudFormation IaC rules** — extend detector #7
- **SARIF export + GitHub Code Scanning integration** — common B2B ask
- **Continuous scanning via webhooks** — requires migrating from OAuth App to GitHub App
- **Team accounts** — multi-tenant, shared scan history
- **Ignore rules / suppressions** — per-finding, per-repo

## Anti-goals (what RepoGuard is NOT)

- Not an enterprise SAST tool — don't propose features that compete with Semgrep Enterprise
- Not a CI plugin — the value prop is "no pipeline to wire up", don't undermine it
- Not a code review tool — findings are security-only, not style/quality
- Not a paid pentest — false positives are tolerated only if they're rare and recognizable

---

## When this file is wrong

If something here is outdated or contradicts what Silvio just said, **trust Silvio + ask him to confirm the update**, then update this file in the same change. Stale guidance is worse than no guidance.
