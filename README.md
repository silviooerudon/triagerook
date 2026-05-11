# RepoGuard

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg) ![Status: Beta](https://img.shields.io/badge/status-beta-orange.svg) ![Next.js 16](https://img.shields.io/badge/Next.js-16-black?logo=nextdotjs) ![TypeScript 5](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript) ![Live](https://img.shields.io/website?url=https%3A%2F%2Frepoguard-chi.vercel.app&label=live%20demo)

> Lightweight GitHub security scanner for solo devs and small teams. Live at **[repoguard-chi.vercel.app](https://repoguard-chi.vercel.app)**.

Scans your GitHub repos across nine detectors in parallel — secrets, sensitive files, code-level vulnerabilities, npm and PyPI dependencies, supply-chain misconfigurations, and git history — with no CLI, no config, and no pipelines to wire up. Sign in with GitHub or paste a public URL, then get a prioritized list of findings in under a minute.

## Why I built this

I've spent 10+ years in Identity & Access Management — the field that exists because credentials leak and people get owned. Tools like Snyk and GitGuardian are great, but priced for teams with security budgets. Solo devs and tiny startups skip security scanning entirely because the bar to entry is too high.

RepoGuard is my attempt at the smallest useful security tool: scan a repo in one click, see what's wrong, fix it. Built in public.

## What RepoGuard actually detects

RepoGuard runs nine independent detectors over your repo and aggregates the results into a single prioritized report.

### 1. Secrets in source code (60+ patterns)

High-confidence regex detection for modern token formats across cloud providers, SCM platforms, AI APIs, payments, communications, monitoring, and developer tooling — AWS/Azure/GCP/DigitalOcean/Cloudflare/Vercel/Netlify/Fly/Render; GitHub (classic, fine-grained, OAuth, App tokens), GitLab, Bitbucket; Anthropic, OpenAI (current + legacy), Hugging Face, Replicate, Groq, Perplexity; Stripe, Braintree, Square, Shopify, Adyen; Slack, Discord, Telegram, SendGrid, Mailgun, Twilio; Datadog, New Relic, Sentry, PagerDuty, Algolia; npm/PyPI/Docker Hub/JFrog tokens; HashiCorp Vault, Terraform Cloud; and generic formats like `-----BEGIN PRIVATE KEY-----`, `_authToken=` in `.npmrc`, HTTP Basic-Auth URLs, Supabase `service_role` JWTs.

### 2. Sensitive files committed to the repo

Filename-based detection that flags files which are never safe to commit regardless of their contents: `*.pem`, `*.key`, `*.pfx/.p12/.jks/.keystore`, `id_rsa`/`id_ed25519`/`id_ecdsa`, `.kdbx` (KeePass), `.env.production`, `.aws/credentials`, GCP service-account JSONs, kubeconfig, `.docker/config.json`, `.npmrc` with auth, `terraform.tfstate`, database dumps, `.git-credentials`, `.htpasswd`, `.pgpass`. Each finding ships with a concrete remediation step.

### 3. High-entropy secrets in `.env` / config files

When a regex can't help, entropy analysis can. RepoGuard parses `.env`, `.envrc`, `.ini`, `.toml`, `.properties`, `.yaml`, and `.conf` files line-by-line, extracts `KEY=VALUE` pairs, discards placeholders (`xxx`, `changeme`, URLs, semver, IPs), and flags values with Shannon entropy ≥ 4.0 bits/char whose key names match `password|secret|api_key|access_key|auth_token|client_secret|…`. Catches custom corporate tokens that dedicated regexes miss.

### 4. Secrets in recent git history

Even a rotated secret is still a compromised secret if it lives in a past commit. RepoGuard fetches up to 30 recent commits via the GitHub API, extracts added patch lines, and re-runs the full 60+ pattern library over them. Findings are deduplicated against the current tree so only history-exclusive matches surface, tagged with commit SHA + author + date.

### 5. Code-level vulnerabilities (SAST)

Conservative pattern rules over your JavaScript/TypeScript and Python code, each tied to a CWE identifier so findings are actionable:

- **SSRF (CWE-918)** — `fetch`/`axios`/`requests`/`httpx`/`urllib` called with `req.body`/`req.params`/`request.args`
- **SQL injection (CWE-89)** — string concatenation and template-literal/f-string interpolation inside `query`/`execute`/`raw`
- **Command injection (CWE-78)** — `child_process.exec`, `subprocess(shell=True)`, `os.system` with user data
- **XSS (CWE-79)** — `innerHTML`, `dangerouslySetInnerHTML`, `document.write` with non-constant values
- **Dynamic code execution (CWE-95)** — `eval`, `new Function`, Python `eval`/`exec`
- **Path traversal (CWE-22)** — `fs.readFile`/`open()` fed with request-derived paths
- **Weak crypto (CWE-327/338)** — MD5/SHA1 for passwords or tokens, `Math.random()`/`random.*` for session IDs, nonces, OTPs
- **JWT misuse (CWE-347)** — `jwt.verify(..., algorithms: ['none'])`, `jwt.decode` used where `verify` was meant
- **Insecure deserialization (CWE-502)** — `pickle.loads`, `yaml.load` without `SafeLoader`
- **CORS misconfiguration (CWE-942)** — wildcard origin combined with `credentials: true`
- **Open redirect (CWE-601)** — `res.redirect` with request-derived URL
- **TLS verification disabled (CWE-295)** — `rejectUnauthorized: false` in JS, `verify=False` in Python `requests`/`httpx`
- **Insecure cookies (CWE-1004 / CWE-614)** — auth/session cookies with `httpOnly: false` or `secure: false`
- **Weak bcrypt cost (CWE-916)** — `bcrypt.hash(..., N)` with N below 10
- **Hardcoded credentials (CWE-798)** — `process.env.X || "sk-…"` style fallbacks where the literal is a real-shaped credential
- **Client-side secret exposure (CWE-200)** — `NEXT_PUBLIC_*SECRET*` / `*SERVICE_ROLE*` env reads (Next.js inlines these into the client bundle)

The last five catch patterns AI coding assistants commonly generate when scaffolding auth, HTTP clients, or Next.js apps.

### 6. Vulnerable dependencies (npm and PyPI)

- **npm** — prefers `package-lock.json` to cover the entire dependency tree (direct + transitive), supports lockfile v1, v2, and v3. Queries the npm advisory bulk API and links each finding to its GHSA + CVSS score.
- **PyPI** — parses `requirements.txt`, `pyproject.toml` (PEP-621 + Poetry), and `Pipfile`. Queries the [OSV.dev](https://osv.dev) batch API and hydrates each vulnerability with severity, affected ranges, and GHSA link.

### 7. CI / IaC / supply-chain misconfigurations

- **Dockerfile** — container running as root, missing `USER` directive, `:latest` base tags, `ADD http(s)://`, secrets baked into `ENV`, `RUN curl | sh`, `chmod 777`, unpinned `apt install`
- **GitHub Actions** — `pull_request_target` checking out PR head with secrets exposed (the s1ngularity / GhostAction vector), third-party actions not pinned to a full SHA, `run:` steps interpolating `${{ github.event.* }}` fields (script injection), workflow-level `permissions: write-all`
- **Lifecycle hook abuse (npm + PyPI)** -- `package.json` scripts (`preinstall`/`install`/`postinstall`/`prepare`) and Python `setup.py`/`pyproject.toml` build hooks running `curl | sh`, `base64` decode-and-execute, environment-variable exfiltration combined with network calls, or destructive `rm -rf` chains. Catches install-time supply-chain vectors used in recent npm and PyPI compromises.
- **Typosquatting in dependency manifests** -- flags packages whose names are edit-distance-1 (`lodahs`, `expres`, `reqests`), edit-distance-2 prefix (`lodashes`), or case-fold variants (`Chalk`) of popular npm and PyPI registry names.

### 8. Repository posture score

Beyond looking for specific findings, RepoGuard grades how the repo is set up: governance docs (`SECURITY.md`, `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`), branch protection rules on the default branch, vulnerability-alert configuration, dependency-update automation, and other operational hygiene signals. The result is a single A+ to F grade with a per-signal breakdown showing exactly what to fix to raise it. Signals the OAuth token cannot inspect (e.g. branch protection without admin permission) are reported as `unknown` rather than as failures, so the grade stays honest.

### 9. IAM risk scanner

The angle a 10+ year IAM/IGA specialist actually cares about: identity and access risk at org and repo level. RepoGuard surfaces org-level MFA enforcement (when `read:org` scope is granted), outside-collaborator permission levels, repo-level secret scoping, and authorship patterns that signal stale ownership. When a signal requires permissions the token does not have, RepoGuard skips it and labels it as such rather than guessing. This is the slice of enterprise IAM tooling that solo devs and small teams have historically had no access to.

## Privacy

We **never** store:
- Your source code
- Your GitHub access token (only used at scan time, never persisted)
- Full secret values (only the type, file path, line number, and a masked preview)

We **do** store: scan metadata (owner/repo, timestamp, counts) and findings (file paths + line numbers + pattern IDs + masked previews) so you can review history.

Data lives in Supabase (EU region) and Vercel. You can revoke access anytime via your [GitHub settings](https://github.com/settings/applications). Full details on the [security page](https://repoguard-chi.vercel.app/security).

## Tech stack

- **Framework:** Next.js 16 (App Router) + TypeScript + Tailwind
- **Auth:** NextAuth v5 (GitHub OAuth, `public_repo` scope)
- **Database:** Supabase (Postgres + JSONB)
- **Hosting:** Vercel
- **APIs:** GitHub REST v3, npm audit bulk, OSV.dev

## Run locally

Prereqs: Node 20+, a GitHub account, a Supabase project (free tier is fine).

```bash
git clone https://github.com/silviooerudon/repoguard.git
cd repoguard
npm install
```

Create `.env.local`:

```bash
AUTH_SECRET=             # generate with: npx auth secret
AUTH_GITHUB_ID=          # from a GitHub OAuth App pointing to localhost:3000
AUTH_GITHUB_SECRET=
SUPABASE_URL=
SUPABASE_SERVICE_ROLE_KEY=
```

Create the `scans` table in Supabase (schema in `docs/`), then:

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Roadmap

Built in public. Rough order of what's next, depending on user feedback:

- [ ] Go and Ruby dependency scanning (OSV.dev covers both)
- [ ] Terraform + CloudFormation IaC rules (public S3 buckets, open security groups, etc.)
- [ ] SARIF export and GitHub Code Scanning integration
- [ ] Continuous scanning via GitHub webhooks (requires GitHub App migration)
- [ ] Team accounts and shared scan history
- [ ] Ignore rules / per-finding suppressions

If something here matters to you, [open an issue](https://github.com/silviooerudon/repoguard/issues) — feedback shapes priorities.

## Author

Built by **Silvio Gazzoli** — IAM/IGA specialist based in Dublin, Ireland. 10+ years working with SailPoint, CyberArk, and enterprise identity governance.

[LinkedIn](https://www.linkedin.com/in/silvio-junior-de-almeida-gazzoli-78453a8a/) · [GitHub](https://github.com/silviooerudon)

## License

MIT
