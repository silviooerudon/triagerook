# TriageRook

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg) ![Status: Beta](https://img.shields.io/badge/status-beta-orange.svg) ![Next.js 16](https://img.shields.io/badge/Next.js-16-black?logo=nextdotjs) ![TypeScript 5](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript) ![Live](https://img.shields.io/website?url=https%3A%2F%2Fwww.triagerook.com&label=live%20demo)

> Lightweight GitHub security scanner for solo devs and small teams. Live at **[www.triagerook.com](https://www.triagerook.com)**.

Scans your GitHub repos across ten detector families, run in parallel where independent — **60+ secret patterns**, sensitive files, **28 AST-based SAST rules**, dependencies across **npm, PyPI, Go, and RubyGems**, supply-chain misconfigurations, IaC checks for Dockerfile and GitHub Actions, and git-history replay — with no CLI, no config, and no pipelines to wire up. Sign in with GitHub or paste a public URL, then get a prioritized list of findings in under a minute. Every finding is one click from a **SARIF 2.1.0 export** ready to upload to GitHub Code Scanning.

📖 The full rule catalog (170+ rules, every CWE) is published at [`/docs/rules`](https://www.triagerook.com/docs/rules). The SARIF integration guide lives at [`/docs/sarif`](https://www.triagerook.com/docs/sarif).

## Why I built this

I've spent 10+ years in Identity & Access Management — the field that exists because credentials leak and people get owned. Tools like Snyk and GitGuardian are great, but priced for teams with security budgets. Solo devs and tiny startups skip security scanning entirely because the bar to entry is too high.

TriageRook is my attempt at the smallest useful security tool: scan a repo in one click, see what's wrong, fix it. Built in public.

## What TriageRook actually detects

TriageRook runs ten independent detectors over your repo and aggregates the results into a single prioritized report.

### 1. Secrets in source code (60+ patterns)

High-confidence regex detection for modern token formats across cloud providers, SCM platforms, AI APIs, payments, communications, monitoring, and developer tooling — AWS/Azure/GCP/DigitalOcean/Cloudflare/Vercel/Netlify/Fly/Render; GitHub (classic, fine-grained, OAuth, App tokens), GitLab, Bitbucket; Anthropic, OpenAI (current + legacy), Hugging Face, Replicate, Groq, Perplexity; Stripe, Braintree, Square, Shopify, Adyen; Slack, Discord, Telegram, SendGrid, Mailgun, Twilio; Datadog, New Relic, Sentry, PagerDuty, Algolia; npm/PyPI/Docker Hub/JFrog tokens; HashiCorp Vault, Terraform Cloud; and generic formats like `-----BEGIN PRIVATE KEY-----`, `_authToken=` in `.npmrc`, HTTP Basic-Auth URLs, Supabase `service_role` JWTs.

### 2. Sensitive files committed to the repo

Filename-based detection that flags files which are never safe to commit regardless of their contents: `*.pem`, `*.key`, `*.pfx/.p12/.jks/.keystore`, `id_rsa`/`id_ed25519`/`id_ecdsa`, `.kdbx` (KeePass), `.env.production`, `.aws/credentials`, GCP service-account JSONs, kubeconfig, `.docker/config.json`, `.npmrc` with auth, `terraform.tfstate`, database dumps, `.git-credentials`, `.htpasswd`, `.pgpass`. Each finding ships with a concrete remediation step.

### 3. High-entropy secrets in `.env` / config files

When a regex can't help, entropy analysis can. TriageRook parses `.env`, `.envrc`, `.ini`, `.toml`, `.properties`, `.yaml`, and `.conf` files line-by-line, extracts `KEY=VALUE` pairs, discards placeholders (`xxx`, `changeme`, URLs, semver, IPs), and flags values with Shannon entropy ≥ 4.0 bits/char whose key names match `password|secret|api_key|access_key|auth_token|client_secret|…`. Catches custom corporate tokens that dedicated regexes miss.

### 4. Secrets in recent git history

Even a rotated secret is still a compromised secret if it lives in a past commit. TriageRook fetches up to 30 recent commits via the GitHub API, extracts added patch lines, and re-runs the full 60+ pattern library over them. Findings are deduplicated against the current tree so only history-exclusive matches surface, tagged with commit SHA + author + date.

### 5. Code-level vulnerabilities (SAST)

Two layers run side-by-side:

- **AST analysis** via the TypeScript Compiler API (`ts-morph`) — 28 rules over JS/TS that track user input flowing into dangerous sinks across property hops the regex layer can't follow.
- **Conservative regex rules** over JS/TS and Python where AST parsing would be overkill — TLS verify disabled, weak bcrypt cost, NEXT_PUBLIC_ secret reads, Python `yaml.load` without `SafeLoader`, etc.

Every rule is tied to a CWE identifier so findings are actionable. Headline coverage (full list at [`/docs/rules`](https://www.triagerook.com/docs/rules)):

- **Injection** — SQL (CWE-89), command (CWE-78), NoSQL (`$where` user input, CWE-943), SSTI (CWE-1336), prototype pollution (CWE-1321), XXE (CWE-611)
- **Cross-site scripting** — React `dangerouslySetInnerHTML` (CWE-79), reflected XSS via `res.send`
- **SSRF / Open redirect** — `fetch`/`axios` with `req.body` / `req.params` (CWE-918), `res.redirect` with request-derived URL (CWE-601)
- **Authentication / authorization** — JWT signed without `expiresIn` (CWE-613), JWT with hardcoded string secret (CWE-798), JWT decoded without verifying signature (CWE-347), hardcoded admin credentials, timing-unsafe credential compare (CWE-208)
- **Crypto** — MD5/SHA1 for password or secret hashing (CWE-327), weak cipher mode (ECB / deprecated `createCipher`), hardcoded encryption key, `Math.random()` for session IDs, OTPs, tokens (CWE-338), insecure-randomness `uuid.v1()`
- **Path / file** — path traversal via `fs.readFile`/`open()` with request-derived paths (CWE-22)
- **Dynamic code / execution** — `eval`, `new Function`, `setTimeout(string)`, Python `eval`/`exec` (CWE-95)
- **Denial of service** — ReDoS via dynamic `RegExp` constructed from user input (CWE-1333)
- **Network / transport** — TLS verification disabled (CWE-295), WebSocket opened over cleartext `ws://` (CWE-319), wildcard CORS via `setHeader('Access-Control-Allow-Origin', '*')` with credentials, CORS `credentials: true` with `origin: '*'` (CWE-942)
- **Session / cookie hygiene** — insecure-cookie `httpOnly: false` / `secure: false` (CWE-1004 / CWE-614), insecure session config (`resave: true`, `saveUninitialized: true`, weak secret), weak bcrypt cost (CWE-916)
- **Insecure deserialization** — Python `pickle.loads`, `yaml.load` without `SafeLoader` (CWE-502)
- **Information disclosure** — `console.log` of `password` / `apiKey` / `token` / `secret`-named locals (CWE-532), Next.js `NEXT_PUBLIC_*SECRET*` env reads that inline into the client bundle (CWE-200)
- **Misc AI-typical mistakes** — `process.env.X || "sk-…"` fallback literals, `bcrypt.hash(..., N)` with N below 10

Detection runs over JavaScript / TypeScript primarily. Python coverage extends to the regex layer for SAST and the dependency layer for vulnerabilities.

**Framework-aware rules (context-aware SAST).** A third layer reads the repo's manifests to detect the stack in use (Next.js, Express, NestJS, Django, Flask, FastAPI, Spring, Laravel, Rails) and runs framework-specific checks *only when that framework is present* — so `DEBUG = True` is flagged as a Django production risk rather than as noise on any variable named `DEBUG`. Coverage includes Django `DEBUG`/`ALLOWED_HOSTS=['*']`/`@csrf_exempt`, Flask `debug=True`, FastAPI wildcard-CORS-with-credentials, Express/NestJS default-wildcard CORS, Spring `csrf().disable()` / `@CrossOrigin("*")` / Actuator `exposure.include=*`, Laravel `'debug' => true`, and Rails `skip_before_action :verify_authenticity_token`.

### 6. Vulnerable dependencies (npm, PyPI, Go, RubyGems)

- **npm** — prefers `package-lock.json` to cover the entire dependency tree (direct + transitive), supports lockfile v1, v2, and v3. Queries the npm advisory bulk API and links each finding to its GHSA + CVSS score.
- **PyPI** — parses `requirements.txt`, `pyproject.toml` (PEP-621 + Poetry), and `Pipfile`. Queries the [OSV.dev](https://osv.dev) batch API and hydrates each vulnerability with severity, affected ranges, and GHSA link.
- **Go** — parses `go.mod` (direct + indirect requires, strips `+incompatible`). Queries OSV with ecosystem `Go`; advisories link to `pkg.go.dev/vuln/...` for the official Go vulnerability page when available.
- **RubyGems** — parses `Gemfile.lock` for pinned versions (Gemfile alone is not authoritative because it carries constraints, not concrete versions). Queries OSV with ecosystem `RubyGems`, same advisory coverage `bundler-audit` uses.

### 6b. Cloud IAM in code

Over-privileged cloud IAM declared in code/config — the `chmod 777` of cloud permissions. TriageRook flags **AWS IAM policy documents** (in `*.json` or inline in source) with a wildcard action (`"Action": "*"`), service-wide wildcard (`"s3:*"`), wildcard resource (`"Resource": "*"`), or a public principal (`"Principal": "*"` / `{"AWS": "*"}`); and **GCP primitive roles** (`roles/owner`, `roles/editor`) wherever they appear. AWS rules require a real policy-document context (`Statement` + `Effect`) to avoid false positives on arbitrary JSON. HCL (`.tf`) is left to the Terraform layer. This is distinct from the org/repo IAM-posture scanner below — this is identity risk *in your code*.

### 7. CI / IaC / supply-chain misconfigurations

- **Dockerfile** — container running as root, missing `USER` directive, `:latest` base tags, `ADD http(s)://`, secrets baked into `ENV`, `RUN curl | sh`, `chmod 777`, unpinned `apt install`
- **GitHub Actions** — `pull_request_target` checking out PR head with secrets exposed (the s1ngularity / GhostAction vector), third-party actions not pinned to a full SHA, `run:` steps interpolating `${{ github.event.* }}` fields (script injection), workflow-level `permissions: write-all`
- **Terraform** — public S3 ACLs and disabled public-access-block flags, security-group `ingress` open to `0.0.0.0/0` (and `::/0`), wildcard IAM `Action`/`Resource` (`*`), unencrypted storage (`storage_encrypted = false`), publicly accessible databases (`publicly_accessible = true`)
- **Kubernetes** — manifests (detected by `apiVersion:` + `kind:`) with privileged containers, host namespaces (`hostNetwork`/`hostPID`/`hostIPC`), `allowPrivilegeEscalation`, running as root (`runAsUser: 0` / `runAsNonRoot: false`), mutable image tags (`:latest`/untagged), and dangerous added Linux capabilities (`SYS_ADMIN`, `NET_ADMIN`, `ALL`, …). Helm-templated lines are skipped to avoid noise.
- **Lifecycle hook abuse (npm + PyPI)** -- `package.json` scripts (`preinstall`/`install`/`postinstall`/`prepare`) and Python `setup.py`/`pyproject.toml` build hooks running `curl | sh`, `base64` decode-and-execute, environment-variable exfiltration combined with network calls, or destructive `rm -rf` chains. Catches install-time supply-chain vectors used in recent npm and PyPI compromises.
- **Typosquatting in dependency manifests** -- flags packages whose names are edit-distance-1 (`lodahs`, `expres`, `reqests`), edit-distance-2 prefix (`lodashes`), or case-fold variants (`Chalk`) of popular npm and PyPI registry names.

### 8. Repository posture score

Beyond looking for specific findings, TriageRook grades how the repo is set up: governance docs (`SECURITY.md`, `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`), branch protection rules on the default branch, vulnerability-alert configuration, dependency-update automation, and other operational hygiene signals. The result is a single A+ to F grade with a per-signal breakdown showing exactly what to fix to raise it. Signals the OAuth token cannot inspect (e.g. branch protection without admin permission) are reported as `unknown` rather than as failures, so the grade stays honest.

### 9. IAM risk scanner

The angle a 10+ year IAM/IGA specialist actually cares about: identity and access risk at org and repo level. TriageRook surfaces org-level MFA enforcement (when `read:org` scope is granted), outside-collaborator permission levels, repo-level secret scoping, and authorship patterns that signal stale ownership. When a signal requires permissions the token does not have, TriageRook skips it and labels it as such rather than guessing. This is the slice of enterprise IAM tooling that solo devs and small teams have historically had no access to.

### 10. Open-source license / compliance risk

Legal risk, not security: a transitive GPL/AGPL dependency in a proprietary product, or a package with no license at all (which grants you no legal right to use it), is a real problem CVE scans never surface. TriageRook reads the `license` field recorded on every entry of `package-lock.json` (npm v2/v3) — **no extra network calls** — and flags **strong copyleft** (GPL/AGPL/SSPL), **weak copyleft** (LGPL/MPL/EPL/CDDL), **missing**, and **proprietary/UNLICENSED** licenses. Dual-licensed `(MIT OR GPL-3.0)` expressions with a permissive escape are treated as acceptable, and dev-only dependencies are skipped since they aren't redistributed. PyPI/Go/RubyGems license coverage (which needs per-package registry lookups) is on the roadmap.

## Beyond detection

### SARIF 2.1.0 export + GitHub Code Scanning

Every saved scan is one click from a SARIF 2.1.0 export. Drop the file into `github/codeql-action/upload-sarif` and findings show up in your repo's `Security → Code scanning` tab next to CodeQL and Dependabot — with each result deep-linked back to its rule documentation. Anonymous scans at `/scan-public/<owner>/<repo>` can also export SARIF (generated client-side from the in-flight result). For public repos, the anonymous scan endpoint accepts `?format=sarif` directly — drop the [ready-made workflow](https://www.triagerook.com/workflows/triagerook.yml) at `.github/workflows/triagerook.yml` and every push gets scanned + uploaded with zero auth setup. Full setup guide with copy-pasteable workflow YAML at [`/docs/sarif`](https://www.triagerook.com/docs/sarif).

### Secret liveness validation (opt-in)

When enabled (`ENABLE_SECRET_VALIDATION=true`), authenticated scans additionally probe each detected provider secret — GitHub, GitLab, Stripe, OpenAI, Anthropic, SendGrid, Slack, npm — against a single read-only endpoint to mark it **live** or **revoked/inactive**, *without ever exposing or storing the value* (only the status). A confirmed-live credential is boosted to the top of the report; a rejected one is pushed down as almost certainly already rotated. This is the single biggest false-positive reducer for secret findings. It is **off by default** and **never** runs on the anonymous public-scan path — that path scans arbitrary repos, and TriageRook will not fire third-party API calls using strangers' leaked credentials. AWS keys are reported as unverifiable (validating them needs both key halves plus request signing).

### Attack paths & blast radius

Individual findings tell you *what's wrong*; this tells you *so what*. TriageRook correlates the findings into multi-hop **attack paths** and assigns each leaked credential a **blast radius** — the concrete assets it reaches. A leaked AWS key becomes "→ AWS account → S3/RDS/data"; pair it with a public-S3 or wildcard-IAM finding in the same repo and the path is chained and elevated to critical. SCM tokens surface the "→ CI/CD → downstream supply chain" pivot; payments keys surface customer-data reach. When secret validation (above) confirms a credential is live, its path is marked and pushed to the top. Pure correlation over the existing findings — no extra calls.

### Auto-fix pull requests

For findings that have a clean fix (secret rotation via `.env.example` updates, dependency bumps to a non-vulnerable version), TriageRook can open a PR against your repo directly. Requires installing the **TriageRook Security** GitHub App on the target repo so the PR can be authored — installation is scoped to the single repo and grants only `Contents: write` and `Pull requests: write`. You review the PR before merging.

### Per-repo suppressions

False positives happen. From the findings view you can suppress a single finding (by fingerprint), a rule on a path (by glob), or a whole rule for the repo. Suppressions are user-scoped and synced via Supabase — they survive across scans without committing a `.repoguardignore` to the repo (though that file is also honored at scan time).

## Privacy

We **never** store in our database:
- Your source code (we keep only file paths and masked previews — never full file contents)
- Your GitHub access token (it lives in the encrypted Auth.js session cookie for server-side scan calls, and is never written to Supabase or exposed via `/api/auth/session`)
- Full secret values (only the type, file path, line number, and a masked preview)

We **do** store: scan metadata (owner/repo, timestamp, counts) and findings (file paths + line numbers + pattern IDs + masked previews) so you can review history.

Data lives in Supabase (EU region) and Vercel. You can revoke access anytime via your [GitHub settings](https://github.com/settings/applications). Full details on the [security page](https://www.triagerook.com/security).

## Tech stack

- **Framework:** Next.js 16 (App Router) + TypeScript + Tailwind
- **Auth:** NextAuth v5 backed by the **TriageRook Security GitHub App** (user OAuth gives read access to public repositories; installing the App on a target repo grants the scoped write needed for auto-fix PRs)
- **Database:** Supabase (Postgres + JSONB, EU region) with RLS policies as a defense-in-depth layer
- **Hosting:** Vercel
- **Static analysis:** `ts-morph` (TypeScript Compiler API wrapper) for the AST layer
- **APIs:** GitHub REST v3, npm audit bulk, OSV.dev

## Run locally

Prereqs: Node 20+, a GitHub account, a Supabase project (free tier is fine).

```bash
git clone https://github.com/silviooerudon/triagerook.git
cd triagerook
npm install
```

Create `.env.local`:

```bash
AUTH_SECRET=                       # generate with: npx auth secret
AUTH_GITHUB_APP_CLIENT_ID=         # from the TriageRook Security GitHub App (OAuth user flow)
AUTH_GITHUB_APP_CLIENT_SECRET=
SUPABASE_URL=
SUPABASE_SECRET_KEY=               # Supabase service-role key (server-side only)

# Optional — needed only if you want to test the auto-fix PR flow locally:
# AUTH_GITHUB_APP_ID=
# AUTH_GITHUB_APP_PRIVATE_KEY=     # PEM, escape newlines as \n in .env
```

Create the `scans` table in Supabase (schema in `docs/`), then:

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

## Roadmap

Built in public. Rough order of what's next, depending on user feedback:

- [x] SARIF 2.1.0 export and GitHub Code Scanning integration — [`/docs/sarif`](https://www.triagerook.com/docs/sarif)
- [x] Ignore rules / per-finding suppressions (user-scoped, synced via Supabase)
- [x] Auto-fix pull requests (requires GitHub App install on the target repo)
- [x] Go and Ruby dependency scanning (OSV.dev covers both — `go.mod` + `Gemfile.lock`)
- [ ] Terraform + CloudFormation IaC rules (public S3 buckets, open security groups, etc.)
- [ ] Continuous scanning via GitHub webhooks
- [ ] Team accounts and shared scan history
- [ ] Private-repo support (read scope expansion)

If something here matters to you, [open an issue](https://github.com/silviooerudon/triagerook/issues) — feedback shapes priorities.

## Author

Built by **Silvio Gazzoli** — IAM/IGA specialist based in Dublin, Ireland. 10+ years working with SailPoint, CyberArk, and enterprise identity governance.

[LinkedIn](https://www.linkedin.com/in/silvio-junior-de-almeida-gazzoli-78453a8a/) · [GitHub](https://github.com/silviooerudon)

## License

MIT
