# TriageRook

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg) ![Status: Beta](https://img.shields.io/badge/status-beta-orange.svg) ![Next.js 16](https://img.shields.io/badge/Next.js-16-black?logo=nextdotjs) ![TypeScript 5](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript) ![Live](https://img.shields.io/website?url=https%3A%2F%2Fwww.triagerook.com&label=live%20demo)

> Lightweight GitHub security scanner for solo devs and small teams. Live at **[www.triagerook.com](https://www.triagerook.com)**.

Scans your GitHub repos across a dozen-plus detector families, run in parallel where independent — **60+ secret patterns**, sensitive files, **28 AST-based SAST rules**, dependencies across **npm, PyPI, Go, RubyGems, Maven/Gradle, and Composer** (plus **container-image OS-package CVEs** ingested from a Trivy SARIF report), supply-chain misconfigurations, IaC checks for **Dockerfile, GitHub Actions, Terraform, Kubernetes, CloudFormation, and Helm**, cloud IAM risk in code (AWS / GCP / Azure / GitHub scopes), and git-history replay — with no CLI, no config, and no pipelines to wire up. Sign in with GitHub or paste a public URL, then get a prioritized list of findings in under a minute. Every finding is one click from a **SARIF 2.1.0 export** ready to upload to GitHub Code Scanning.

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

### 6. Vulnerable dependencies (npm, PyPI, Go, RubyGems, Maven/Gradle, Composer)

- **npm** — prefers `package-lock.json` to cover the entire dependency tree (direct + transitive), supports lockfile v1, v2, and v3. Queries the npm advisory bulk API and links each finding to its GHSA + CVSS score.
- **PyPI** — parses `requirements.txt`, `pyproject.toml` (PEP-621 + Poetry), and `Pipfile`. Queries the [OSV.dev](https://osv.dev) batch API and hydrates each vulnerability with severity, affected ranges, and GHSA link.
- **Go** — parses `go.mod` (direct + indirect requires, strips `+incompatible`). Queries OSV with ecosystem `Go`; advisories link to `pkg.go.dev/vuln/...` for the official Go vulnerability page when available.
- **RubyGems** — parses `Gemfile.lock` for pinned versions (Gemfile alone is not authoritative because it carries constraints, not concrete versions). Queries OSV with ecosystem `RubyGems`, same advisory coverage `bundler-audit` uses.
- **Maven / Gradle (JVM)** — parses `pom.xml` and `build.gradle` / `build.gradle.kts` (both resolve Maven-coordinate artifacts). Queries OSV with ecosystem `Maven`. Property-interpolated (`${spring.version}`) and dynamic (`1.+`) versions that can't be resolved statically are skipped.
- **Composer (PHP)** — parses `composer.lock` (`packages` + `packages-dev`). Queries OSV with ecosystem `Packagist`, the same database `composer audit` uses.
- **Container images** — OS-package CVEs (the `apt`/`apk`/`rpm` layers a lockfile can't see) are ingested from a [Trivy](https://trivy.dev) SARIF report you run in CI and commit — folded in as a **Container** ecosystem. No image-scanning infra on our side; setup guide in [`docs/container-scanning.md`](docs/container-scanning.md).

All ecosystems share one OSV query core, the same 500-package cap, and graceful degradation (a registry outage marks the detector skipped rather than failing the scan).

> **Base-image freshness** is checked statically too: a `FROM` pinned to an **end-of-life** runtime/distro (`node:16`, `python:3.7`, `debian:9`, `ubuntu:18.04`, EOL `alpine`, any `centos`) is flagged, since an unsupported base stops receiving security patches and accumulates CVEs by definition.

### 6b. Cloud IAM in code

Over-privileged cloud IAM declared in code/config — the `chmod 777` of cloud permissions. TriageRook flags:

- **AWS** IAM policy documents (in `*.json` or inline in source) with a wildcard action (`"Action": "*"`), service-wide wildcard (`"s3:*"`), wildcard resource (`"Resource": "*"`), or a public principal (`"Principal": "*"` / `{"AWS": "*"}`). Rules require a real policy-document context (`Statement` + `Effect`) to avoid false positives on arbitrary JSON.
- **GCP** primitive roles (`roles/owner`, `roles/editor`) wherever they're assigned.
- **Azure RBAC** built-in `Owner` / `Contributor` assignments (by well-known role GUID anywhere, or by name inside an Azure context — `az role assignment`, Bicep/ARM `roleDefinitionName`), and custom roles with wildcard `"Actions": ["*"]`.
- **GitHub** over-broad OAuth/PAT scope requests (`delete_repo`, `admin:org`, `admin:enterprise`, `admin:repo_hook`, `site_admin`), in both `scope:`/`scope=` and `--scope` CLI forms — gated so prose mentioning a scope name isn't flagged.

HCL (`.tf`) is left to the Terraform layer. This is distinct from the org/repo IAM-posture scanner below — this is identity risk *in your code*.

### 7. CI / IaC / supply-chain misconfigurations

- **Dockerfile** — container running as root, missing `USER` directive, `:latest` base tags, `ADD http(s)://`, secrets baked into `ENV`, `RUN curl | sh`, `chmod 777`, unpinned `apt install`, and **end-of-life base images**
- **GitHub Actions** — `pull_request_target` checking out PR head with secrets exposed (the s1ngularity / GhostAction vector), third-party actions not pinned to a full SHA, `run:` steps interpolating `${{ github.event.* }}` fields (script injection), workflow-level `permissions: write-all`, and **secret-named `env:` values set to a committed literal** instead of `${{ secrets.* }}`
- **Terraform** — public S3 ACLs and disabled public-access-block flags, security-group `ingress` open to `0.0.0.0/0` (and `::/0`), wildcard IAM `Action`/`Resource` (`*`), unencrypted storage (`storage_encrypted = false`), publicly accessible databases (`publicly_accessible = true`)
- **CloudFormation** — the same AWS misconfig set for CFN templates (YAML **and** JSON): public S3 ACL / disabled public-access-block, wildcard IAM action/resource, `SecurityGroupIngress` open to `0.0.0.0/0` (egress correctly ignored), unencrypted storage, publicly accessible RDS. Self-guards on `AWSTemplateFormatVersion` / `Resources` + an `AWS::` type so non-template YAML/JSON is skipped.
- **Kubernetes** — manifests (detected by `apiVersion:` + `kind:`) with privileged containers, host namespaces (`hostNetwork`/`hostPID`/`hostIPC`), `allowPrivilegeEscalation`, running as root (`runAsUser: 0` / `runAsNonRoot: false`), mutable image tags (`:latest`/untagged), and dangerous added Linux capabilities (`SYS_ADMIN`, `NET_ADMIN`, `ALL`, …). Helm-templated lines are skipped to avoid noise.
- **Helm** — chart `values*.yaml` insecure defaults that flow into every rendered workload (`privileged`, `runAsNonRoot: false` / `runAsUser: 0`, host namespaces, `allowPrivilegeEscalation`, mutable image tag). Values files aren't rendered manifests, so the Kubernetes layer skips them — this catches the gap.
- **Lifecycle hook abuse (npm + PyPI)** -- `package.json` scripts (`preinstall`/`install`/`postinstall`/`prepare`) and Python `setup.py`/`pyproject.toml` build hooks running `curl | sh`, `base64` decode-and-execute, environment-variable exfiltration combined with network calls, or destructive `rm -rf` chains. Catches install-time supply-chain vectors used in recent npm and PyPI compromises.
- **Typosquatting in dependency manifests** -- flags packages whose names are edit-distance-1 (`lodahs`, `expres`, `reqests`), edit-distance-2 prefix (`lodashes`), or case-fold variants (`Chalk`) of popular npm and PyPI registry names.
- **Registry-backed supply-chain signals (npm)** -- via public npm registry metadata: **dependency confusion** (a declared name that 404s on the public registry — an attacker can claim it and hijack resolution), **recently-published** packages (created within 30 days — a common typosquat/hijack vehicle), and **suspicious-maintainer** signals (deprecated package, or zero maintainers listed).

### 8. Repository posture score

Beyond looking for specific findings, TriageRook grades how the repo is set up: governance docs (`SECURITY.md`, `LICENSE`, `CODEOWNERS`), branch protection + rulesets on the default branch (PR review required, status checks, enforce-admins), signed-commit ratio, org MFA enforcement, dependency-update automation, lockfile/`.gitignore` hygiene, plus **GitHub secret scanning + push protection**, **least-privilege default `GITHUB_TOKEN` permissions**, and **release signing / build provenance** (cosign / sigstore / SLSA / npm `--provenance`). The result is a single A–F grade scored as a **percentage of assessable signals** — signals the token cannot inspect (e.g. admin-only secret-scanning status on a public scan) are reported as `unknown` and excluded from the math rather than counted as failures, so the grade stays honest and a missing admin scope doesn't tank the score. The per-signal breakdown shows exactly what to fix to raise it.

### 9. IAM risk scanner

The angle a 10+ year IAM/IGA specialist actually cares about: identity and access risk in the IAM policy-as-code you commit. TriageRook parses IAM policy documents out of Terraform, CloudFormation/SAM, raw JSON, and serverless configs, then runs three families of checks over them — **GitHub Actions OIDC trust** weaknesses (no `Condition`, wildcard repo/ref, `pull_request` trust), **privilege-escalation** paths (`iam:PassRole` on `*`, PassRole combined with compute creation, self-managing policies, unconditioned `sts:AssumeRole`, `Allow` + `NotAction`), and **admin-equivalent** grants (`Action: *` on `Resource: *`, sensitive-service wildcards, wildcard `Principal` with no `Condition`). Findings deduct from a 100-point score that maps to a low/medium/high/critical level. It reads policy-as-code, not your live cloud control plane, and needs no elevated GitHub scope. (Org-level MFA enforcement is graded separately, as a repo-posture signal.) Full write-up with vulnerable-vs-fixed examples at [`/docs/iam-risk-scanner`](https://www.triagerook.com/docs/iam-risk-scanner). This is the slice of enterprise IAM tooling that solo devs and small teams have historically had no access to.

### 10. Open-source license / compliance risk

Legal risk, not security: a transitive GPL/AGPL dependency in a proprietary product, or a package with no license at all (which grants you no legal right to use it), is a real problem CVE scans never surface. For **npm**, TriageRook reads the `license` field recorded on every entry of `package-lock.json` (v2/v3) — **no extra network calls**. For **PyPI / Go / RubyGems** (whose lockfiles don't carry license data), it enriches via [deps.dev](https://deps.dev) (Google's Open Source Insights — same benign public-metadata nature as OSV.dev), bounded to 200 packages with graceful degradation. It flags **strong copyleft** (GPL/AGPL/SSPL), **weak copyleft** (LGPL/MPL/EPL/CDDL), and **proprietary/UNLICENSED** licenses. Dual-licensed `(MIT OR GPL-3.0)` expressions with a permissive escape are treated as acceptable, and dev-only npm dependencies are skipped since they aren't redistributed.

## Beyond detection

### SARIF 2.1.0 export + GitHub Code Scanning

Every saved scan is one click from a SARIF 2.1.0 export. Drop the file into `github/codeql-action/upload-sarif` and findings show up in your repo's `Security → Code scanning` tab next to CodeQL and Dependabot — with each result deep-linked back to its rule documentation. Anonymous scans at `/scan-public/<owner>/<repo>` can also export SARIF (generated client-side from the in-flight result). For public repos, the anonymous scan endpoint accepts `?format=sarif` directly — drop the [ready-made workflow](https://www.triagerook.com/workflows/triagerook.yml) at `.github/workflows/triagerook.yml` and every push gets scanned + uploaded with zero auth setup. Full setup guide with copy-pasteable workflow YAML at [`/docs/sarif`](https://www.triagerook.com/docs/sarif).

### Secret liveness validation (opt-in)

When enabled (`ENABLE_SECRET_VALIDATION=true`), authenticated scans additionally probe each detected provider secret — GitHub, GitLab, Stripe, OpenAI, Anthropic, SendGrid, Slack, npm — against a single read-only endpoint to mark it **live** or **revoked/inactive**, *without ever exposing or storing the value* (only the status). A confirmed-live credential is boosted to the top of the report; a rejected one is pushed down as almost certainly already rotated. This is the single biggest false-positive reducer for secret findings. It is **off by default** and **never** runs on the anonymous public-scan path — that path scans arbitrary repos, and TriageRook will not fire third-party API calls using strangers' leaked credentials. AWS keys are reported as unverifiable (validating them needs both key halves plus request signing).

### Risk prioritization

500 findings sorted by raw severity is noise. TriageRook scores each finding for *real* urgency before ranking: base severity, then multipliers for whether a detected secret is **confirmed live** (validation, below), whether a vulnerable dependency is **transitive** vs direct or **dev-only vs production** (a dev dep isn't shipped to runtime), whether a code finding sits in an **HTTP-exposed file** (a `routes/`, `controllers/`, `pages/api`, or `app/**/route.ts` finding is attacker-reachable, so it ranks above the same bug in internal code), and whether it's in a **test fixture** (deprioritized). The repo score is log-compressed so a huge monorepo with hundreds of criticals doesn't read identically to a hobby project with four.

### Attack paths & blast radius

Individual findings tell you *what's wrong*; this tells you *so what*. TriageRook correlates the findings into multi-hop **attack paths** and assigns each leaked credential a **blast radius** — the concrete assets it reaches. A leaked AWS key becomes "→ AWS account → S3/RDS/data"; pair it with a public-S3 or wildcard-IAM finding in the same repo and the path is chained and elevated to critical. SCM tokens surface the "→ CI/CD → downstream supply chain" pivot; payments keys surface customer-data reach. When secret validation (above) confirms a credential is live, its path is marked and pushed to the top. Pure correlation over the existing findings — no extra calls.

### Auto-fix pull requests

For findings that have a clean, deterministic fix, TriageRook can open a PR against your repo directly:

- **Extract a hardcoded secret** to an env var + update `.env.example`
- **Bump a vulnerable dependency** (npm / Python) to a non-vulnerable version
- **Bump an end-of-life Docker base image** to a current release (variant suffix preserved)
- **Replace `permissions: write-all`** in a workflow with least-privilege `contents: read`

Requires installing the **TriageRook Security** GitHub App on the target repo so the PR can be authored — installation is scoped to the single repo and grants only `Contents: write` and `Pull requests: write`. You review the PR before merging. (SHA-pinning of unpinned Actions is intentionally not auto-fixed — resolving a tag to a commit SHA needs a network lookup that doesn't fit the pure-patch model.)

### Per-repo suppressions

False positives happen. From the findings view you can suppress a single finding (by fingerprint), a rule on a path (by glob), or a whole rule for the repo. Suppressions are user-scoped and synced via Supabase — they survive across scans without committing a `.repoguardignore` to the repo (though that file is also honored at scan time).

## Documentation

Full product documentation lives at **[triagerook.com/docs](https://www.triagerook.com/docs)** — written to be read by skeptical developers, with every factual claim derived from this codebase:

- [Security & data handling](https://www.triagerook.com/docs/security-and-data-handling) — GitHub App permissions, what each scan endpoint stores, secret masking.
- [Scan limits](https://www.triagerook.com/docs/scan-limits) · [Suppressions](https://www.triagerook.com/docs/suppressions) · [Quickstart](https://www.triagerook.com/docs/quickstart) · [FAQ](https://www.triagerook.com/docs/faq)
- [Detectors](https://www.triagerook.com/docs/detectors) · [Detection rules](https://www.triagerook.com/docs/rules) · [Posture score](https://www.triagerook.com/docs/posture-score) · [IAM risk scanner](https://www.triagerook.com/docs/iam-risk-scanner)
- [SARIF export](https://www.triagerook.com/docs/sarif) · [Changelog](https://www.triagerook.com/docs/changelog)

Security policy and vulnerability reporting: [SECURITY.md](SECURITY.md).

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
- **APIs:** GitHub REST v3, npm audit bulk, OSV.dev (PyPI/Go/RubyGems/Maven/Composer), deps.dev (registry license metadata), npm registry (supply-chain signals); container CVEs ingested from a committed Trivy SARIF report

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

Built in public. The detection surface is now broad — recent work closed the
remaining gaps against the standard "what a repo scanner must cover" checklist:

- [x] SARIF 2.1.0 export and GitHub Code Scanning integration — [`/docs/sarif`](https://www.triagerook.com/docs/sarif)
- [x] Ignore rules / per-finding suppressions (user-scoped, synced via Supabase)
- [x] Auto-fix pull requests — secret-extract, dependency bump, EOL base-image bump, workflow `write-all` → least-privilege
- [x] Go and Ruby dependency scanning (OSV.dev — `go.mod` + `Gemfile.lock`)
- [x] Maven/Gradle + Composer dependency scanning (OSV.dev — `pom.xml` / `build.gradle` / `composer.lock`)
- [x] Container-image OS-package CVEs via Trivy SARIF ingestion — [`docs/container-scanning.md`](docs/container-scanning.md)
- [x] Terraform + **CloudFormation** + **Helm** IaC rules
- [x] PyPI/Go/RubyGems license/compliance coverage (via deps.dev)
- [x] Cloud IAM-in-code: AWS + GCP + **Azure RBAC** + **GitHub OAuth scopes**
- [x] Posture: secret scanning, workflow least-privilege, release provenance
- [ ] Continuous scanning via GitHub webhooks (scan-on-push + new-finding alerts)
- [ ] Team accounts and shared scan history
- [ ] Private-repo support (read scope expansion)
- [ ] Billing / paid tiers

The remaining open items are the commercialization layer (continuous monitoring,
teams, private repos, billing) rather than detection coverage.

If something here matters to you, [open an issue](https://github.com/silviooerudon/triagerook/issues) — feedback shapes priorities.

## Author

Built by **Silvio Gazzoli** — IAM/IGA specialist based in Dublin, Ireland. 10+ years working with SailPoint, CyberArk, and enterprise identity governance.

[LinkedIn](https://www.linkedin.com/in/silvio-junior-de-almeida-gazzoli-78453a8a/) · [GitHub](https://github.com/silviooerudon)

## License

MIT
