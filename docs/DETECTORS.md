# TriageRook — Detector Reference / Referência de Detectores

> Bilingual document. **English** first, **Português** below (jump to
> [Português](#português)). See [ARCHITECTURE.md](ARCHITECTURE.md) for how these
> run, and [DEVELOPMENT.md](DEVELOPMENT.md) to add a new one. The user-facing rule
> catalogue is at `/docs/rules` (`app/docs/rules/`), aggregated from
> `lib/rule-catalog.ts`.

---

## English

### How detection is organized

Every detector lives in `lib/` as framework-free TypeScript, returns a typed
finding shape from `lib/types.ts`, and is invoked from the scan pipeline (see
[ARCHITECTURE.md](ARCHITECTURE.md) §4). Findings carry a `ruleId` of the form
`<kind>/<id>`, which is the same vocabulary used by suppressions and SARIF.

The product's headline is **identity & CI/CD security** (§ Identity / CI-CD
below). Everything else is supporting coverage.

### Identity / CI-CD security — the core

This is the class native GitHub tooling does not cover. It needs an
identity-security lens to catch.

**GitHub Actions workflow privilege** — `lib/iac.ts::scanGithubActions()`

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `gha-pull-request-target-checkout` | critical | `pull_request_target` + checkout of the attacker head ref (GhostAction / s1ngularity pattern) |
| `gha-script-injection` | high | `run:` steps interpolating `${{ github.event.* }}` (issue title, PR body, head ref) → shell injection |
| `gha-hardcoded-secret-env` | high | Literal secrets in workflow `env:` instead of `${{ secrets.X }}` |
| `gha-permissions-write-all` | medium | `permissions: write-all` or no explicit block → over-broad `GITHUB_TOKEN` |
| `gha-unpinned-action` | medium | Third-party actions not pinned to a commit SHA |

**OIDC trust** — `lib/iam.ts` + `lib/iam-privesc.ts`
- AWS IAM role trust relationships with the GitHub OIDC provider that lack
  audience/subject restrictions → any (public) repo can assume the role.
- Privilege-escalation chains: OIDC → PassRole + create-compute → code execution.

**IAM admin-equivalent access** — `lib/iam-admin.ts`

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `iam-action-resource-wildcard` | critical | `Action: *` (or 3+ `service:*`) with `Resource: *` |
| `iam-principal-wildcard` | critical | `Principal: *` without a condition |
| `iam-sensitive-service-wildcard` | high | iam/kms/secretsmanager/sts actions with wildcard resource |

**IAM privilege escalation** — `lib/iam-privesc.ts`

| Rule | Severity | What it catches |
|------|----------|-----------------|
| `iam-passrole-wildcard` | critical | `iam:PassRole` with `Resource: *` |
| `iam-passrole-with-create-compute` | critical | PassRole + create-function/ec2/ecs → code execution |
| `iam-self-managing` | critical | CreatePolicyVersion/SetDefaultPolicyVersion/AttachRolePolicy + `Resource: *` |
| `iam-assume-role-no-condition` | high | AssumeRole without a principal condition |
| `iam-not-action-allow` | high | `Allow` with `NotAction` (inverted, dangerous logic) |

Shared IAM policy parsing lives in `lib/iam-policy.ts`.

### Supporting coverage

**Secrets** — `lib/secret-patterns.ts` (+ `entropy.ts`, optional
`secret-validation.ts`)
- 50+ provider patterns (AWS, Azure, GCP, GitHub, Stripe, npm, …), matched
  line-by-line, plus entropy analysis on high-entropy strings.
- Optional liveness validation (`ENABLE_SECRET_VALIDATION`, authenticated path
  only) probes whether a credential is live; feeds the risk multiplier.

**Code / SAST** — `lib/code-vulns.ts` (regex) + `lib/ast/rules/*.ts` (AST)
- ~30 language-agnostic regex rules (SQLi, SSRF, eval, XSS, hardcoded creds,
  weak crypto, …).
- 27 control-flow-aware AST rules for TS/JS via ts-morph, one rule per file
  under `lib/ast/rules/`.
- This layer is **intentionally lightweight** — it is not a CodeQL/Semgrep
  replacement (see [positioning.md](positioning.md)).

**Sensitive files** — `lib/sensitive-files.ts`
- ~24 detectors matching by name on the tree (`.env*`, keychains, Terraform
  state, ssh keys, kubeconfig, `.pgpass`, …) — no blob fetch needed.

**IaC** — beyond GitHub Actions above:
- `lib/iac.ts` — Dockerfile (root user, `latest` tags, `curl|sh`, ADD-from-URL,
  chmod 777, unpinned base image, …; base-image lookup in `docker-baseimage.ts`).
- `lib/iac-terraform.ts` — HCL (hardcoded secrets, wildcard resources,
  over-permissive SGs, public RDS/S3, over-permissive IAM, missing encryption).
- `lib/iac-k8s.ts` — Kubernetes YAML (privileged containers, root, unsafe caps,
  hostNetwork/PID/IPC, default/automount service-account token).
- `lib/iac-cloudformation.ts` — CFN JSON/YAML (IAM, secrets, public resources).
- `lib/iac-helm.ts` — Helm values.

**Dependencies** — `lib/deps.ts` + per-ecosystem modules
- npm (`deps.ts`, npm audit bulk endpoint), PyPI (`python-deps.ts`), Go
  (`go-deps.ts`), Ruby (`ruby-deps.ts`), Maven/Gradle (`jvm-deps.ts`), PHP
  Composer (`php-deps.ts`). Non-npm ecosystems resolve CVEs via OSV.dev
  (`lib/osv.ts`).
- Container OS-package CVEs are ingested from a committed Trivy SARIF report
  (`lib/trivy-sarif.ts`).

**Licenses** — `lib/licenses.ts` + `lib/licenses-registry.ts`
- Copyleft/GPL/AGPL/SSPL and missing-license detection; SPDX classified from the
  npm lockfile (no extra calls), deps.dev for other ecosystems.

**Supply chain** — `lib/supply-chain*.ts`
- Typosquatting (`supply-chain-typo.ts`), postinstall scripts for npm
  (`supply-chain-pi-npm.ts`) and Python (`supply-chain-pi-py.ts`), dependency
  confusion, recently-published / suspicious-maintainer signals
  (`supply-chain-registry.ts`).

**Posture** — `lib/posture.ts` + `lib/posture-rulesets.ts`
- Repo posture grade (A–F): branch protection, CODEOWNERS, signed commits,
  Dependabot, secret scanning + push protection, least-privilege `GITHUB_TOKEN`,
  release provenance, ruleset bypass.

**Frameworks / business logic / AI-generated** —
- `lib/framework-rules.ts` + `framework-detect.ts` (Django `DEBUG=True`, Flask
  autoescape/debug, Spring misconfig).
- `lib/biz-logic.ts` (broken access control / IDOR heuristics).
- `lib/ai-insecure.ts` (TODO-auth markers, placeholder creds, unimplemented
  security comments).

### Finding types (lib/types.ts)

`Severity` is `critical | high | medium | low`. Each detector family has its own
finding type: `SecretFinding`, `CodeFinding`, `SensitiveFileFinding`,
`IaCFinding`, `DependencyFinding`, `LicenseFinding`, `RulesetBypassFinding`, plus
`DetectorHealth` for soft-failures. See `lib/types.ts` for the canonical shapes.

---

## Português

### Como a detecção é organizada

Todo detector vive em `lib/` como TypeScript livre de framework, retorna um tipo
de achado de `lib/types.ts` e é invocado pelo pipeline de scan (veja
[ARCHITECTURE.md](ARCHITECTURE.md) §4). Os achados carregam um `ruleId` no formato
`<kind>/<id>`, que é o mesmo vocabulário usado por suppressions e SARIF.

A manchete do produto é **segurança de identidade & CI/CD** (§ Identidade / CI-CD
abaixo). Todo o resto é cobertura de apoio.

### Identidade / CI-CD — o núcleo

Esta é a classe que as ferramentas nativas do GitHub não cobrem. Exige um olhar
de segurança de identidade para ser detectada.

**Privilégio em workflows GitHub Actions** — `lib/iac.ts::scanGithubActions()`

| Regra | Severidade | O que detecta |
|-------|------------|---------------|
| `gha-pull-request-target-checkout` | critical | `pull_request_target` + checkout do head ref do atacante (padrão GhostAction / s1ngularity) |
| `gha-script-injection` | high | Steps `run:` interpolando `${{ github.event.* }}` (título de issue, corpo de PR, head ref) → injeção de shell |
| `gha-hardcoded-secret-env` | high | Secrets literais no `env:` do workflow em vez de `${{ secrets.X }}` |
| `gha-permissions-write-all` | medium | `permissions: write-all` ou bloco ausente → `GITHUB_TOKEN` amplo demais |
| `gha-unpinned-action` | medium | Actions de terceiros não fixadas num commit SHA |

**Trust OIDC** — `lib/iam.ts` + `lib/iam-privesc.ts`
- Relações de trust de IAM role da AWS com o provider OIDC do GitHub sem
  restrição de audience/subject → qualquer repo (público) pode assumir a role.
- Cadeias de escalada de privilégio: OIDC → PassRole + create-compute → execução
  de código.

**Acesso equivalente a admin (IAM)** — `lib/iam-admin.ts`

| Regra | Severidade | O que detecta |
|-------|------------|---------------|
| `iam-action-resource-wildcard` | critical | `Action: *` (ou 3+ `service:*`) com `Resource: *` |
| `iam-principal-wildcard` | critical | `Principal: *` sem condição |
| `iam-sensitive-service-wildcard` | high | Ações iam/kms/secretsmanager/sts com resource curinga |

**Escalada de privilégio (IAM)** — `lib/iam-privesc.ts`

| Regra | Severidade | O que detecta |
|-------|------------|---------------|
| `iam-passrole-wildcard` | critical | `iam:PassRole` com `Resource: *` |
| `iam-passrole-with-create-compute` | critical | PassRole + create-function/ec2/ecs → execução de código |
| `iam-self-managing` | critical | CreatePolicyVersion/SetDefaultPolicyVersion/AttachRolePolicy + `Resource: *` |
| `iam-assume-role-no-condition` | high | AssumeRole sem condição no principal |
| `iam-not-action-allow` | high | `Allow` com `NotAction` (lógica invertida, perigosa) |

O parsing compartilhado de políticas IAM fica em `lib/iam-policy.ts`.

### Cobertura de apoio

**Secrets** — `lib/secret-patterns.ts` (+ `entropy.ts`, opcional
`secret-validation.ts`)
- 50+ padrões de provedores (AWS, Azure, GCP, GitHub, Stripe, npm, …), casados
  linha a linha, mais análise de entropia em strings de alta entropia.
- Validação de liveness opcional (`ENABLE_SECRET_VALIDATION`, só no caminho
  autenticado) sonda se a credencial está viva; alimenta o multiplicador de
  risco.

**Código / SAST** — `lib/code-vulns.ts` (regex) + `lib/ast/rules/*.ts` (AST)
- ~30 regras regex agnósticas de linguagem (SQLi, SSRF, eval, XSS, creds
  hardcoded, cripto fraca, …).
- 27 regras AST sensíveis a control-flow para TS/JS via ts-morph, uma regra por
  arquivo em `lib/ast/rules/`.
- Esta camada é **intencionalmente leve** — não é substituta de CodeQL/Semgrep
  (veja [positioning.md](positioning.md)).

**Arquivos sensíveis** — `lib/sensitive-files.ts`
- ~24 detectores que casam por nome na árvore (`.env*`, keychains, state do
  Terraform, chaves ssh, kubeconfig, `.pgpass`, …) — sem precisar buscar o blob.

**IaC** — além do GitHub Actions acima:
- `lib/iac.ts` — Dockerfile (usuário root, tags `latest`, `curl|sh`,
  ADD-de-URL, chmod 777, base image não fixada, …; lookup de base image em
  `docker-baseimage.ts`).
- `lib/iac-terraform.ts` — HCL (secrets hardcoded, resources curinga, SGs
  permissivos demais, RDS/S3 público, IAM permissivo demais, encryption ausente).
- `lib/iac-k8s.ts` — YAML Kubernetes (containers privilegiados, root, caps
  inseguras, hostNetwork/PID/IPC, token de service-account default/automount).
- `lib/iac-cloudformation.ts` — CFN JSON/YAML (IAM, secrets, resources públicos).
- `lib/iac-helm.ts` — values do Helm.

**Dependências** — `lib/deps.ts` + módulos por ecossistema
- npm (`deps.ts`, endpoint bulk do npm audit), PyPI (`python-deps.ts`), Go
  (`go-deps.ts`), Ruby (`ruby-deps.ts`), Maven/Gradle (`jvm-deps.ts`), PHP
  Composer (`php-deps.ts`). Ecossistemas não-npm resolvem CVEs via OSV.dev
  (`lib/osv.ts`).
- CVEs de pacotes de SO em container são ingeridos de um relatório Trivy SARIF
  commitado (`lib/trivy-sarif.ts`).

**Licenças** — `lib/licenses.ts` + `lib/licenses-registry.ts`
- Detecção de copyleft/GPL/AGPL/SSPL e licença ausente; classificação SPDX a
  partir do lockfile npm (sem chamadas extras), deps.dev para outros
  ecossistemas.

**Supply chain** — `lib/supply-chain*.ts`
- Typosquatting (`supply-chain-typo.ts`), scripts postinstall para npm
  (`supply-chain-pi-npm.ts`) e Python (`supply-chain-pi-py.ts`), dependency
  confusion, sinais de publicação-recente / maintainer-suspeito
  (`supply-chain-registry.ts`).

**Postura** — `lib/posture.ts` + `lib/posture-rulesets.ts`
- Nota de postura do repo (A–F): branch protection, CODEOWNERS, commits
  assinados, Dependabot, secret scanning + push protection, `GITHUB_TOKEN` de
  menor privilégio, provenance de release, bypass de ruleset.

**Frameworks / lógica de negócio / código gerado por IA** —
- `lib/framework-rules.ts` + `framework-detect.ts` (Django `DEBUG=True`, Flask
  autoescape/debug, misconfig de Spring).
- `lib/biz-logic.ts` (heurísticas de broken access control / IDOR).
- `lib/ai-insecure.ts` (marcadores TODO-auth, creds placeholder, comentários de
  segurança não implementados).

### Tipos de achado (lib/types.ts)

`Severity` é `critical | high | medium | low`. Cada família de detector tem seu
tipo de achado: `SecretFinding`, `CodeFinding`, `SensitiveFileFinding`,
`IaCFinding`, `DependencyFinding`, `LicenseFinding`, `RulesetBypassFinding`, mais
`DetectorHealth` para soft-failures. Veja `lib/types.ts` para os tipos
canônicos.
