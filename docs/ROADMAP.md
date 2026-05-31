# TriageRook — Roadmap de detecção

> Plano de implementação incremental. Cada item é uma unidade entregável
> (1 PR), com onde encaixa no código, esforço e dependências. Ordem pensada
> para maximizar valor/custo: primeiro fecha gaps baratos do "obrigatório",
> depois ataca os diferenciais reais de mercado.

Arquitetura de plug-in (referência rápida):

- **Detector por arquivo** (lê conteúdo de cada blob): dispatch em
  [`lib/scan.ts`](../lib/scan.ts) (`isDockerfilePath` / `isActionsWorkflowPath`
  ~L511) + registrar extensões em `SCANNABLE_EXTENSIONS` (~L123). Emite
  `IaCFinding[]` / `CodeFinding[]` / `SecretFinding[]`.
- **Detector por repo** (chamadas à API, agregação): adicionar ao
  `Promise.all` em [`lib/scan-pipeline.ts`](../lib/scan-pipeline.ts) (~L84) e
  expor no `FullScanResult`.
- Todo finding novo precisa: tipo em [`lib/types.ts`](../lib/types.ts),
  flatten/score em [`lib/risk.ts`](../lib/risk.ts), entrada no catálogo
  [`lib/rule-catalog.ts`](../lib/rule-catalog.ts), e mapeamento SARIF em
  [`lib/sarif.ts`](../lib/sarif.ts).
- Cada PR novo: testes em `tests/`, e atualizar `/docs/rules` + README.

---

## Fase 1 — Fechar o "obrigatório" (baixo custo, alto sinal)

### 1.1 Terraform IaC scanner ✅ FEITO (2026-05-28)
- **O quê:** bucket S3 público, security group `0.0.0.0/0`, IAM policy `*:*`,
  RDS sem encryption, DB publicamente acessível.
- **Entregue:** [`lib/iac-terraform.ts`](../lib/iac-terraform.ts) (`scanTerraform`,
  `isTerraformPath`, 7 regras), dispatch em [`lib/scan.ts`](../lib/scan.ts),
  registro em [`lib/rule-catalog.ts`](../lib/rule-catalog.ts) (layer
  `iac-terraform` + resolver SARIF), blurb em `app/docs/rules/page.tsx`, e
  [`tests/iac-terraform.test.ts`](../tests/iac-terraform.test.ts) (16 testes).
  `.tf`/`.tfvars` já estavam em `SCANNABLE_EXTENSIONS`.
- **Parsing:** MVP por linha/heurística; o único caso com contexto de bloco
  (ingress vs egress) usa um contador de chaves local. Evoluir para parser HCL
  real (`@cdktf/hcl2json` / wasm) só se a precisão exigir.
- **Não coberto de propósito:** hardcoded secrets em `.tf` — já cobertos pelos
  detectores de secret/entropia (evita double-report).

### 1.2 Kubernetes / Helm IaC scanner ✅ FEITO (PR #90)
- **O quê:** container como root, `privileged: true`, `hostNetwork`,
  `allowPrivilegeEscalation`, secrets em ConfigMap, `securityContext` ausente,
  imagens `:latest`, capabilities perigosas.
- **Entregue:** [`lib/iac-k8s.ts`](../lib/iac-k8s.ts) (`scanKubernetes`, 6 regras),
  identificação por conteúdo via `looksLikeKubernetesManifest` (`apiVersion:` +
  `kind:`), multi-doc aware, pula linhas de template Helm (`{{ }}`).
  `"kubernetes"` adicionado ao `IaCCategory`; testes em
  [`tests/iac-k8s.test.ts`](../tests/iac-k8s.test.ts).

### 1.3 Licenças open source ✅ FEITO (PR #91)
- **O quê:** GPL/AGPL/copyleft, pacotes sem licença, proprietário/UNLICENSED.
- **Entregue:** [`lib/licenses.ts`](../lib/licenses.ts) (`classifyLicense` +
  `scanNpmLicenses`) — lê o campo `license` das entradas `packages` do
  `package-lock.json`, **zero rede**; dev deps puladas; expressão `OR` com escape
  permissivo → ignorada. Novos tipos `LicenseFinding`/`LicenseRisk`.
- **Pendente (follow-up):** estender para PyPI / Go / RubyGems.

---

## Fase 2 — Diferencial #1: Validação de secrets (corta falso-positivo)

### 2.1 Secret validation engine ✅ FEITO (PR #92) — desligado por padrão
- **Entregue:** [`lib/secret-validation.ts`](../lib/secret-validation.ts)
  (`validateSecrets`, `isSecretValidationEnabled`, `isVerifiable`). Validadores:
  GitHub / GitLab / OpenAI / Anthropic / Stripe / SendGrid / Slack / npm; AWS =
  `unverifiable`. `SecretFinding.validation?: "active" | "inactive" |
  "unverifiable" | "error" | "skipped"`. Secret `active` → boost em
  [`lib/risk.ts`](../lib/risk.ts) (`ACTIVE_SECRET_MULTIPLIER`).
- **Gating de segurança:** duplo gate — env `ENABLE_SECRET_VALIDATION=true`
  **E** flag por-chamada `allowSecretValidation` (só na rota autenticada, nunca
  no path público). O valor do secret nunca é logado nem persistido — só o status.
- **Para ativar em prod:** setar `ENABLE_SECRET_VALIDATION=true` na Vercel +
  redeploy (ver passo a passo já entregue ao time).

<details><summary>Especificação original (mantida para referência)</summary>

- **O quê:** dado um secret detectado, dizer se **ainda está ativo** sem expor
  o valor — chamada read-only mínima ao provedor.
  - GitHub token → `GET /user` (ou `/rate_limit`)
  - AWS key → `sts:GetCallerIdentity`
  - Stripe → `GET /v1/balance`
  - OpenAI/Anthropic → endpoint de modelos
  - Slack webhook → não validar (side-effect); marcar "não verificável"
- **Onde:** novo `lib/secret-validation.ts` com um registry
  `patternId -> validator`. Roda **depois** do scan de secrets, opt-in por
  finding (latência + rede saindo pra terceiros).
- **Modelo de finding:** adicionar a `SecretFinding`:
  `validation?: "active" | "inactive" | "unverifiable" | "skipped"`.
- **Risco/priorização:** secret `active` → boost para `critical` em
  [`lib/risk.ts`](../lib/risk.ts) / [`lib/scan-priority.ts`](../lib/scan-priority.ts).
- **Decisões a tomar antes:** (a) validar no server (nosso IP) vs side-channel;
  (b) opt-in explícito do usuário (estamos batendo em APIs com credencial alheia
   — implicações legais/ToS); (c) rate-limit e timeout agressivos.
- **Esforço:** L (1 validador por provedor, incremental). Começar com
  GitHub + AWS + Stripe (maior volume de leaks).

</details>

---

## Fase 3 — Diferencial #2: IAM/permissões dentro do código

### 3.1 IAM-in-code scanner ✅ FEITO (PR #93, refinado #96/#97)
- **Entregue:** [`lib/iam-policy.ts`](../lib/iam-policy.ts) — regras de policy AWS
  (exigem contexto `Statement` + `Effect`) + roles amplos GCP (`roles/owner`,
  `roles/editor`). Refinado em #96 (exige contexto de atribuição p/ `roles/owner`,
  pula `.tf/.tfvars/.md/.txt`) e #97 (de-prioriza findings em paths de
  teste/fixture). Testes em [`tests/iam-policy.test.ts`](../tests/iam-policy.test.ts).

<details><summary>Especificação original (mantida para referência)</summary>

- **O quê:** detectar excesso de permissão *no código/config*, não só no GitHub:
  - AWS IAM policy com `"Action": "*"` / `"Resource": "*"` (em `.tf`, `.json`, SDK)
  - GCP service account com roles amplos (`roles/owner`, `roles/editor`)
  - Azure Managed Identity mal escopada
  - `GITHUB_TOKEN` / PAT com escopo amplo pedido no código
- **Onde:** complementa 1.1 (Terraform) e o IAM atual de org/repo
  ([`lib/iam.ts`](../lib/iam.ts)). Novo `lib/iam-policy.ts` reusando o parser
  de 1.1 + detector JSON para policies inline.
- **Esforço:** M (depende de 1.1). Fica natural construir junto com Terraform.

</details>

---

## Fase 4 — Diferencial #3: Context-aware SAST

### 4.1 Framework detection + regras específicas ✅ FEITO (PR #94)
- **Entregue:** [`lib/framework-detect.ts`](../lib/framework-detect.ts)
  (`detectFrameworks` a partir dos manifests) + [`lib/framework-rules.ts`](../lib/framework-rules.ts)
  (12 regras gated por framework: Django/Flask/FastAPI/Express/NestJS/Spring/
  Laravel/Rails). `"framework"` adicionado a `CodeVulnCategory`; layer `framework`
  no catálogo (id `code/<id>`). Contexto de frameworks passado ao `scanFile`.

<details><summary>Especificação original (mantida para referência)</summary>

- **O quê:** entender Next.js / Express / Django / Spring / Laravel / NestJS e
  rodar regras de framework, não só AST genérico.
- **Onde:** novo `lib/framework-detect.ts` (lê `package.json` /
  `requirements.txt` / `pom.xml` → set de frameworks ativos). Passar o contexto
  para o runner AST ([`lib/ast/runner.ts`](../lib/ast/runner.ts)) e gatear
  regras novas por framework em `lib/ast/rules/`.
- **Exemplos de regra:** Next.js Server Action sem authz, Express route sem
  middleware de auth, Django view sem `@login_required`, mass-assignment.
- **Esforço:** L (é uma família que cresce regra a regra). Entregar a infra de
  detecção de framework primeiro, depois 2-3 regras de alto valor por framework.

</details>

---

## Fase 5 — Diferencial #4: Blast radius & Attack graph ✅ FEITO (PR #95)

**Entregue:** [`lib/attack-graph.ts`](../lib/attack-graph.ts)
(`blastRadiusForSecret`, `buildAttackGraph`) — análise pura sobre os findings já
coletados (sem I/O extra), roda em todo scan. Correlaciona secret + exposição
cloud (IaC) → caminhos de ataque encadeados críticos; lê `validation`
defensivamente (secret confirmado vivo eleva o caminho a `critical`); pula infra
de teste/fixture (#97). Anexado a `fullResult.attackGraph`; UI no dashboard.

<details><summary>Especificação original (5.1 + 5.2, mantida para referência)</summary>

### 5.1 Blast radius por finding
- **O quê:** "essa AWS key dá acesso a S3 prod", "esse GitHub token pode push".
- **Nota:** implementado como mapa estático `patternId → BlastRadius` (domínio +
  capability + assets) em vez de capturar escopo da validação — funciona sem
  depender de a validação estar ligada.

### 5.2 Attack graph do repositório
- **O quê:** caminho `secret vazado → acesso cloud → bucket prod → dados`.

</details>

---

## Fora de escopo originalmente (registrado aqui, depois entregue)

- **Scanner de lógica de negócio** (IDOR, role escalation, bypass de aprovação,
  fluxo de pagamento): foi marcado como "exige análise semântica profunda / LLM",
  mas entregamos um MVP heurístico de alto sinal (PR #99) — ver follow-ups. Uma
  versão assistida por LLM continua sendo candidato futuro para cobertura mais rica.
- **Detector dedicado de "código inseguro gerado por IA":** virou família própria
  (PR #100) — ver follow-ups.

---

## Ordem de execução — ✅ todas as fases entregues (PRs #89–#97)

1. ✅ **1.1 Terraform** (PR #89)
2. ✅ **1.2 Kubernetes** (PR #90)
3. ✅ **1.3 Licenças npm** (PR #91)
4. ✅ **2.1 Validação de secrets** (PR #92, desligado por padrão)
5. ✅ **3.1 IAM-in-code** (PR #93, refinado #96/#97)
6. ✅ **4.1 Context-aware SAST** (PR #94)
7. ✅ **5.1/5.2 Blast radius + Attack graph** (PR #95)

Cada item: 1 branch, testes em `tests/`, catálogo de regras + README + `/docs/rules`
atualizados, e checagem de que entra tanto no scan autenticado quanto no público
(ambos passam por `runFullScan`).

---

## Follow-ups — todos entregues ✅

- ✅ **Licenças PyPI / Go / RubyGems** (PR #101) — [`lib/licenses-registry.ts`](../lib/licenses-registry.ts)
  (`scanRegistryLicenses`). Os lockfiles desses ecossistemas não carregam
  licença (ao contrário do npm), então enriquece via **deps.dev** (Google Open
  Source Insights, mesma natureza benigna do OSV.dev): 1 GET por (pacote,
  versão), bounded — cap global de 200 pacotes, concorrência 8, timeout 5s,
  degradação graciosa (`DetectorHealth "license-registry"`) e nota explícita
  quando o cap trunca. Reusa `classifyLicense`. Parsers Python exportados.
- ✅ **Scanner de lógica de negócio** (PR #99) — [`lib/biz-logic.ts`](../lib/biz-logic.ts):
  IDOR, mass assignment, privilege escalation, payment tampering. Categorias
  `access-control`/`business-logic`, layer `business-logic`.
- ✅ **Detector de código inseguro gerado por IA** (PR #100) — [`lib/ai-insecure.ts`](../lib/ai-insecure.ts):
  credenciais placeholder, segurança adiada via TODO, disclaimers
  "não-é-pra-produção", exceções engolidas. Categoria/layer `ai-generated`
  (único layer que escaneia comentários).

---

## Onda de fechamento de gaps de mercado — entregue ✅ (PRs #107–#110)

Auditoria cruzando a lista "o que um scanner de repositório precisa cobrir"
(3 tiers) contra a base. Tudo que faltava foi fechado:

- ✅ **SCA Maven/Gradle + Composer** (PR #107) — núcleo OSV compartilhado
  ([`lib/osv.ts`](../lib/osv.ts)) + [`lib/jvm-deps.ts`](../lib/jvm-deps.ts)
  (`pom.xml`/`build.gradle` → OSV `Maven`) + [`lib/php-deps.ts`](../lib/php-deps.ts)
  (`composer.lock` → OSV `Packagist`).
- ✅ **Docker base-image EOL** (PR #107) — [`lib/docker-baseimage.ts`](../lib/docker-baseimage.ts).
  Proxy estático do "CVE de imagem"; ampliado com Ubuntu LTS jammy/noble (PR #108).
- ✅ **CloudFormation** (PR #107) — [`lib/iac-cloudformation.ts`](../lib/iac-cloudformation.ts)
  (YAML+JSON, espelha as regras do Terraform).
- ✅ **Helm dedicado** (PR #109) — [`lib/iac-helm.ts`](../lib/iac-helm.ts)
  (defaults inseguros em `values*.yaml`, que o scanner K8s pula).
- ✅ **Supply-chain registry-backed** (PR #107) — dependency-confusion,
  recently-published, suspicious-maintainer ([`lib/supply-chain-registry.ts`](../lib/supply-chain-registry.ts)).
- ✅ **Posture extras** (PR #107) — secret-scanning + push-protection,
  least-privilege do `GITHUB_TOKEN`, release provenance; score renormalizado
  para "percentual dos sinais avaliáveis".
- ✅ **IAM Azure + GitHub** (PR #107) — Azure RBAC Owner/Contributor + custom
  wildcard, e escopos amplos de OAuth/PAT do GitHub ([`lib/iam-policy.ts`](../lib/iam-policy.ts));
  forma CLI `--scope` adicionada (PR #108).
- ✅ **Priorização de risco** (PR #107) — desconto dev-dep + boost de rota
  pública em [`lib/risk.ts`](../lib/risk.ts).
- ✅ **Fix-engines novos** (PR #109) — secret hardcoded em workflow `env:`;
  e auto-PR de bump de base-image EOL + `permissions: write-all` →
  least-privilege ([`lib/fix-engines/`](../lib/fix-engines/)).
- ✅ **Ingestão de Trivy SARIF** (PR #110) — CVE de pacote de SO da imagem,
  via relatório commitado ([`lib/trivy-sarif.ts`](../lib/trivy-sarif.ts),
  [`docs/container-scanning.md`](./container-scanning.md)).

> Status: as 5 fases do roadmap + os 3 follow-ups + a onda de fechamento de
> gaps (#107–#110) estão implementados. A lista de mercado (3 tiers) está
> integralmente coberta. O que resta é a **camada de comercialização**
> (monitoramento contínuo via webhook, contas de time, repos privados,
> billing) — não cobertura de detecção. Candidatos não planejados que seguem
> de fora: análise de lógica de negócio assistida por LLM; CVE de layer via
> scanner próprio (hoje feito por ingestão de Trivy, sem infra nossa).
