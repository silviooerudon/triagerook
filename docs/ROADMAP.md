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

### 1.2 Kubernetes / Helm IaC scanner
- **O quê:** container como root, `privileged: true`, `hostNetwork`,
  `allowPrivilegeEscalation`, secrets em ConfigMap, `securityContext` ausente,
  imagens `:latest`, capabilities perigosas.
- **Onde:** `lib/iac-k8s.ts`, dispatch por arquivo YAML com `kind:` k8s.
  Adicionar `"kubernetes"` ao `IaCCategory`.
- **Cuidado:** YAML multi-doc (`---`) e Helm templates (`{{ }}`) — no MVP,
  pular arquivos que são template puro Helm.
- **Esforço:** M.

### 1.3 Licenças open source
- **O quê:** GPL/AGPL/copyleft, pacotes sem licença, conflito de compatibilidade.
- **Onde:** estender os detectores de deps (`lib/deps.ts` etc.) — o registro
  npm/PyPI já retorna `license` no metadata; OSV não, então cruzar com
  `registry.npmjs.org/<pkg>`. Novo tipo `LicenseFinding` + categoria.
- **Esforço:** M. **Dependência:** 1 chamada extra de API por pacote (cachear).

---

## Fase 2 — Diferencial #1: Validação de secrets (corta falso-positivo)

### 2.1 Secret validation engine
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

---

## Fase 3 — Diferencial #2: IAM/permissões dentro do código

### 3.1 IAM-in-code scanner
- **O quê:** detectar excesso de permissão *no código/config*, não só no GitHub:
  - AWS IAM policy com `"Action": "*"` / `"Resource": "*"` (em `.tf`, `.json`, SDK)
  - GCP service account com roles amplos (`roles/owner`, `roles/editor`)
  - Azure Managed Identity mal escopada
  - `GITHUB_TOKEN` / PAT com escopo amplo pedido no código
- **Onde:** complementa 1.1 (Terraform) e o IAM atual de org/repo
  ([`lib/iam.ts`](../lib/iam.ts)). Novo `lib/iam-policy.ts` reusando o parser
  de 1.1 + detector JSON para policies inline.
- **Esforço:** M (depende de 1.1). Fica natural construir junto com Terraform.

---

## Fase 4 — Diferencial #3: Context-aware SAST

### 4.1 Framework detection + regras específicas
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

---

## Fase 5 — Diferencial #4: Blast radius & Attack graph

> Depende de 2.1 (validação) e 3.1 (IAM-in-code) estarem maduros. É o topo da
> pirâmide — maior esforço, maior diferenciação.

### 5.1 Blast radius por finding
- **O quê:** "essa AWS key dá acesso a S3 prod", "esse GitHub token pode push".
  Derivado da validação: ao validar (2.1), capturar o **escopo/permissões**
  retornado e anexar ao finding.
- **Onde:** estende `secret-validation.ts` → `blastRadius?: string[]`.
- **Esforço:** M (em cima de 2.1).

### 5.2 Attack graph do repositório
- **O quê:** caminho `secret vazado → acesso cloud → bucket prod → dados`.
  Grafo ligando findings (secret ativo) → recursos (do IaC/IAM) → impacto.
- **Onde:** novo `lib/attack-graph.ts` que consome o `FullScanResult` agregado
  e produz arestas; UI nova no dashboard.
- **Esforço:** XL. Tratar como épico próprio depois das fases 2-3.

---

## Fora de escopo por enquanto (registrar e revisitar)

- **Scanner de lógica de negócio** (IDOR, role escalation, bypass de aprovação,
  fluxo de pagamento): altíssimo valor, mas exige análise semântica profunda /
  LLM. Candidato a um épico de pesquisa separado, provavelmente assistido por IA.
- **Detector dedicado de "código inseguro gerado por IA":** hoje coberto só por
  regras pontuais. Reavaliar se vira família própria depois da Fase 4.

---

## Ordem sugerida de execução

1. **1.1 Terraform** → fecha o maior gap do obrigatório e destrava 3.1/5.1.
2. **2.1 Validação de secrets (GitHub+AWS+Stripe)** → corte brutal de FP, é o
   "uau" mais barato para o usuário.
3. **1.2 Kubernetes** → completa o IaC.
4. **3.1 IAM-in-code** → reusa parser do Terraform.
5. **1.3 Licenças** → compliance, fecha 100% do obrigatório.
6. **4.1 Context-aware SAST** → família incremental, roda em paralelo às outras.
7. **5.1 / 5.2 Blast radius + Attack graph** → épico final de diferenciação.

Cada item: 1 branch, testes em `tests/`, catálogo de regras + README + `/docs/rules`
atualizados, e checagem de que entra tanto no scan autenticado quanto no público
(ambos passam por `runFullScan`).
