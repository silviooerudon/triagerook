# TriageRook — Development Guide / Guia de Desenvolvimento

> Bilingual document. **English** first, **Português** below (jump to
> [Português](#português)). See [ARCHITECTURE.md](ARCHITECTURE.md) for the system
> shape and [DETECTORS.md](DETECTORS.md) for the detector reference.

---

## English

### 1. Prerequisites

- Node.js (version matching Next.js 16 / React 19 support).
- A Supabase project (URL + service-role key).
- A GitHub OAuth app for login; optionally a GitHub App for installation tokens
  and auto-fix PRs.

### 2. Setup

```bash
npm install
cp .env.example .env.local   # then fill in the values below
npm run dev                  # http://localhost:3000
```

### 3. Environment variables

From `.env.example`:

| Variable | Required | Purpose |
|----------|----------|---------|
| `SUPABASE_URL` | yes | Supabase project URL |
| `SUPABASE_SECRET_KEY` | yes | Service-role key (server-side only) |
| `AUTH_SECRET` | yes | NextAuth session encryption |
| `AUTH_GITHUB_ID` / `AUTH_GITHUB_SECRET` | yes | GitHub OAuth app (login) |
| `AUTH_GITHUB_APP_ID` | for auto-fix | GitHub App ID |
| `AUTH_GITHUB_APP_CLIENT_ID` / `AUTH_GITHUB_APP_CLIENT_SECRET` | for auto-fix | GitHub App OAuth |
| `AUTH_GITHUB_APP_PRIVATE_KEY` | for auto-fix | GitHub App private key (PEM) |
| `AUTH_GITHUB_APP_INSTALLATION_ID` | for auto-fix | Installation lookup |
| `PUBLIC_SCAN_GITHUB_TOKEN` | optional | Raises anonymous-scan API ceiling to 5000/hr (public_repo scope) |
| `PUBLIC_SCAN_LIMIT_PER_IP` | optional | Per-IP anonymous-scan limit |
| `PUBLIC_SCAN_LIMIT_PER_REPO` | optional | Per-repo anonymous-scan limit |
| `ENABLE_SECRET_VALIDATION` | optional | Enables secret liveness probes (authenticated path only) |

Scan budgets `SCAN_MAX_FILES` and `SCAN_MAX_TIME_MS` are also env-configurable
(see `lib/scan-budget.ts`).

**Never** commit `.env` / `.env.local` or any secret. Supabase keys are
service-role — server-side only, never exposed to the client.

### 4. Scripts

| Command | Does |
|---------|------|
| `npm run dev` | Dev server |
| `npm run build` | Production build |
| `npm run start` | Run production build |
| `npm run lint` | ESLint |
| `npm run test` | Vitest, single run |
| `npm run test:watch` | Vitest, watch mode |

### 5. Repo layout

```
app/        Next.js App Router — pages, layouts, api/ route handlers
lib/        the engine — detectors, scan pipeline, risk, SARIF (framework-free TS)
lib/ast/    ts-morph AST rules (one rule per file under lib/ast/rules/)
types/      shared type declarations
scripts/    maintenance / one-off scripts
tests/      Vitest unit tests (*.test.ts)
docs/       this documentation
```

The architectural rule: **detection logic stays in `lib/` and stays
framework-free.** Route handlers in `app/api/` are thin glue (auth → validate →
call `lib/` → shape response). This is what keeps detectors unit-testable without
Next.js.

### 6. Adding a new detector / rule

Two flavours:

**a) A regex / parser detector (most categories)**

1. Add the detection module under `lib/` (or extend the matching one, e.g.
   `iac-terraform.ts`, `code-vulns.ts`).
2. Return the appropriate finding type from `lib/types.ts`. Give each rule a
   stable `ruleId` of the form `<kind>/<id>` — this is the suppression and SARIF
   key, so don't rename it casually.
3. Wire it into the pipeline: core detectors via `lib/scan.ts::scanRepo()`,
   extended detectors via `lib/scan-pipeline.ts::runFullScan()` (add to the
   `Promise.all` fan-out and to `FullScanResult`).
4. Register rule metadata (title, severity, CWE, remediation) so it shows in the
   public catalogue — see `lib/rule-catalog.ts` and the pages under
   `app/docs/rules/`.
5. Add a Vitest test under `tests/` with positive and negative fixtures.
6. If the detector's own definition file would trip another detector (e.g. your
   pattern library contains literal secrets), add a self-reference suppression —
   see `.repoguardignore` and `lib/scanner-self-reference.ts`.

**b) An AST rule (TS/JS, control-flow aware)**

1. Add one file under `lib/ast/rules/` following the existing one-rule-per-file
   pattern (ts-morph walk).
2. Same steps 2–5 above for finding shape, registration and tests.

### 7. Soft-failure discipline

If your detector depends on an external API (GitHub, npm registry, OSV.dev),
**do not** silently return empty on failure. Return empty *and* push a
`DetectorHealth` entry so the UI can tell the user the detector was skipped. A
silent empty reads as "clean" and is a correctness bug. See
`FullScanResult.degraded` and `lib/types.ts::DetectorHealth`.

### 8. Input validation

Any path that takes owner/repo/ref/file from the request must validate with the
helpers in `lib/path-validation.ts` (`isSafeOwnerRepo`, `isSafeGitRef`,
`isSafeRepoFilePath`) before constructing GitHub URLs. This prevents URL
injection.

### 9. Before opening a PR

```bash
npm run lint
npm run test
npm run build
```

All three should pass. The project ships changes via PRs squash-merged to `main`
(see recent history). Match the existing commit-message style.

---

## Português

### 1. Pré-requisitos

- Node.js (versão compatível com Next.js 16 / React 19).
- Um projeto Supabase (URL + service-role key).
- Um GitHub OAuth app para login; opcionalmente um GitHub App para installation
  tokens e PRs de auto-fix.

### 2. Setup

```bash
npm install
cp .env.example .env.local   # depois preencha os valores abaixo
npm run dev                  # http://localhost:3000
```

### 3. Variáveis de ambiente

Do `.env.example`:

| Variável | Obrigatória | Propósito |
|----------|-------------|-----------|
| `SUPABASE_URL` | sim | URL do projeto Supabase |
| `SUPABASE_SECRET_KEY` | sim | Service-role key (só no servidor) |
| `AUTH_SECRET` | sim | Criptografia da sessão NextAuth |
| `AUTH_GITHUB_ID` / `AUTH_GITHUB_SECRET` | sim | GitHub OAuth app (login) |
| `AUTH_GITHUB_APP_ID` | para auto-fix | ID do GitHub App |
| `AUTH_GITHUB_APP_CLIENT_ID` / `AUTH_GITHUB_APP_CLIENT_SECRET` | para auto-fix | OAuth do GitHub App |
| `AUTH_GITHUB_APP_PRIVATE_KEY` | para auto-fix | Chave privada do GitHub App (PEM) |
| `AUTH_GITHUB_APP_INSTALLATION_ID` | para auto-fix | Lookup de installation |
| `PUBLIC_SCAN_GITHUB_TOKEN` | opcional | Eleva o teto de API do scan anônimo pra 5000/h (escopo public_repo) |
| `PUBLIC_SCAN_LIMIT_PER_IP` | opcional | Limite de scan anônimo por IP |
| `PUBLIC_SCAN_LIMIT_PER_REPO` | opcional | Limite de scan anônimo por repo |
| `ENABLE_SECRET_VALIDATION` | opcional | Habilita sondas de liveness de secret (só no caminho autenticado) |

Os orçamentos de scan `SCAN_MAX_FILES` e `SCAN_MAX_TIME_MS` também são
configuráveis por env (veja `lib/scan-budget.ts`).

**Nunca** commite `.env` / `.env.local` nem qualquer secret. As chaves do
Supabase são service-role — só no servidor, nunca expostas ao cliente.

### 4. Scripts

| Comando | Faz |
|---------|-----|
| `npm run dev` | Servidor de dev |
| `npm run build` | Build de produção |
| `npm run start` | Roda o build de produção |
| `npm run lint` | ESLint |
| `npm run test` | Vitest, execução única |
| `npm run test:watch` | Vitest, modo watch |

### 5. Layout do repo

```
app/        Next.js App Router — páginas, layouts, route handlers em api/
lib/        o motor — detectores, pipeline de scan, risco, SARIF (TS sem framework)
lib/ast/    regras AST com ts-morph (uma regra por arquivo em lib/ast/rules/)
types/      declarações de tipo compartilhadas
scripts/    scripts de manutenção / pontuais
tests/      testes unitários Vitest (*.test.ts)
docs/       esta documentação
```

A regra arquitetural: **a lógica de detecção fica em `lib/` e fica livre de
framework.** Os route handlers em `app/api/` são cola fina (auth → validar →
chamar `lib/` → moldar resposta). É isso que mantém os detectores testáveis sem o
Next.js.

### 6. Adicionando um novo detector / regra

Dois tipos:

**a) Detector regex / parser (maioria das categorias)**

1. Adicione o módulo de detecção em `lib/` (ou estenda o correspondente, ex.:
   `iac-terraform.ts`, `code-vulns.ts`).
2. Retorne o tipo de achado apropriado de `lib/types.ts`. Dê a cada regra um
   `ruleId` estável no formato `<kind>/<id>` — é a chave de suppression e SARIF,
   então não renomeie sem cuidado.
3. Ligue ao pipeline: detectores core via `lib/scan.ts::scanRepo()`, detectores
   estendidos via `lib/scan-pipeline.ts::runFullScan()` (adicione ao fan-out do
   `Promise.all` e ao `FullScanResult`).
4. Registre os metadados da regra (título, severidade, CWE, remediação) pra
   aparecer no catálogo público — veja `lib/rule-catalog.ts` e as páginas em
   `app/docs/rules/`.
5. Adicione um teste Vitest em `tests/` com fixtures positivos e negativos.
6. Se o próprio arquivo de definição do detector dispararia outro detector (ex.:
   sua biblioteca de padrões contém secrets literais), adicione uma suppression
   de auto-referência — veja `.repoguardignore` e `lib/scanner-self-reference.ts`.

**b) Regra AST (TS/JS, sensível a control-flow)**

1. Adicione um arquivo em `lib/ast/rules/` seguindo o padrão de uma-regra-por-
   arquivo (walk com ts-morph).
2. Mesmos passos 2–5 acima para tipo de achado, registro e testes.

### 7. Disciplina de soft-failure

Se o seu detector depende de uma API externa (GitHub, registry npm, OSV.dev),
**não** retorne vazio silenciosamente em caso de falha. Retorne vazio *e*
registre uma entrada `DetectorHealth` pra UI poder avisar que o detector foi
pulado. Um vazio silencioso é lido como "limpo" e é um bug de correção. Veja
`FullScanResult.degraded` e `lib/types.ts::DetectorHealth`.

### 8. Validação de input

Qualquer caminho que receba owner/repo/ref/arquivo da requisição precisa validar
com os helpers em `lib/path-validation.ts` (`isSafeOwnerRepo`, `isSafeGitRef`,
`isSafeRepoFilePath`) antes de construir URLs do GitHub. Isso previne injeção de
URL.

### 9. Antes de abrir um PR

```bash
npm run lint
npm run test
npm run build
```

Os três devem passar. O projeto entrega mudanças via PRs squash-merged na `main`
(veja o histórico recente). Siga o estilo de mensagem de commit existente.
