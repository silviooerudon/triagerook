# TriageRook — Architecture / Arquitetura

> Bilingual document. **English** first, **Português** below (jump to
> [Português](#português)). Companion docs: [DETECTORS.md](DETECTORS.md)
> (detection engine reference) and [DEVELOPMENT.md](DEVELOPMENT.md) (dev guide).
> Product framing lives in [positioning.md](positioning.md).

---

## English

### 1. What this system is

TriageRook is a one-click security scanner for GitHub repositories. A user points
it at a repo; it fetches the repo over the GitHub API, runs a battery of detectors
against the file tree and metadata, scores the result, and renders findings in a
dashboard (or exports them as SARIF for GitHub Code Scanning). The product's core
angle is **CI/CD + identity security** — see [positioning.md](positioning.md).

There is no agent installed in the user's repo and no running application is
tested. All analysis is performed server-side over content fetched from the
GitHub API.

### 2. Stack

| Layer | Technology |
|-------|------------|
| Framework | Next.js 16 (App Router) |
| Language | TypeScript |
| UI | React 19, Tailwind CSS 4 |
| Auth | NextAuth 5, GitHub OAuth (login) + GitHub App (installation tokens, fix PRs) |
| Database | Supabase (PostgreSQL), accessed server-side with the service-role key |
| Tests | Vitest 4 |
| Deploy | Vercel (serverless functions) |

### 3. High-level shape

```
            ┌──────────────────────────────────────────────┐
  Browser → │  app/  (Next.js App Router)                   │
            │   ├─ public pages: /, /about, /security,      │
            │   │                 /docs, /scan-public        │
            │   ├─ /dashboard (auth-gated)                   │
            │   └─ api/ route handlers                       │
            └───────────────┬──────────────────────────────┘
                            │ calls
            ┌───────────────▼──────────────────────────────┐
            │  lib/  (engine — no React, pure TS)           │
            │   scan-pipeline.ts  ← central orchestrator    │
            │     ├─ scan.ts        (repo fetch + core)     │
            │     ├─ deps / iac / iam / supply-chain / …    │
            │     ├─ suppressions   (file + DB)             │
            │     ├─ risk.ts        (scoring)               │
            │     └─ attack-graph.ts                        │
            └───────────────┬──────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        ▼                                        ▼
   GitHub API                               Supabase
   (repo tree, blobs, metadata,            (scans, suppressions,
    installation tokens, fix PRs)           rate-limit state)
```

The hard rule: **detection logic lives in `lib/` and is framework-free.** API
routes are thin — they authenticate, validate input, call into `lib/`, and shape
the HTTP response. This keeps the engine testable under Vitest without spinning up
Next.js.

### 4. The scan pipeline

`lib/scan-pipeline.ts::runFullScan()` is the single orchestrator. Both the
authenticated route (`app/api/scan/[owner]/[repo]`) and the anonymous route
(`app/api/scan-public/[owner]/[repo]`) call it, so a new detector reaches both
paths without editing either. (Historically the two routes were ~90% identical
and silently diverged; centralizing fixed that.)

End-to-end flow:

1. **Input validation** — owner/repo/ref/path are checked with the helpers in
   `lib/path-validation.ts` (`isSafeOwnerRepo`, `isSafeGitRef`,
   `isSafeRepoFilePath`) to prevent GitHub URL injection.
2. **Repo fetch & core scan** — `lib/scan.ts::scanRepo()` fetches repo metadata
   and the git tree, applies the file budget/prioritization
   (`scan-budget.ts`, `scan-priority.ts`), then runs the core detectors in
   parallel: secrets, sensitive files, code vulns (regex + AST), IaC.
3. **Extended detectors** — `runFullScan` fans out (via `Promise.all`) to the
   dependency scanners (npm/PyPI/Go/Ruby/JVM/PHP), container OS-package CVEs
   (Trivy SARIF ingest), licenses, IAM (`iam.ts`/`iam-privesc.ts`/`iam-admin.ts`),
   posture, and supply-chain.
4. **Suppressions** — `.repoguardignore` from the repo plus, for authenticated
   scans, the user's DB suppressions are unioned and applied
   (`suppressions.ts` + `db-suppressions.ts`).
5. **Risk & attack graph** — `risk.ts` computes a compressed 0–100 score;
   `attack-graph.ts` correlates findings into blast-radius paths.
6. **Result** — a `FullScanResult` (see `scan-pipeline.ts:31`) is returned;
   the authenticated route persists it to Supabase, the public route does not.

### 5. Errors, budgets and degraded health

- **Typed errors** bubble up from `scan.ts`: `GitHubRateLimitError`,
  `GitHubRepoNotFoundError`, `PrivateRepoRefusedError`. Callers choose the user
  copy (authenticated vs anonymous messaging differs).
- **Budgets** are env-configurable: `SCAN_MAX_FILES` and `SCAN_MAX_TIME_MS`
  (see `scan-budget.ts`). File prioritization spends the budget on likely-vulnerable
  source before tests/docs.
- **Degraded health** — when an upstream (GitHub, npm registry, OSV.dev) is
  unavailable, a detector returns empty *and* pushes a `DetectorHealth` entry.
  The UI shows a "we skipped X" banner so `0 findings` is never confused with
  "actually clean". The aggregate lives on `FullScanResult.degraded`.

### 6. Auth & GitHub integration

- **Login** uses GitHub OAuth via NextAuth 5 (`auth.ts`). The access token is
  stored in an encrypted HTTP-only cookie, never returned in JSON; read it
  server-side with the `getAccessToken` helper. `session.user.id` is the stable
  numeric GitHub user ID.
- **GitHub App** credentials (`AUTH_GITHUB_APP_*`) mint per-(owner,repo)
  installation tokens (`octokit-app.ts`) used for auto-fix PRs and elevated repo
  access. App ID/Client ID are stable across renames.
- **Public scans** use `PUBLIC_SCAN_GITHUB_TOKEN` (public_repo scope) so
  anonymous scans get the 5000/hr API ceiling instead of 60/hr, and never touch
  user credentials.

### 7. Output: SARIF & suppressions

- **SARIF** (`lib/sarif.ts`, route `/api/scans/[id]/sarif`) emits SARIF 2.1.0.
  Severity maps critical/high→error, medium→warning, low→note; test fixtures are
  demoted to note. `ruleId` is `<kind>/<id>` — the same vocabulary used by
  suppressions. Findings deep-link back to the rule docs on TriageRook.
- **Suppressions** are `(path, rule)` scoped. File source is `.repoguardignore`
  (glob + optional `rule=`, `reason=`, `expires=`); DB source is per-user
  dashboard suppressions. `applySuppressions()` returns kept/suppressed/expired
  counts.

### 8. API routes

| Route | Method | Auth | Purpose |
|-------|--------|------|---------|
| `/api/auth/[...nextauth]` | GET/POST | — | NextAuth OAuth + session |
| `/api/scan/[owner]/[repo]` | POST | yes | Authenticated scan, persisted |
| `/api/scan-public/[owner]/[repo]` | POST | no | Anonymous scan, not persisted |
| `/api/scans` | GET | yes | Recent scans |
| `/api/scans/[id]` | GET/DELETE | yes | Fetch/delete one scan |
| `/api/scans/[id]/sarif` | GET | yes | SARIF 2.1.0 export |
| `/api/scans/diff` | POST | yes | Diff two scans |
| `/api/suppressions` | GET/POST | yes | List/create suppressions |
| `/api/suppressions/[id]` | DELETE/PATCH | yes | Update/delete suppression |
| `/api/findings/fix-preview` | POST | yes | Dry-run auto-fix |
| `/api/findings/fix` | POST | yes | Commit auto-fix PR |

### 9. Risk scoring & attack graph

- **`risk.ts`** — base points per severity (critical 40, high 15, medium 5,
  low 1), then multipliers for context (test fixture ×0.1, transitive dep ×0.5,
  dev-only dep ×0.4, public/HTTP-reachable ×1.3, validated-live secret ×1.5,
  validated-inactive ×0.15, history secret ×0.5). Raw is log-compressed:
  `log10(1 + raw) × 25`, clamped to 100, so big repos don't all saturate.
- **`attack-graph.ts`** — pure analysis over existing findings. Maps credentials
  to blast-radius domains (cloud, scm, payments, data, comms, ai,
  package-registry, observability) and correlates (e.g. live AWS key + public S3 =
  exfil path). No extra I/O.

---

## Português

### 1. O que é este sistema

O TriageRook é um scanner de segurança one-click para repositórios GitHub. O
usuário aponta para um repo; ele busca o repo pela API do GitHub, roda uma
bateria de detectores contra a árvore de arquivos e os metadados, pontua o
resultado e exibe os achados num dashboard (ou exporta como SARIF para o GitHub
Code Scanning). O ângulo central do produto é **CI/CD + segurança de
identidade** — veja [positioning.md](positioning.md).

Não há agente instalado no repo do usuário e nenhuma aplicação em execução é
testada. Toda a análise acontece no servidor sobre o conteúdo buscado na API do
GitHub.

### 2. Stack

| Camada | Tecnologia |
|--------|------------|
| Framework | Next.js 16 (App Router) |
| Linguagem | TypeScript |
| UI | React 19, Tailwind CSS 4 |
| Auth | NextAuth 5, GitHub OAuth (login) + GitHub App (installation tokens, PRs de fix) |
| Banco | Supabase (PostgreSQL), acessado no servidor com a service-role key |
| Testes | Vitest 4 |
| Deploy | Vercel (funções serverless) |

### 3. Forma de alto nível

```
            ┌──────────────────────────────────────────────┐
 Navegador →│  app/  (Next.js App Router)                   │
            │   ├─ páginas públicas: /, /about, /security,  │
            │   │                    /docs, /scan-public     │
            │   ├─ /dashboard (com auth)                     │
            │   └─ api/ route handlers                       │
            └───────────────┬──────────────────────────────┘
                            │ chama
            ┌───────────────▼──────────────────────────────┐
            │  lib/  (motor — sem React, TS puro)           │
            │   scan-pipeline.ts  ← orquestrador central    │
            │     ├─ scan.ts        (fetch do repo + core)  │
            │     ├─ deps / iac / iam / supply-chain / …    │
            │     ├─ suppressions   (arquivo + DB)          │
            │     ├─ risk.ts        (pontuação)             │
            │     └─ attack-graph.ts                        │
            └───────────────┬──────────────────────────────┘
                            │
        ┌───────────────────┴───────────────────┐
        ▼                                        ▼
    API GitHub                              Supabase
   (árvore, blobs, metadados,              (scans, suppressions,
    installation tokens, PRs de fix)        estado de rate-limit)
```

A regra dura: **a lógica de detecção mora em `lib/` e é livre de framework.** As
rotas de API são finas — autenticam, validam input, chamam o `lib/` e moldam a
resposta HTTP. Isso mantém o motor testável sob o Vitest sem subir o Next.js.

### 4. O pipeline de scan

`lib/scan-pipeline.ts::runFullScan()` é o único orquestrador. Tanto a rota
autenticada (`app/api/scan/[owner]/[repo]`) quanto a anônima
(`app/api/scan-public/[owner]/[repo]`) o chamam, então um novo detector alcança
os dois caminhos sem editar nenhum dos dois. (Historicamente as duas rotas eram
~90% idênticas e divergiram silenciosamente; centralizar resolveu isso.)

Fluxo ponta-a-ponta:

1. **Validação de input** — owner/repo/ref/path são checados pelos helpers em
   `lib/path-validation.ts` (`isSafeOwnerRepo`, `isSafeGitRef`,
   `isSafeRepoFilePath`) para prevenir injeção de URL do GitHub.
2. **Fetch do repo & scan core** — `lib/scan.ts::scanRepo()` busca os metadados e
   a árvore git, aplica o orçamento/priorização de arquivos
   (`scan-budget.ts`, `scan-priority.ts`) e roda os detectores core em paralelo:
   secrets, arquivos sensíveis, code vulns (regex + AST), IaC.
3. **Detectores estendidos** — `runFullScan` distribui (via `Promise.all`) para
   os scanners de dependência (npm/PyPI/Go/Ruby/JVM/PHP), CVEs de pacotes de SO
   em container (ingestão de Trivy SARIF), licenças, IAM
   (`iam.ts`/`iam-privesc.ts`/`iam-admin.ts`), postura e supply-chain.
4. **Suppressions** — o `.repoguardignore` do repo mais, em scans autenticados,
   as suppressions de DB do usuário são unidas e aplicadas
   (`suppressions.ts` + `db-suppressions.ts`).
5. **Risco & attack graph** — `risk.ts` calcula um score comprimido de 0–100;
   `attack-graph.ts` correlaciona achados em caminhos de blast radius.
6. **Resultado** — um `FullScanResult` (veja `scan-pipeline.ts:31`) é retornado;
   a rota autenticada persiste no Supabase, a pública não.

### 5. Erros, orçamentos e saúde degradada

- **Erros tipados** sobem do `scan.ts`: `GitHubRateLimitError`,
  `GitHubRepoNotFoundError`, `PrivateRepoRefusedError`. Quem chama escolhe o
  texto pro usuário (mensagem autenticada vs anônima difere).
- **Orçamentos** são configuráveis por env: `SCAN_MAX_FILES` e `SCAN_MAX_TIME_MS`
  (veja `scan-budget.ts`). A priorização gasta o orçamento no código-fonte
  provavelmente vulnerável antes de testes/docs.
- **Saúde degradada** — quando um upstream (GitHub, registry npm, OSV.dev) está
  indisponível, o detector retorna vazio *e* registra uma entrada
  `DetectorHealth`. A UI mostra um banner "pulamos X" pra que `0 achados` nunca
  seja confundido com "realmente limpo". O agregado fica em
  `FullScanResult.degraded`.

### 6. Auth & integração GitHub

- **Login** usa GitHub OAuth via NextAuth 5 (`auth.ts`). O access token é
  guardado num cookie HTTP-only criptografado, nunca retornado em JSON; leia no
  servidor com o helper `getAccessToken`. `session.user.id` é o ID numérico
  estável do usuário GitHub.
- **GitHub App** (`AUTH_GITHUB_APP_*`) emite installation tokens por
  (owner,repo) (`octokit-app.ts`), usados para PRs de auto-fix e acesso elevado.
  App ID/Client ID são estáveis entre renomeações.
- **Scans públicos** usam `PUBLIC_SCAN_GITHUB_TOKEN` (escopo public_repo) pra que
  scans anônimos tenham o teto de 5000/h em vez de 60/h, e nunca toquem em
  credenciais do usuário.

### 7. Saída: SARIF & suppressions

- **SARIF** (`lib/sarif.ts`, rota `/api/scans/[id]/sarif`) emite SARIF 2.1.0.
  Severidade mapeia critical/high→error, medium→warning, low→note; fixtures de
  teste são rebaixados a note. `ruleId` é `<kind>/<id>` — o mesmo vocabulário das
  suppressions. Os achados deep-linkam de volta pros docs de regra no TriageRook.
- **Suppressions** têm escopo `(path, rule)`. A fonte de arquivo é o
  `.repoguardignore` (glob + `rule=`, `reason=`, `expires=` opcionais); a fonte
  de DB são as suppressions por usuário do dashboard. `applySuppressions()`
  retorna contagens de mantidos/suprimidos/expirados.

### 8. Rotas de API

| Rota | Método | Auth | Propósito |
|------|--------|------|-----------|
| `/api/auth/[...nextauth]` | GET/POST | — | OAuth + sessão NextAuth |
| `/api/scan/[owner]/[repo]` | POST | sim | Scan autenticado, persistido |
| `/api/scan-public/[owner]/[repo]` | POST | não | Scan anônimo, não persistido |
| `/api/scans` | GET | sim | Scans recentes |
| `/api/scans/[id]` | GET/DELETE | sim | Buscar/apagar um scan |
| `/api/scans/[id]/sarif` | GET | sim | Export SARIF 2.1.0 |
| `/api/scans/diff` | POST | sim | Diff de dois scans |
| `/api/suppressions` | GET/POST | sim | Listar/criar suppressions |
| `/api/suppressions/[id]` | DELETE/PATCH | sim | Atualizar/apagar suppression |
| `/api/findings/fix-preview` | POST | sim | Auto-fix em dry-run |
| `/api/findings/fix` | POST | sim | Commitar PR de auto-fix |

### 9. Pontuação de risco & attack graph

- **`risk.ts`** — pontos base por severidade (critical 40, high 15, medium 5,
  low 1), depois multiplicadores por contexto (fixture de teste ×0.1, dep
  transitiva ×0.5, dep dev-only ×0.4, público/alcançável por HTTP ×1.3, secret
  validado-vivo ×1.5, validado-inativo ×0.15, secret de histórico ×0.5). O bruto
  é comprimido em log: `log10(1 + bruto) × 25`, limitado a 100, pra que repos
  grandes não saturem todos.
- **`attack-graph.ts`** — análise pura sobre os achados existentes. Mapeia
  credenciais a domínios de blast radius (cloud, scm, payments, data, comms, ai,
  package-registry, observability) e correlaciona (ex.: chave AWS viva + S3
  público = caminho de exfiltração). Sem I/O extra.
