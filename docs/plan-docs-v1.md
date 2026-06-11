# Plan — Documentação técnica completa em /docs (v1)

Status: em execução. Lançamento de distribuição seg 15/06.
Branch desta fase: `feat/docs-pr1`.

## Objetivo

Documentação como página web dentro do produto (rota `/docs` no próprio Next.js)
+ links no GitHub. Público: devs céticos de segurança — a documentação é prova de
confiança, não manual.

## Regra central — a fonte da verdade é o CÓDIGO

Toda claim factual é derivada do código real e verificada antes de escrever. Onde
o código e o briefing original divergiram, **o código venceu** e a divergência está
registrada abaixo (conforme instruído).

## Decisões técnicas tomadas

- **Formato do conteúdo:** páginas TSX (React Server Components), NÃO MDX. Justificativa:
  as páginas existentes de docs (`/docs/rules`, `/docs/sarif`) já são TSX com o design
  system da landing; um parser MDX seria dependência nova sem ganho — o briefing pede
  evitar deps pesadas. Zero dependência nova. TypeScript strict.
- **Infra:** `app/docs/layout.tsx` provê a sidebar fixa (colapsável no mobile) + área de
  conteúdo. As páginas existentes `/docs/rules` e `/docs/sarif` foram integradas ao shell
  (removido o `PublicNav` que cada uma renderizava por conta própria, para não duplicar).
- **`/docs/detectors` (PR 2):** ~10 detectores de alto nível, cada um linkando para as
  regras reais em `/docs/rules` (alinha com o README, que diz "ten independent
  detectors"). Decisão do mantenedor.
- **Auth na página de segurança:** documentar o modelo real (GitHub App), não "scopes
  OAuth". Decisão do mantenedor.
- **Commits:** sem `-S` neste ambiente (sem chave GPG no Codespace). Decisão do mantenedor.

## Divergências verificadas (briefing × código)

| Item | Briefing | Código (fonte da verdade) | Bate? |
|---|---|---|---|
| Limite de arquivos | 300 | default **1000**, cap 10000 (`SCAN_MAX_FILES`, `lib/scan-budget.ts`) | ✗ |
| Tempo de scan | 45s | default **55s**, cap 290s; timeout Vercel **Hobby 60s / Pro 300s** | ✗ |
| Tamanho máx. arquivo | 1MB | 1MB (`MAX_FILE_SIZE = 1_000_000`, `lib/scan.ts`) | ✓ |
| Commits de histórico | 30 | 30 (`HISTORY_COMMIT_LIMIT`, `lib/product-constants.ts`) | ✓ |
| Patch máx. | 200KB | 200KB (`MAX_PATCH_SIZE = 200_000`, `lib/history.ts`) | ✓ |
| Sinais de posture | 14 | **17** (`POSTURE_SIGNAL_COUNT = 17`; branch 4 + docs 5 + deps 3 + governance 5) | ✗ |
| Modelo de auth | scopes OAuth (`public_repo`; `read:org`) | **GitHub App**, sem `scope`. Permissões do App: **Contents read+write, Pull requests write, Email read, Metadata read** (`auth.ts`) | ✗ |
| SAST | "regex-based, não AST" | **AST** (28 regras TS/JS via TS Compiler API / ts-morph) **+** regex p/ outras linguagens | ✗ |
| Nº de detectores | 9 | README: "ten independent detectors"; root metadata diz "Nine detectors" (inconsistência interna); catálogo: 14 layers | ✗ |
| Endpoint público persiste | nada | nada — só contadores de rate-limit + 1 log stdout (sem PII/IP) | ✓ |
| Endpoint autenticado persiste | resultados no Supabase | result completo na tabela `scans` | ✓ |
| Secrets mascarados antes de persistir | sim | sim (`maskLine`; raw transitório, nunca persistido) | ✓ |

### Notas de nuance
- **`read:org`** NÃO é usado pelo IAM risk scanner (file-based, escaneia policy docs no
  código). É necessário só para o sinal `mfa-org` do posture (ler
  `two_factor_requirement_enabled` da org). Sem ele → sinal `unknown`, pontos retidos,
  nunca penalizado silenciosamente. (afeta PR 3)
- **Recusa de repos privados:** o endpoint autenticado lança `PrivateRepoRefusedError`
  antes de qualquer fetch — a promessa "só repos públicos" é verdadeira no código.
- **Rate limits anônimos:** 10/hora por IP, 5/hora por repo (janela de 60min,
  `lib/rate-limit.ts`).
- **Inconsistência interna do produto:** root metadata (`app/layout.tsx`) diz "Nine
  detectors"; README diz "ten independent detectors". Fora do escopo de docs (read-only);
  reportado ao mantenedor.

## Escopo — 3 PRs sequenciais

### PR 1 (esta branch) — infra + páginas de confiança
- Infra `/docs` (sidebar, mobile, estática) + sitemap + metadata por página.
- `/docs` (hub/overview)
- `/docs/security-and-data-handling`
- `/docs/scan-limits`
- `/docs/suppressions`

### PR 2 — referência dos detectores
- `/docs/detectors` (índice ~10 + link p/ regras reais)
- `/docs/posture-score` (17 sinais, grupos, pesos, escala, caso unknown)

### PR 3 — IAM deep-dive + onboarding + manutenção
- `/docs/iam-risk-scanner`, `/docs/quickstart`, `/docs/faq`, `/docs/changelog`
- README (seção Documentation) + `SECURITY.md` apontando p/ `/docs/security-and-data-handling`

## Workflow por PR
1. Branch a partir de main atualizada.
2. `npm run build` antes de cada commit.
3. Commit (sem `-S` neste ambiente), push, PR, Vercel preview, validar visual desktop+mobile.
4. Merge só via "Create a merge commit".
5. Cleanup de branch por último, pós-merge.
6. Não iniciar PR 2 antes do merge do PR 1.

## Restrições
- TS strict, espelhar patterns existentes. ASCII em código, sem emoji novo.
- Visual: fundo neutro (slate-950/900) + barra lateral 3px colorida p/ callouts. Seguir o
  design system da landing (amber-400 accent, font-display/font-mono).
- Não tocar em auth, endpoints de scan ou detectores. Documentação é leitura.
