# RepoGuard - Briefing: Cleanup #2 (post-Bloco-2)

Sessao planejada: 4 commits sequenciais. Branch: main.

## Contexto

Apos fechar Bloco 2 inteiro em 8/maio (4 features grandes + cleanup #1 = 9 commits no dia), iniciamos cleanup #2 pra fechar bugs UX residuais e completar a `view/[id]` que ainda nao acompanhou Bloco 2.

## Itens incluidos

### Fix 1 - view/[id] consolidacao (esforco grande)

`app/dashboard/scan/view/[id]/page.tsx` mostra historico de scan, mas estava parado na pre-Bloco-2: so secrets/deps/IaC sections. Faltava Risk gauge, PostureCard, IamCard, SupplyChainCard - exatamente as features fechadas hoje. Resultado: usuario logado que abre um scan antigo ve um produto pela metade.

Mudancas:
- `app/api/scans/[id]/route.ts`: select expandido pra 12 colunas adicionais (`risk_score, suppressed_count, posture_*, iam_*, supply_chain_*`). Re-compute server-side de `flattenScan` + `scoreRepo` sobre o `result` JSONB pra produzir `riskBreakdown` + `prioritized`. Reconstroi os 3 nested objects (`posture`, `iam`, `supplyChain`) a partir das colunas dedicadas.
- `app/dashboard/scan/view/[id]/page.tsx`: estrutura visual espelhando o live scan. Header com data + duracao + files. Summary row. RiskGauge + RiskBreakdownChart card. PostureCard / IamCard / SupplyChainCard (renderizados condicionalmente - scan antigo sem essas colunas omite). ViewToggleButton + PrioritizedList alternativa.

Decisao de produto: scans antigos pre-Bloco-2 que nao tem Posture v2 / IAM / SupplyChain renderizam tudo o que tem, sem placeholder visual extra. Cards faltantes simplesmente nao aparecem (decisao A do single-select). Risk gauge sempre aparece (re-computavel do JSONB). Sections legacy sempre aparecem.

Tradeoff conhecido (anotado no codigo): o re-compute de `scoreRepo` no /api/scans/[id] roda sobre TODOS os findings do `result` JSONB, incluindo os que foram suprimidos por `.repoguardignore` na hora do scan. O `risk_score` persistido foi calculado apos suppression. Em scans com suppressions ativas, o score do view/[id] pode ser ligeiramente maior que o score original. Aceitavel pra MVP. Backlog: persistir `risk_breakdown` + `prioritized` em colunas dedicadas pra eliminar o drift.

Approximations conhecidas (nao persistidas no DB):
- `IAMResult.filesScanned` reconstruido como 0 (footer "across 0 files" indica indiretamente que dado historico nao tem)
- `SupplyChainResult.scanned.{packageJsonCount, setupPyCount, ...}` reconstruido como 0
- `PostureResult.degraded` reconstruido como `false` (campo nao usado em UI atual)

### Fix 2 - CORS warning github oauth no scan publico anonimo

`app/scan-public/[owner]/[repo]/page.tsx` tem 3 `<Link href="/signin">`. NextJS faz prefetch desses Links em background. O `/signin` faz `redirect()` server-side que vai pra `/api/auth/signin/github`, que por sua vez emite redirect 302 pra `https://github.com/login/oauth/authorize?...`. **O prefetch segue redirects** -> tenta fetch cross-origin pra GitHub -> CORS preflight bloqueado pelo browser.

Fix: adicionar `prefetch={false}` nos 3 `<Link href="/signin">` da scan-public page. Stop o speculative fetch. Zero impacto UX (redirect ainda funciona ao clicar normalmente).

### Fix 3 - "Seven detectors" residual em README.md + AGENTS.md

3 ocorrencias detectadas via git grep:
- `README.md:5` - "across seven detectors"
- `README.md:15` - "runs seven independent detectors"
- `AGENTS.md:74` - "7 detectors run in parallel"

Atualizar pra "nine" / "9". Sub-issue noted (defer): a prosa do README lista textualmente apenas 7 detectores no nome ("secrets, sensitive files, code-level vulns, npm/PyPI deps, supply-chain misconfigs, git history") - falta IAM e Posture. Se quiser refletir os 9 reais, e edicao maior. Nao incluida neste cleanup.

### Fix 4 - postcss duplicate "Vulnerable versions" - DEFERRED

Sem print do bug em prod, fix seria adivinhacao. Documentado no backlog. Provavel causa: `npm audit bulk` retorna multiplas advisories para o mesmo pacote (cada CVE separado), e o `queryNpmAudit` em `lib/deps.ts` cria um finding por advisory sem dedupe por (package, vulnerable_versions). UI agrupa por pacote mas mostra "Vulnerable versions" duplicado.

Proxima sessao: pedir print do Silvio + decidir se dedupe e em `lib/deps.ts` (server-side, mais limpo) ou em `DependenciesSection` (client-side, menos invasivo).

## Estrutura de codigo

```
app/api/scans/[id]/route.ts          # MODIFIED - 12 cols extras + recompute risk + reconstruct
app/dashboard/scan/view/[id]/page.tsx # MODIFIED - mirror live scan structure
app/scan-public/[owner]/[repo]/page.tsx # MODIFIED - prefetch={false} em 3 Links
README.md                            # MODIFIED - 2 ocorrencias seven->nine
AGENTS.md                            # MODIFIED - 1 ocorrencia 7->9
docs/plan-cleanup-2.md               # NEW - este briefing
```

Sem migration. Sem schema change. Tudo se sustenta nas colunas existentes.

## Tipos novos exportados

Nenhum. Todas as mudancas sao consumo de tipos existentes:
- `PostureResult` (lib/posture.ts)
- `IAMResult` (lib/iam.ts)
- `SupplyChainResult` (lib/supply-chain.ts)
- `RiskBreakdown`, `PrioritizedFinding` (lib/risk.ts)

## Sessions breakdown

S1 (esta sessao):
1. **briefing**: docs/plan-cleanup-2.md
2. **fix(scans/view)**: app/api/scans/[id]/route.ts + app/dashboard/scan/view/[id]/page.tsx (em 1 commit pq os 2 arquivos sao co-dependentes)
3. **fix(public-scan)**: app/scan-public/[owner]/[repo]/page.tsx (CORS prefetch)
4. **chore(docs)**: README.md + AGENTS.md

Smoke pos-deploy:
- Login -> History -> abre qualquer scan antigo. Esperado: ver o gauge de risk + Posture/IAM/SupplyChain cards (se persistidos), prioritized list, view toggle.
- Scan-public anonimo: abrir DevTools, recarregar, esperar scan terminar. Esperado: console limpo, sem CORS warning.
- README + AGENTS: visual confirmation - "nine"/"9" no lugar.

## Riscos e nao-objetivos

Nao e objetivo:
- Persistir scoreRepo breakdown/prioritized (resolve drift de suppression) - backlog
- Persistir IAM filesScanned + SupplyChain scanned counts em colunas dedicadas - backlog
- Refatorar ScanResultFull duplicado em 3 pages (live + public + view) - candidato Claude Code
- Mojibake fix - candidato Claude Code
- Postcss duplicate - DEFER (precisa print do bug)
- Pricing tier setup + landing page polish - sessao dedicada futura

Riscos:
- Scans antigos no DB podem ter `result` JSONB malformado (faltando campos esperados por flattenScan/scoreRepo). MITIGACAO: try/catch ja envolve recompute. Em caso de erro, riskScore vira null e UI cai pro path "no risk", renderizando so legacySections.
- Cards renderizam com approximations (filesScanned=0, scanned counts=0). Footer "across 0 files" pode confundir. MITIGACAO ACEITAVEL: backlog item.
- prefetch={false} pode marginalmente atrasar primeiro click pra /signin (sem prefetch, NextJS busca a pagina so no clique). Trade-off ACEITAVEL: zero impacto vs eliminar CORS warning visivel pra cliente potencial.

## Definition of done

- [x] Briefing commitado em docs/plan-cleanup-2.md
- [ ] /api/scans/[id]/route.ts atualizado com 12 cols + recompute + reconstruct
- [ ] view/[id]/page.tsx mirror live scan structure
- [ ] scan-public/page.tsx com prefetch={false} em 3 Links
- [ ] README.md + AGENTS.md count fix
- [ ] npm run build verde
- [ ] sandbox typecheck verde (3 files passed)
- [ ] 4 commits push, deploy verde
- [ ] Smoke pos-deploy: history -> scan antigo mostra cards, scan-public sem CORS warning, docs com texto correto
