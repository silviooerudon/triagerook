# Briefing: Landing hero + pagina /compare (pre-divulgacao)

## Contexto
TriageRook (repo silviooerudon/triagerook, live em triagerook.com) entra em fase de divulgacao amanha.
A landing precisa responder em 5 segundos: "por que escanear aqui e nao usar Snyk/GitHub gratis?"
Resposta: zero-install, 1 clique, scan publico sem login, e IAM Risk Scanner (OIDC trust,
privilege escalation, admin-equivalent) que nenhuma ferramenta zero-setup oferece.

## Antes de codar
1. git pull --rebase (multi-maquina, nao assumir estado local).
2. Inspecionar a landing atual e componentes existentes (hero, secoes, cards) antes de editar.
3. Commitar este briefing em docs/plan-landing-compare.md ANTES de qualquer mudanca de codigo.

## Entrega 1 - Hero da landing
- Headline acima da dobra. Direcao de copy (ajustar ao tom existente da pagina):
  "One-click GitHub security scan. No install, no agent, no CI config."
  Subline: "Including IAM risks no other zero-setup tool catches: OIDC trust
  misconfigurations, privilege escalation paths, admin-equivalent access."
- CTA primario: "Scan a public repo now - no login" apontando pro fluxo do scan publico
  (/api/scan-public ja existe; usar a UI que ja consome ele).
- CTA secundario: sign-in GitHub pro scan autenticado.
- Nao remover conteudo existente sem necessidade; reposicionar se preciso.

## Entrega 2 - Pagina /compare
Tabela comparativa HONESTA. TriageRook vs GitHub nativo (Dependabot/secret scanning/CodeQL)
vs Snyk vs TruffleHog/Gitleaks. Linhas sugeridas:
- Setup necessario (TriageRook: zero / outros: app install, CI config ou CLI)
- Scan sem login de repo publico (so TriageRook)
- Secrets detection (todos tem; TriageRook: 60+ patterns, sempre mascarado, + git history 30 commits)
- SAST: ADMITIR explicitamente que TriageRook e regex-based e que CodeQL/Snyk sao
  superiores em profundidade (AST). Frase tipo "If you already run CodeQL or Snyk,
  keep them - they are deeper for code analysis."
- Dependency scanning (npm/PyPI; Snyk cobre mais ecossistemas - admitir)
- Supply chain (lifecycle hooks, typosquatting)
- IAM/OIDC static analysis (so TriageRook nesta categoria zero-setup)
- Repo posture score 14 sinais (so TriageRook)
- Preco (TriageRook: free beta / citar que outros tem free tier tambem - nao esconder)
REGRA DURA: nenhuma claim sobre concorrente que nao seja verificavel na documentacao
publica deles. Em caso de duvida, suavizar ou omitir a celula. Comunidade dev vai testar
cada linha dessa tabela no Reddit.
- Link pro /compare no header/footer da landing.

## Restricoes tecnicas
- TypeScript strict, espelhar patterns existentes do codebase.
- ASCII em codigo, sem emoji/Unicode novos.
- Visual: NAO usar fundo verde claro com texto verde escuro. Destaques = fundo neutro
  + barra lateral 3px colorida (padrao existente dos cards de risco).
- Nao tocar em auth (NextAuth beta.31 fica como esta), nao tocar em endpoints de scan.
- Patches via Python str_replace com anchor assertion + normalizacao \r\n -> \n, escrita em LF.

## Workflow obrigatorio
1. Branch nova: feat/landing-compare
2. npm run build local antes de CADA commit, sem excecao.
3. Commits assinados (-S). git push -u origin feat/landing-compare.
4. Abrir PR, aguardar Vercel preview, validar visualmente o preview.
5. Merge SOMENTE via "Create a merge commit" no web (nunca Squash/Rebase - destroem GPG).
6. Cleanup de branch e o ULTIMO passo, depois do merge commit confirmado em main.

## Criterio de pronto
- Preview do Vercel mostrando hero novo + /compare renderizando em light e dark (se houver).
- Build passando. Nenhuma claim inventada na tabela.

## Notas de implementacao (verificadas contra o codigo antes de codar)
Numeros conferidos no codigo-fonte para nao imprimir claim inventada:
- Repo posture: 17 sinais (lib/posture.ts), NAO 14 como sugerido no briefing. Usar 17.
- IAM lens: 12 checks reais - 4 OIDC trust (lib/iam.ts), 5 privilege-escalation
  (lib/iam-privesc.ts), 3 admin-equivalent (lib/iam-admin.ts). OIDC trust, privesc e
  admin-equivalent confirmados. "stale-owner" e "outside-collaborator levels" NAO estao
  implementados como checks - nao mencionar na tabela.
- SAST: hibrido - AST TypeScript/JavaScript (28 regras, TS Compiler API via lib/ast/) +
  regex para outras linguagens (lib/code-vulns.ts). Honestamente: AST so cobre TS/JS e e
  raso comparado a dataflow semantico cross-language do CodeQL/Snyk. Manter a frase
  "if you already run CodeQL or Snyk, keep them - they go deeper".
- Secrets: 80 patterns no codigo; manter "60+" conservador para alinhar com o resto do site.
- Git history replay: 30 commits (lib/history.ts).
- Deps: npm (npm advisories) + OSV.dev para PyPI/Go/RubyGems/Maven/Composer + Trivy
  para CVEs de OS-package de container.
- Supply chain: typosquatting Damerau-Levenshtein (npm/PyPI) + install-hook abuse.
- Site e dark-only (sem theme toggle); "light e dark" do criterio nao se aplica - validar
  apenas o tema escuro existente no preview.
