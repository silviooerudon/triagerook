# RepoGuard - Briefing: Posture expansion (Bloco 2 Item 4)

Sessao planejada: feature inteira em 1 sessao consecutiva (3 commits efetivos).
Branch: main. Migrations dir: docs/migrations/.

## Contexto

Bloco 2 Item 4 do roadmap. Expande Posture Score original (8 signals em 3 categorias, 100 pts) para 14 signals em 4 categorias, mantendo 100 pts max via re-balanceamento. Nova categoria `governance` agrupa controles humanos/processuais que nao se encaixam em branch/docs/deps.

Diferencial vs Posture original: o Posture v1 cobria principalmente "esta tudo configurado?" (branch protected? security.md existe? lockfile commitado?). Posture v2 adiciona signals de qualidade processual: signed commits, MFA enforcement, e detalhes de branch protection (PR review, status checks, enforce admins) - sinais de maturidade que distinguem repos hobbyistas de empresas serias.

## Decisoes tecnicas fechadas

### Re-balanceamento (100 pts max preservado)

| Cat | Antes | Depois | Sinais |
|---|---|---|---|
| branch | 35 | 30 | branch-protection 15, pr-required 5, status-checks 5, enforce-admins 5 |
| docs | 35 | 30 | security-md 10, license 8, codeowners 5, readme-substantial 4, readme-security 3 |
| deps | 30 | 25 | auto-updates 12, lockfile 8, gitignore 5 |
| governance | --- | 15 | signed-commits 10, mfa-org 5 |

Total: 100. 14 signals (era 8, +6).

Justificativa:
- Old DB rows persistem com calibracao v1 (sem migration de dados). Foward-looking change. Pre-distribuicao (1 user) aceita a inconsistencia historica.
- `posture_breakdown` JSONB ja flexivel - novos signals + nova categoria sem schema change. Sem migration 006.
- Pesos novos refletem que branch protection details + governance sao premium. Hobby projects mantem grau D-F. Empresas serias com tudo configurado atingem A.

### Scope OAuth: read:user user:email public_repo read:org

Adicao de `read:org` necessaria pra avaliar MFA enforcement em orgs. Em pre-distribuicao (1 user = Silvio), impacto = 1 logout+login pra Vercel re-emitir token com novo scope. Pos-distribuicao, novos users veem permissao adicional ao logar (low friction se UI explica). Mudanca isolada em commit separado pra revert facil se OAuth quebrar.

### Sinal `unknown` (novo concept)

Pra signals que nao podem ser avaliados sem permissao especial (admin do repo) ou contexto especifico (org repo), introduzimos `unknown?: boolean` em PostureSignal:
- `pointsEarned = 0` (conservador)
- `satisfied = false`
- `unknown = true` (UI distinguishe de "nao satisfied" deliberado)
- Excluido de quickWins (nao recomendamos "habilite X" se nao sabemos se ja esta)

Casos de uso:
- Branch protection details: API requer admin/maintain. Non-admin user scaneando repo publico -> 3 sub-signals unknown.
- MFA org: repo user-owned -> signal N/A com label especial. Repo de org que user nao e member -> unknown.
- Signed commits: API failure -> unknown. Commits sem verification info -> ratio 0.
- Network errors em qualquer signal -> softFail seta unknown via degraded flag.

### Branch protection sub-signals: filtrados em quickWins quando parent unsatisfied

Se `branch-protection` (parent, 15 pts) nao esta satisfied, os 3 sub-signals (pr/status/admins) sao SUPRIMIDOS de quickWins. Motivo: habilitar protection e prerequisito - sub-signals seguem naturalmente quando voce ativa. Sem isso, quickWins ficaria saturada de "Require PR review" / "Require status checks" / "Apply to admins" repetidas, polluindo a lista.

Logic: filter explicito apos `!satisfied && !unknown`, antes de sort+slice.

## Estrutura de codigo

```
lib/posture.ts                  # MODIFIED - 14 signals, 4 categorias, novo `unknown` flag
app/components/posture-card.tsx # MODIFIED - adicionar label "Governance"
app/components/posture-gauge.tsx # UNCHANGED - score 0-100 + grade A-F igual
auth.ts                          # MODIFIED - scope expansion read:org
docs/plan-posture-expansion.md  # NEW - este briefing
```

Sem migration 006. JSONB schema absorve novos campos.

## Tipos exportados de lib/posture.ts (mudancas)

NOVOS:
- PostureCategoryId adiciona "governance"
- PostureSignal adiciona `unknown?: boolean`

MANTIDOS:
- PostureGrade, PostureCategoryBreakdown, QuickWin, PostureResult (shapes inalterados)
- computeScore, assessPosture (signature inalterada)

## API endpoints adicionais

| Signal | Endpoint | Scope necessario | Notes |
|---|---|---|---|
| codeowners | `/contents/{path}` x 3 | public_repo | Existing helper |
| signed-commits | `/commits?per_page=30` | public_repo | Verifica `verification.verified` em cada commit |
| branch-protection details | `/branches/{branch}/protection` | public_repo (admin recheck) | 403/404 -> null = unknown sub-signals |
| mfa-org | `/repos/{o}/{r}` + `/orgs/{login}` | read:org | User-owned repo -> "na-user-repo". Org repo + sem read:org -> "unknown" |

Total API calls em assessPosture: 19 (era 13, +6 novas calls). Todas em Promise.all paralelo. Soft-failed via softFail wrapper (rate-limit propaga, network errors degrad).

## Scoring rules para signals com gradiente

Signed commits: 
- ratio >= 0.8 -> 10 pts (full), satisfied=true
- ratio >= 0.5 -> 5 pts (half), satisfied=false (counts as quick win)
- ratio < 0.5 -> 0 pts, satisfied=false (counts as quick win)
- ratio === null (API fail / no commits) -> 0 pts, unknown=true

MFA org:
- "enforced" -> 5 pts, satisfied=true
- "not-enforced" -> 0 pts, satisfied=false (counts as quick win)
- "na-user-repo" -> 0 pts, unknown=true (repo de pessoa, signal N/A com label especial)
- "unknown" -> 0 pts, unknown=true (sem read:org ou nao-member da org privada)

## Sessions breakdown

### S1 (esta sessao) - tudo

3 commits sequenciais:
1. **briefing**: docs/plan-posture-expansion.md (este arquivo)
2. **scope**: auth.ts (1-line change). Apos push, Silvio precisa logout+login pra novo scope ser efetivo.
3. **posture expansion**: lib/posture.ts + app/components/posture-card.tsx (todos signals + re-balance + nova categoria + graceful degradation)

Smoke pos-deploy: scan logado de silviooerudon/repoguard pelo dashboard. Esperado:
- 4 categorias na breakdown bar (era 3)
- Quick wins inclui "Add a CODEOWNERS file" (silvio nao tem CODEOWNERS), "Sign commits" (a maioria dos commits dele nao sao signed)
- Branch protection details: visivel pq Silvio e admin do repo. Score reflete sub-signals reais.
- MFA: signal aparece com label "(N/A - user-owned repo)" pq silviooerudon e user, nao org

## Riscos e nao-objetivos

Nao sao objetivos desta feature:
- Migration de dados (re-pontuar scans antigos)
- Workflow files inspection beyond GHA (ex: CircleCI, GitLab CI)
- Detection de codigo de terceiros copiado/adapted (license compliance)
- Org-level secret scanning enable detection (precisa scope adicional)

Riscos:
- Scope expansion `read:org` pode parecer permissao excessiva pra novos users post-distribution. MITIGACAO: mostrar tooltip explicativo no signin se decidirmos investir em UX. Pre-distribuicao baixo risco.
- Branch protection details sao admin-only. Maioria dos repos publicos scaneados gera 3 unknowns visualmente. MITIGACAO: tooltip explicativo no card sub-signals - "Requires admin permission".
- Re-balanceamento muda relativa importance dos signals existentes. Repos previously perfect podem ter score < 100 agora se nao tem nova categoria governance. ACEITAVEL pq foward-looking - novos scans usam novos pesos.
- 19 API calls em paralelo em assessPosture. GitHub anonymous limit = 60/h. Pra public scans heavy (varios scans/min do mesmo IP), pode esgotar. MITIGACAO existente: rate limit 429 propaga e API retorna Retry-After. Usuario logado tem 5000/h, nao e issue.

## Decisoes adiadas

- AST-based YAML parser pra branch protection (atual usa REST API direct)
- Cache de signals pos-scan (deduping commits cross-scan)
- MFA detection via SAML SSO requirements
- Permission auditing (collaborators externos, write access)

## Definition of done

- [x] Briefing commitado em docs/plan-posture-expansion.md
- [ ] auth.ts atualizado com scope read:org
- [ ] lib/posture.ts re-balanceado + 4 signals novos + governance + graceful degradation
- [ ] app/components/posture-card.tsx mostra label "Governance"
- [ ] npm run build verde
- [ ] sandbox tests 6/6 PASS (computeScore exhaustive)
- [ ] 3 commits push, deploy verde
- [ ] Silvio logout+login pra novo scope ser efetivo
- [ ] Smoke pos-deploy: scan logado de silviooerudon/repoguard mostra 4 categorias e novos signals
