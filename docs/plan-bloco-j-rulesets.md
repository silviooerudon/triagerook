# Bloco J - Rulesets Posture Fix

## Contexto

`lib/posture.ts` hoje le apenas `/repos/:owner/:repo/branches/:branch/protection` (classic branch protection). Repos que protegem branches via Rulesets - incluindo o proprio RepoGuard - sub-reportam:

- Branch protection trava em 15/30 (perde signals presentes na Ruleset mas ausentes do classic)
- Signed commits trava em 0/10 mesmo com `required_signatures` enforced via Ruleset

Self-scan baseline atual (HEAD `b634d33`, 2026-05-08): Risk 90, Posture C(70), IAM 100, Supply Chain 100.

Esse fix sozinho deve subir Posture pra A-/A e ja serve de evidencia pro Show HN ("o scanner pega o que o proprio scanner ship, incluindo ele mesmo").

## Decisoes de produto

| # | Decisao | Escolha | Por que |
|---|---------|---------|---------|
| 1 | Merge classic + Ruleset | Union per signal | Cobre os dois modelos sem penalizar setups hibridos |
| 2 | Rule enforced com bypass actors nao-vazios | Conta como satisfeito + finding informativo low severity | Setups legit tem bypass para automation (Dependabot, deploy bots, release-please). Penalizar score geraria FP demais. Sec-minded ve via finding side-channel |
| 3 | Enforcement mode | So `active` conta | Scanner reflete postura real, nao intencao. `evaluate` eh dry-run, nao previne nada. `disabled` obvio |

## Abordagem tecnica

### Endpoints

- `GET /repos/{owner}/{repo}/rules/branches/{branch}` - rules aplicaveis ao branch (com `ruleset_id`)
- `GET /repos/{owner}/{repo}/rulesets/{ruleset_id}` - ruleset details (`enforcement`, `bypass_actors`)

### Fluxo

1. Existing: classic protection do branch default
2. Novo: rules aplicaveis ao branch default
3. Para cada `ruleset_id` unico no array de rules: fetch ruleset details (cache local por scan)
4. Filtra rules onde `ruleset.enforcement === "active"` (decisao 3)
5. Union com classic per-signal (decisao 1)
6. Para rules ativas com `bypass_actors.length > 0`: emite finding informativo (decisao 2)

Custo de API por scan posture: 1 (classic) + 1 (rules/branches) + N (rulesets details, tipico 1-3) = 3-5 chamadas. Negligivel.

### Mapeamento Ruleset rule type -> signal posture.ts

| Signal | Classic field | Ruleset rule type |
|---|---|---|
| Required PRs | `required_pull_request_reviews` presente | `pull_request` |
| Required approving reviews | `required_pull_request_reviews.required_approving_review_count >= 1` | `pull_request` com `parameters.required_approving_review_count >= 1` |
| Dismiss stale reviews | `required_pull_request_reviews.dismiss_stale_reviews` | `pull_request` com `parameters.dismiss_stale_reviews_on_push` |
| Code owner reviews | `required_pull_request_reviews.require_code_owner_reviews` | `pull_request` com `parameters.require_code_owner_review` |
| Required status checks | `required_status_checks.contexts.length > 0` | `required_status_checks` com `parameters.required_status_checks.length > 0` |
| Linear history | `required_linear_history.enabled` | `required_linear_history` |
| No force push | `allow_force_pushes.enabled === false` | `non_fast_forward` |
| No deletions | `allow_deletions.enabled === false` | `deletion` |
| Signed commits | `required_signatures.enabled` | `required_signatures` |
| Admin enforcement | `enforce_admins.enabled` | `bypass_actors` vazio na ruleset (proxy) |

Buckets de pontos exatos (30pts BP, 10pts SC) confirmados durante o patch contra posture.ts atual - a fonte de verdade dos valores mora la, briefing nao duplica.

### Funcao de merge

Pseudocodigo (TS final no commit do codigo):

- input: classicSatisfied (bool), rulesetSatisfied (bool), rulesetBypassActors (string[])
- output: satisfied (bool), source (classic | ruleset | both | none), bypassActors (string[])
- regra: satisfied = classicSatisfied OR rulesetSatisfied
- score final = soma dos pontos dos signals com satisfied true; bypass nao zera, so emite finding

### Bypass finding (decisao 2)

- severity: low
- category: governance
- rule: ruleset-bypass-actors
- title: Branch protection rule allows bypass
- message: Ruleset rule {rule.type} on branch {branch} can be bypassed by {N} actor(s): {names}
- file: .github/rulesets (synthetic path)
- informational: true (nao reduz score)

Aparece na lista de findings da secao governance do Posture, separado dos findings que afetam pontuacao.

## Smoke test

Fixture novo: `repoguard-fixtures/rulesets/sample.json` (gitignored - pasta `repoguard-fixtures/` ja excluida).

5 cases novos no smoke script:

1. Repo sem nada (baseline - sanity)
2. Repo so com Ruleset active sem bypass (caso RepoGuard)
3. Repo so com Ruleset enforcement evaluate (deve nao contar - valida decisao 3)
4. Repo com classic + Ruleset overlap (valida union - decisao 1)
5. Repo com Ruleset active + bypass actors (valida finding informativo - decisao 2)

Cada case verifica: score esperado + presenca/ausencia de finding informativo.

## Self-scan esperado pos-merge

| Metric | Antes (b634d33) | Depois (esperado) |
|---|---|---|
| Risk Score | 90 / Excellent | 90-95 / Excellent |
| Posture | C / 70 | A- a A / 85-92 |
| Branch protection | 15/30 | 27-30/30 |
| Signed commits | 0/10 | 10/10 |
| IAM | 100 | 100 |
| Supply Chain | 100 | 100 |

A- vs A depende se signals menores (linear history, required deployments) ainda ficam de fora - confirmar no scan pos-merge e refresh do baseline.

## Plan de commits (branch fix/posture-rulesets)

1. docs: plan Bloco J - rulesets posture fix (este arquivo, antes de codigo)
2. feat(posture): add rulesets API client - novo lib/github/rulesets.ts, isolado, sem integrar
3. feat(posture): union classic + ruleset signals - integra em lib/posture.ts
4. feat(posture): emit informative finding for ruleset bypass
5. test(posture): add ruleset fixtures and smoke cases
6. chore(self-scan): refresh baseline post-rulesets-fix

npm run build antes de cada commit. Cada commit signed (GPG). PR final com Create a merge commit (preserva os 6 commits assinados).

## Out-of-scope nessa sessao

- Org rulesets / Enterprise rulesets (ruleset_source_type !== Repository): codigo trata identico, mas validacao end-to-end espera fixture real
- UI changes: finding informativo aparece automatico no Posture, sem alteracao de tela
- Cache cross-scan: tudo fresh por scan
- Fix das classic protections que tambem tem buracos (separadamente em sessao futura se aparecer)
