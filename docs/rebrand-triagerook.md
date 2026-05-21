# Rebrand: RepoGuard -> TriageRook

## Contexto
Colisao de nome com repoguard.org (CLI tool open source). Decidido rebrand em 2026-05-20.
Dominio triagerook.com adquirido, repo GitHub renomeado de silviooerudon/repoguard para silviooerudon/triagerook.

## Escopo
1. Find/replace global "RepoGuard" -> "TriageRook" (preservando case quando relevante)
2. Find/replace "repoguard" -> "triagerook" em lowercase contexts (package names, env vars NAO sensiveis, URLs)
3. Atualizar tagline em landing, /about, /pricing
4. Atualizar metadata (title, description, OG)
5. Atualizar package.json name
6. Atualizar README.md
7. Verificar build passa

## Tagline nova
"Security triage for solo devs. Scan your GitHub repo in one click."

## Nao-escopo
- NAO mexer em .env / .env.local / secrets do Vercel
- NAO renomear arquivo .repoguardignore (manter compatibilidade, pode aceitar ambos no parser numa fase futura)
- NAO mexer em logo image files (nao existem, sera adicionado depois)
- NAO renomear identifiers internos de codigo que NAO sao branding (ex: variaveis tipo `repoData`, classes tipo `RepoCard`)
- NAO renomear o git remote (ja feito local)
- NAO mexer em DB schema, supabase tables, RLS policies

## Criterios de aceitacao
- npm run build passa sem erros
- npm run lint passa
- Grep "RepoGuard" no codigo deve retornar apenas casos intencionais (se algum)
- Grep "repoguard" (lowercase) deve retornar apenas: .repoguardignore (arquivo backward compat), referencias historicas em CHANGELOG/docs se houver
