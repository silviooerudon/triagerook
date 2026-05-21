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

## Deferred to follow-up PRs

These items are intentionally NOT in this PR. Each unblocks separately and has its own risk profile.

### 1. URL swap (repoguard-chi.vercel.app -> triagerook.com)
- Blocked by DNS for triagerook.com being verified live on Vercel.
- Then update: metadataBase in app/layout.tsx, TRIAGEROOK_INFO_URI in lib/sarif.ts, curl examples in app/docs/sarif/page.tsx, README badges and links, SECURITY.md scope URL, public/workflows/triagerook.yml curl URL.
- Also re-tighten tests/sarif.test.ts informationUri assertion (currently weakened to toContain(".vercel.app") - should pin to the exact host once stable).

### 2. GitHub App rename (repoguard-security -> triagerook-security)
- Blocked by manual rename at github.com/settings/apps.
- Then update APP_INSTALL_URL in app/components/fix-pr-button.tsx (TODO comment marks the spot), remove the bridge wording in app/signin/page.tsx and app/security/page.tsx mentioning the legacy "RepoGuard Security" name, update the App-name reference in .env.example, and verify the auto-fix PR author display name matches the body text.

### 3. .triagerookignore alias in the suppressions parser (optional)
- Add fallback so the parser accepts either .repoguardignore (current) or .triagerookignore (new). Lets users migrate at their own pace.
- Files to touch: lib/scan.ts (fetch helper), lib/suppressions.ts (parser entry point).
