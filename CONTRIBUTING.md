# Contributing to TriageRook

Thank you for considering a contribution. TriageRook is currently maintained as a solo project, but PRs and issues are welcome.

## Quick Start

```
git clone <your-fork-url>
cd triagerook
npm install
npm run build
npm run dev
```

The app will be available at http://localhost:3000.

## Environment

You will need a `.env.local` file with:

- `AUTH_SECRET` - random 32+ byte string (`npx auth secret`)
- `AUTH_GITHUB_APP_CLIENT_ID` - TriageRook Security GitHub App OAuth client ID
- `AUTH_GITHUB_APP_CLIENT_SECRET` - matching client secret
- `SUPABASE_URL` - your Supabase project URL
- `SUPABASE_SECRET_KEY` - Supabase service-role key (server-side only)

Optional, only needed if you want to exercise the auto-fix PR flow locally:

- `AUTH_GITHUB_APP_ID` - GitHub App numeric ID
- `AUTH_GITHUB_APP_PRIVATE_KEY` - PEM private key (escape newlines as `\n` in `.env`)

For local development, register a GitHub App (not an OAuth App) with the callback URL `http://localhost:3000/api/auth/callback/github`.

## Testing

TriageRook uses smoke tests against fixture repositories rather than unit tests.

```
npx tsx scripts/smoke-supply-chain.ts
npx tsx scripts/smoke-iam.ts
npx tsx scripts/smoke-posture.ts
```

Fixtures live in `triagerook-fixtures/` (committed in repo).

## Commit Style

We use Conventional Commits: `<type>(<scope>): <description>`.

Common types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`.

Examples:
- `feat(posture): add governance signals`
- `fix(scan-public): handle empty repo response`
- `docs(readme): update detector count`

## Pull Requests

1. Fork and create a branch off `main`
2. Run `npm run build` locally - all PRs must build green
3. Run relevant smoke scripts if you touched a detector
4. Open the PR with a description of what changed and why

Branch protection requires status checks (Vercel preview deploy) to pass before merge.

## Code of Conduct

Be respectful. Assume good faith. Focus on the code, not the contributor.

## Questions

Open a GitHub Discussion or issue for general questions. For security issues, see SECURITY.md.