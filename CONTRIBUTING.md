# Contributing to RepoGuard

Thank you for considering a contribution. RepoGuard is currently maintained as a solo project, but PRs and issues are welcome.

## Quick Start

```
git clone <your-fork-url>
cd repoguard
npm install
npm run build
npm run dev
```

The app will be available at http://localhost:3000.

## Environment

You will need a `.env.local` file with:

- `AUTH_SECRET` - random 32+ byte string
- `AUTH_GITHUB_ID` - GitHub OAuth App client ID
- `AUTH_GITHUB_SECRET` - GitHub OAuth App client secret
- `SUPABASE_URL` - your Supabase project URL
- `SUPABASE_SECRET_KEY` - Supabase service role key

For local development, create a GitHub OAuth App with callback URL `http://localhost:3000/api/auth/callback/github`.

## Testing

RepoGuard uses smoke tests against fixture repositories rather than unit tests.

```
npx tsx scripts/smoke-supply-chain.ts
npx tsx scripts/smoke-iam.ts
npx tsx scripts/smoke-posture.ts
```

Fixtures live in `repoguard-fixtures/` (committed in repo).

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