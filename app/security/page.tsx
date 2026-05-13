import Link from "next/link";

export default function SecurityPage() {
  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      {/* NAV */}
      <nav className="border-b border-slate-800/60 bg-slate-950/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
          <Link href="/" className="flex items-center gap-2.5 group">
            <span className="font-mono text-amber-400 text-sm">[R/]</span>
            <span className="font-mono text-sm tracking-tight text-slate-100 group-hover:text-amber-400 transition">
              repoguard
            </span>
          </Link>
          <Link
            href="/"
            className="text-xs font-mono text-slate-400 hover:text-amber-400 transition"
          >
            ← back to home
          </Link>
        </div>
      </nav>

      <article className="max-w-3xl mx-auto px-6 py-16">
        <h1 className="text-4xl font-bold tracking-tight mb-2">Security & Privacy</h1>
        <p className="text-slate-400 mb-12">
          What RepoGuard accesses, stores, and protects. Plain language, no legal jargon.
        </p>

        <Section title="What we access">
          <p>
            RepoGuard is authenticated through the <strong>RepoGuard Security</strong>{" "}
            GitHub App (not a legacy OAuth App). When you sign in, RepoGuard reads:
          </p>
          <ul className="list-disc pl-6 space-y-1 mt-3">
            <li>Your GitHub username, avatar, and public email — for the session</li>
            <li>Your public repositories — to list them on the dashboard</li>
            <li>Public file contents of a repository — only during a scan you trigger</li>
          </ul>
          <p className="mt-3">
            We do <strong>not</strong> read private repositories. Private-repo support
            is on the roadmap; today, signing in scans public code only.
          </p>
          <p className="mt-3">
            For the optional <strong>auto-fix PR</strong> feature, you install the
            RepoGuard Security GitHub App on the target repository. That install grants
            the App <code className="bg-slate-900 px-1.5 py-0.5 rounded text-sm">Contents: write</code>{" "}
            and <code className="bg-slate-900 px-1.5 py-0.5 rounded text-sm">Pull requests: write</code>{" "}
            <strong>scoped to that repo only</strong>, so we can push a branch and open
            a PR for your review. Without an install, RepoGuard cannot write to a repo.
          </p>
        </Section>

        <Section title="What we store">
          <p>
            After each scan, we persist only <strong>metadata</strong> and <strong>findings</strong>:
          </p>
          <ul className="list-disc pl-6 space-y-1 mt-3">
            <li>Repository name (owner/repo)</li>
            <li>Scan timestamp and duration</li>
            <li>File paths and line numbers where secrets were detected</li>
            <li>Masked previews of matched secrets (never the full value)</li>
            <li>Vulnerable package names and advisory IDs</li>
          </ul>
        </Section>

        <Section title="What we never store">
          <ul className="list-disc pl-6 space-y-1">
            <li>Your source code</li>
            <li>Full values of detected secrets (only masked previews)</li>
            <li>Your GitHub access token (we keep a short-lived session only)</li>
            <li>Any data from repositories you haven&apos;t explicitly scanned</li>
          </ul>
          <p className="mt-3">
            Files are fetched from the GitHub API during a scan and discarded
            immediately after the scan completes.
          </p>
        </Section>

        <Section title="Where your data lives">
          <p>
            Scan metadata is stored in a Postgres database hosted on Supabase (EU region).
            The application runs on Vercel. Both providers are SOC 2 compliant.
          </p>
        </Section>

        <Section title="Source code">
          <p>
            RepoGuard is open source. You can audit the entire codebase, including how
            we handle your token and data:{" "}
            <a
              href="https://github.com/silviooerudon/repoguard"
              target="_blank"
              rel="noopener noreferrer"
              className="text-amber-400 hover:underline"
            >
              github.com/silviooerudon/repoguard
            </a>
          </p>
        </Section>

        <Section title="Revoking access">
          <p>
            You can revoke RepoGuard&apos;s access at any time:
          </p>
          <ul className="list-disc pl-6 space-y-2 mt-3">
            <li>
              <strong>Revoke sign-in:</strong> GitHub →{" "}
              <a href="https://github.com/settings/applications" target="_blank" rel="noopener noreferrer" className="text-amber-400 hover:underline">
                Settings → Applications → Authorized GitHub Apps
              </a>{" "}
              → find <strong>RepoGuard Security</strong> → <strong>Revoke</strong>.
            </li>
            <li>
              <strong>Uninstall auto-fix:</strong> GitHub →{" "}
              <a href="https://github.com/settings/installations" target="_blank" rel="noopener noreferrer" className="text-amber-400 hover:underline">
                Settings → Applications → Installed GitHub Apps
              </a>{" "}
              → find <strong>RepoGuard Security</strong> → <strong>Uninstall</strong>{" "}
              (or remove individual repos).
            </li>
          </ul>
          <p className="mt-3">
            Revocation is immediate. Any tokens already minted expire within an hour.
          </p>
        </Section>

        <Section title="Reporting security issues">
          <p>
            Found a vulnerability or have a concern? Contact{" "}
            <a
              href="https://www.linkedin.com/in/silvio-junior-de-almeida-gazzoli-78453a8a/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-amber-400 hover:underline"
            >
              Silvio directly on LinkedIn
            </a>{" "}
            or open an issue on{" "}
            <a
              href="https://github.com/silviooerudon/repoguard/issues"
              target="_blank"
              rel="noopener noreferrer"
              className="text-amber-400 hover:underline"
            >
              GitHub
            </a>.
          </p>
        </Section>

        <p className="text-xs text-slate-500 mt-16 pt-8 border-t border-slate-800/60">
          Last updated: May 2026. This page is maintained honestly. If anything here
          becomes outdated or inaccurate, please report it.
        </p>
      </article>
    </main>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-10">
      <h2 className="text-xl font-semibold mb-3">{title}</h2>
      <div className="text-slate-300 leading-relaxed space-y-2">
        {children}
      </div>
    </section>
  );
}