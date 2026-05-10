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
            When you sign in with GitHub, RepoGuard requests the following OAuth scopes:
          </p>
          <ul className="list-disc pl-6 space-y-1 mt-3">
            <li><code className="bg-slate-900 px-1.5 py-0.5 rounded text-sm">read:user</code> — your GitHub username and avatar</li>
            <li><code className="bg-slate-900 px-1.5 py-0.5 rounded text-sm">user:email</code> — your public email</li>
            <li><code className="bg-slate-900 px-1.5 py-0.5 rounded text-sm">repo</code> — read access to your repositories, including private ones</li>
          </ul>
          <p className="mt-3">
            We use <code className="bg-slate-900 px-1.5 py-0.5 rounded text-sm">repo</code> because scanning private code requires it.
            We <strong>never</strong> write, modify, or push to any repository. Reducing this
            scope to read-only-only is on our roadmap.
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
              className="text-blue-400 hover:underline"
            >
              github.com/silviooerudon/repoguard
            </a>
          </p>
        </Section>

        <Section title="Revoking access">
          <p>
            You can revoke RepoGuard&apos;s access at any time:
          </p>
          <ol className="list-decimal pl-6 space-y-1 mt-3">
            <li>Go to <a href="https://github.com/settings/applications" target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline">GitHub → Settings → Applications</a></li>
            <li>Find <strong>RepoGuard</strong> and click <strong>Revoke</strong></li>
          </ol>
          <p className="mt-3">
            This immediately invalidates our access to your repositories.
          </p>
        </Section>

        <Section title="Reporting security issues">
          <p>
            Found a vulnerability or have a concern? Contact{" "}
            <a
              href="https://www.linkedin.com/in/silvio-junior-de-almeida-gazzoli-78453a8a/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-400 hover:underline"
            >
              Silvio directly on LinkedIn
            </a>{" "}
            or open an issue on{" "}
            <a
              href="https://github.com/silviooerudon/repoguard/issues"
              target="_blank"
              rel="noopener noreferrer"
              className="text-blue-400 hover:underline"
            >
              GitHub
            </a>.
          </p>
        </Section>

        <p className="text-xs text-slate-500 mt-16 pt-8 border-t border-slate-800/60">
          Last updated: April 2026. This page is maintained honestly. If anything here
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