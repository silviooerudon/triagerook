import Link from "next/link";
import { PublicNav } from "@/app/components/public-nav";
import { LEGAL } from "@/lib/legal";

export default function SecurityPage() {
  return (
    <>
      <PublicNav />
      <main id="main">
      <article className="max-w-3xl mx-auto px-6 py-16">
        <h1 className="font-display text-3xl md:text-4xl font-bold tracking-tight mb-2">Security & Privacy</h1>
        <p className="text-slate-400 mb-12">
          What TriageRook accesses, stores, and protects. Plain language, no legal jargon.
        </p>

        <Section title="What we access">
          <p>
            TriageRook is authenticated through the <strong>TriageRook Security</strong>{" "}
            GitHub App (not a legacy OAuth App). When you sign in, TriageRook reads:
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
            TriageRook Security GitHub App on the target repository. That install grants
            the App <code className="bg-slate-900 px-1.5 py-0.5 rounded text-sm">Contents: write</code>{" "}
            and <code className="bg-slate-900 px-1.5 py-0.5 rounded text-sm">Pull requests: write</code>{" "}
            <strong>scoped to that repo only</strong>, so we can push a branch and open
            a PR for your review. Without an install, TriageRook cannot write to a repo.
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
            TriageRook is open source. You can audit the entire codebase, including how
            we handle your token and data:{" "}
            <a
              href="https://github.com/silviooerudon/triagerook"
              target="_blank"
              rel="noopener noreferrer"
              className="text-amber-400 hover:underline"
            >
              github.com/silviooerudon/triagerook
            </a>
          </p>
        </Section>

        <Section title="Revoking access">
          <p>
            You can revoke TriageRook&apos;s access at any time:
          </p>
          <ul className="list-disc pl-6 space-y-2 mt-3">
            <li>
              <strong>Revoke sign-in:</strong> GitHub →{" "}
              <a href="https://github.com/settings/applications" target="_blank" rel="noopener noreferrer" className="text-amber-400 hover:underline">
                Settings → Applications → Authorized GitHub Apps
              </a>{" "}
              → find <strong>TriageRook Security</strong> → <strong>Revoke</strong>.
            </li>
            <li>
              <strong>Uninstall auto-fix:</strong> GitHub →{" "}
              <a href="https://github.com/settings/installations" target="_blank" rel="noopener noreferrer" className="text-amber-400 hover:underline">
                Settings → Applications → Installed GitHub Apps
              </a>{" "}
              → find <strong>TriageRook Security</strong> → <strong>Uninstall</strong>{" "}
              (or remove individual repos).
            </li>
          </ul>
          <p className="mt-3">
            Revoking sign-in immediately stops TriageRook from obtaining new access.
            Installation tokens used for fix PRs are short-lived (GitHub expires them
            after one hour).
          </p>
          <p className="mt-3">
            To also erase everything we stored about you, use{" "}
            <Link href="/dashboard/account" className="text-amber-400 hover:underline">
              Dashboard → Your data
            </Link>
            . It deletes your saved scans and suppressions and revokes the GitHub
            authorization in one step. Details are in the{" "}
            <Link href="/privacy" className="text-amber-400 hover:underline">
              Privacy Policy
            </Link>
            .
          </p>
        </Section>

        <Section title="Reporting security issues">
          <p>
            Found a vulnerability? Please report it <strong>privately</strong> by
            email to{" "}
            <a href={`mailto:${LEGAL.privacyEmail}`} className="text-amber-400 hover:underline">
              {LEGAL.privacyEmail}
            </a>{" "}
            — do not open a public issue. Expect an acknowledgement within 72 hours
            and an initial assessment within 7 days. Good-faith research that avoids
            privacy violations, data destruction and service disruption is welcome,
            and we will not pursue it.
          </p>
        </Section>

        <p className="text-xs text-slate-500 mt-16 pt-8 border-t border-slate-800/60">
          Last updated: November 2026. This page is maintained honestly. If anything here
          becomes outdated or inaccurate, please report it.
        </p>
      </article>
      </main>
    </>
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