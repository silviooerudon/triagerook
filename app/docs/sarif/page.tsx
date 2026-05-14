import Link from "next/link"
import type { Metadata } from "next"
import { PublicNav } from "@/app/components/public-nav"

export const metadata: Metadata = {
  title: "SARIF export — RepoGuard",
  description:
    "How to download SARIF 2.1.0 from RepoGuard and upload to GitHub Code Scanning so findings appear in your repo's Security tab.",
}

export default function SarifDocsPage() {
  return (
    <>
      <PublicNav />
      <main className="px-6 py-16">
        <div className="max-w-3xl mx-auto">
          <Link
            href="/docs/rules"
            className="inline-flex items-center gap-1 text-xs font-mono text-slate-500 hover:text-amber-400 transition mb-8"
          >
            ← rules catalog
          </Link>

          <p className="font-mono text-xs text-amber-400 mb-3">SARIF export</p>
          <h1 className="text-3xl font-semibold tracking-tight mb-4 leading-tight">
            Send RepoGuard findings to GitHub Code Scanning
          </h1>
          <p className="text-slate-300 leading-relaxed mb-10">
            Every RepoGuard scan can be exported as{" "}
            <a
              href="https://docs.oasis-open.org/sarif/sarif/v2.1.0/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-amber-400 hover:underline"
            >
              SARIF 2.1.0
            </a>
            , the same format GitHub Code Scanning, Azure DevOps, and most SAST
            consumers speak. Upload it once and your findings show up in the
            repo&apos;s <span className="font-mono">Security → Code scanning</span>{" "}
            tab alongside Dependabot and CodeQL — with each result linked back
            to its rule page on RepoGuard.
          </p>

          <section className="mb-10">
            <h2 className="text-sm uppercase tracking-wider text-slate-500 font-mono mb-3">
              Step 1 — Download the SARIF
            </h2>
            <p className="text-slate-300 leading-relaxed text-sm mb-4">
              On any saved scan, click{" "}
              <span className="font-mono text-amber-300">Export SARIF</span> in
              the top-right header. You get a{" "}
              <code className="font-mono text-amber-300">.sarif.json</code> file
              ready to upload — one result per finding, severities mapped to
              SARIF levels (critical/high → <code>error</code>, medium →{" "}
              <code>warning</code>, low → <code>note</code>), test-fixture
              findings discounted to <code>note</code>.
            </p>
            <p className="text-slate-300 leading-relaxed text-sm">
              You can also pull it programmatically:
            </p>
            <pre className="mt-3 bg-slate-900/80 border border-slate-800 rounded-lg p-4 text-xs font-mono text-slate-300 overflow-x-auto">
{`curl -L "https://repoguard-chi.vercel.app/api/scans/<SCAN_ID>/sarif" \\
  -H "Cookie: authjs.session-token=<your-session-cookie>" \\
  -o repoguard.sarif.json`}
            </pre>
          </section>

          <section className="mb-10">
            <h2 className="text-sm uppercase tracking-wider text-slate-500 font-mono mb-3">
              Step 2 — Upload to GitHub Code Scanning
            </h2>
            <p className="text-slate-300 leading-relaxed text-sm mb-4">
              The cleanest path is a GitHub Actions job that runs after your
              normal CI, downloads the SARIF, and hands it to{" "}
              <code className="font-mono text-amber-300">
                github/codeql-action/upload-sarif
              </code>
              :
            </p>
            <pre className="bg-slate-900/80 border border-slate-800 rounded-lg p-4 text-xs font-mono text-slate-300 overflow-x-auto">
{`# .github/workflows/repoguard-sarif.yml
name: RepoGuard → Code Scanning

on:
  workflow_dispatch:
    inputs:
      scan_id:
        description: "RepoGuard scan id"
        required: true

permissions:
  contents: read
  security-events: write   # required to upload SARIF

jobs:
  upload:
    runs-on: ubuntu-latest
    steps:
      - name: Download SARIF from RepoGuard
        run: |
          curl -fL \\
            -H "Cookie: authjs.session-token=\${{ secrets.REPOGUARD_SESSION }}" \\
            "https://repoguard-chi.vercel.app/api/scans/\${{ inputs.scan_id }}/sarif" \\
            -o repoguard.sarif.json

      - name: Upload to Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: repoguard.sarif.json
          category: repoguard`}
            </pre>
            <p className="text-slate-400 leading-relaxed text-sm mt-4">
              The session cookie comes from your authenticated browser session
              with RepoGuard. Long-term we&apos;ll ship a proper API token; for
              now this manual flow is enough to satisfy any team policy that
              requires findings to live in the GitHub Security tab.
            </p>
          </section>

          <section className="mb-10">
            <h2 className="text-sm uppercase tracking-wider text-slate-500 font-mono mb-3">
              What you get inside Code Scanning
            </h2>
            <ul className="text-slate-300 leading-relaxed text-sm space-y-2 list-disc list-inside">
              <li>
                Each result deep-links back to its rule page on RepoGuard via{" "}
                <code className="font-mono text-amber-300">helpUri</code>, so a
                triager can read the &quot;what / why / remediation&quot;
                without leaving the alert.
              </li>
              <li>
                Dependency findings dedupe across versions using the GHSA id —
                upgrading the package closes every linked alert in one shot.
              </li>
              <li>
                Test fixtures get downgraded to{" "}
                <code className="font-mono">note</code> level, so a known
                fixture key never blocks a merge gate.
              </li>
              <li>
                Sensitive-file findings ship a file-level location (no line
                number) — Code Scanning groups them by path.
              </li>
            </ul>
          </section>

          <section className="mb-10">
            <h2 className="text-sm uppercase tracking-wider text-slate-500 font-mono mb-3">
              Public scans
            </h2>
            <p className="text-slate-300 leading-relaxed text-sm">
              Anonymous scans at{" "}
              <code className="font-mono text-amber-300">
                /scan-public/&lt;owner&gt;/&lt;repo&gt;
              </code>{" "}
              also expose <span className="font-mono">Export SARIF</span> once
              the scan finishes. The export is generated in your browser from
              the in-flight result — no persistence, no account needed. Same
              SARIF schema, same severity mapping; only the{" "}
              <code className="font-mono">helpUri</code> is omitted (the
              browser doesn&apos;t have access to the catalog resolver).
            </p>
          </section>

          <div className="pt-8 border-t border-slate-800/60 text-sm text-slate-500">
            <p>
              SARIF schema version:{" "}
              <code className="font-mono text-amber-300">2.1.0</code>. Tool
              driver name:{" "}
              <code className="font-mono text-amber-300">RepoGuard</code>.
              Found a mapping bug or want a richer SARIF field populated?{" "}
              <a
                href="https://github.com/silviooerudon/repoguard/issues/new?title=SARIF%20feedback"
                target="_blank"
                rel="noopener noreferrer"
                className="text-amber-400 hover:underline"
              >
                File an issue
              </a>
              .
            </p>
          </div>
        </div>
      </main>
    </>
  )
}
