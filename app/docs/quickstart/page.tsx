import Link from "next/link"
import type { Metadata } from "next"
import { DocHeader, Section, Callout, Code, Pre } from "../_components/doc-ui"

export const metadata: Metadata = {
  title: "Quickstart",
  description:
    "Scan a GitHub repo with TriageRook in about 60 seconds — anonymously with no account, or signed in for saved history, diffs, and fix PRs.",
}

export default function QuickstartPage() {
  return (
    <div className="max-w-3xl">
      <DocHeader eyebrow="start here" title="Quickstart">
        Two ways to scan, both finish in about a minute. Start anonymous to try it
        on any public repo; sign in when you want history, diffs, suppressions that
        sync, and one-click fix PRs.
      </DocHeader>

      <Section title="Option A — anonymous, no account">
        <ol className="list-decimal space-y-3 pl-5 text-sm leading-relaxed text-slate-300">
          <li>
            Go to{" "}
            <a
              href="https://www.triagerook.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-amber-400 hover:underline"
            >
              triagerook.com
            </a>{" "}
            and paste a public repo &mdash; a full URL or just{" "}
            <Code>owner/repo</Code>.
          </li>
          <li>
            The scan runs against the public-scan endpoint and streams a
            prioritized report straight to your browser. Nothing is saved &mdash;
            no account, no persistence (see{" "}
            <Link
              href="/docs/security-and-data-handling"
              className="text-amber-400 hover:underline"
            >
              data handling
            </Link>
            ).
          </li>
          <li>
            When it finishes, hit <Code>Export SARIF</Code> to download findings for
            GitHub Code Scanning if you want them.
          </li>
        </ol>
        <Callout variant="info" title="Rate limits">
          <p>
            Anonymous scans are capped at <strong>10 per source IP per hour</strong>{" "}
            and <strong>5 per repo per hour</strong>. Plenty for evaluating; sign in
            to scan on your own GitHub quota instead.
          </p>
        </Callout>
      </Section>

      <Section title="Option B — signed in">
        <ol className="list-decimal space-y-3 pl-5 text-sm leading-relaxed text-slate-300">
          <li>
            Click <Code>Sign in</Code> and authorize the{" "}
            <strong>TriageRook Security</strong> GitHub App. It asks only for what
            it needs &mdash; details on the{" "}
            <Link
              href="/docs/security-and-data-handling"
              className="text-amber-400 hover:underline"
            >
              security page
            </Link>
            .
          </li>
          <li>
            Pick one of your public repos (or enter <Code>owner/repo</Code>) and
            scan. The result is saved to your history.
          </li>
          <li>
            From a saved scan you get: SARIF export, scan-to-scan diffs,
            suppressions that sync across scans, and &mdash; for findings with a
            clean deterministic fix &mdash; a one-click PR you review before
            merging.
          </li>
        </ol>
        <p className="mt-4 text-sm leading-relaxed text-slate-400">
          Signed-in scans still only read <strong>public</strong> repositories; a
          private repo is refused at the boundary.
        </p>
      </Section>

      <Section title="Option C — in CI (zero-auth, public repos)">
        <p className="mb-3 text-sm leading-relaxed text-slate-300">
          For a public repo you can wire scanning into CI with no token at all
          &mdash; the anonymous endpoint speaks SARIF directly:
        </p>
        <Pre>{`# .github/workflows/triagerook.yml
on:
  push: { branches: [main] }
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - run: |
          curl -fSL -X POST \\
            "https://www.triagerook.com/api/scan-public/\${{ github.repository_owner }}/\${{ github.event.repository.name }}?format=sarif" \\
            -o triagerook.sarif.json
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: triagerook.sarif.json
          category: triagerook`}</Pre>
        <p className="mt-3 text-sm leading-relaxed text-slate-400">
          Full walkthrough, including the authenticated variant, on the{" "}
          <Link href="/docs/sarif" className="text-amber-400 hover:underline">
            SARIF export
          </Link>{" "}
          page.
        </p>
      </Section>

      <div className="mt-12 border-t border-slate-800/60 pt-8 text-sm text-slate-500">
        <p>
          Next: skim what each{" "}
          <Link href="/docs/detectors" className="text-amber-400 hover:underline">
            detector
          </Link>{" "}
          looks for, or read the{" "}
          <Link href="/docs/faq" className="text-amber-400 hover:underline">
            FAQ
          </Link>
          .
        </p>
      </div>
    </div>
  )
}
