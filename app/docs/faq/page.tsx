import Link from "next/link"
import type { ReactNode } from "react"
import type { Metadata } from "next"
import { DocHeader } from "../_components/doc-ui"

export const metadata: Metadata = {
  title: "FAQ",
  description:
    "Common questions about TriageRook: timeouts on large repos, GitHub rate limits, private repositories, false positives, and why a scan might miss a finding.",
}

const FAQ: { q: string; a: ReactNode }[] = [
  {
    q: "The scan timed out / didn't finish on a large repo. Why?",
    a: (
      <>
        A scan runs inside one serverless request with a fixed budget &mdash; by
        default 1,000 files and 55 seconds. A repo bigger than that is scanned up
        to the cap and the result is flagged <em>truncated</em>, so you know it
        wasn&apos;t exhaustive. For a huge monorepo, narrow the scan to a subfolder.
        Full numbers and the rationale are on{" "}
        <Link href="/docs/scan-limits" className="text-amber-400 hover:underline">
          Scan limits
        </Link>
        .
      </>
    ),
  },
  {
    q: "I hit a GitHub rate limit.",
    a: (
      <>
        Anonymous scans share GitHub&apos;s API quota, so a burst of public scans
        can hit a limit; the response includes a <code className="font-mono text-amber-300">Retry-After</code>{" "}
        you can wait out. Signed-in scans run against your own GitHub quota, which
        is far higher &mdash; if you&apos;re evaluating on a popular repo and
        keep getting limited, signing in is the fix. TriageRook also surfaces a
        rate-limited history pass as <em>degraded</em> rather than pretending the
        history is clean.
      </>
    ),
  },
  {
    q: "Can I scan a private repository?",
    a: (
      <>
        No. TriageRook only scans public repositories, and the authenticated
        endpoint refuses a private repo at the boundary &mdash; before any file is
        fetched. That refusal is what makes the &ldquo;we don&apos;t read private
        code&rdquo; promise true in the code, not just in copy. See{" "}
        <Link
          href="/docs/security-and-data-handling"
          className="text-amber-400 hover:underline"
        >
          Security &amp; data handling
        </Link>
        .
      </>
    ),
  },
  {
    q: "A finding is a false positive. What do I do?",
    a: (
      <>
        Suppress it. You can silence a single finding, a rule on a path, or a whole
        rule for the repo &mdash; either from the findings view (synced to your
        account) or by committing a <code className="font-mono text-amber-300">.repoguardignore</code>{" "}
        file. The full syntax, with tested examples, is on{" "}
        <Link href="/docs/suppressions" className="text-amber-400 hover:underline">
          Suppressions
        </Link>
        . Findings in test/fixture paths are already de-prioritized automatically.
      </>
    ),
  },
  {
    q: "Why didn't it find a vulnerability I know is there?",
    a: (
      <>
        A few honest reasons: the file was past the per-run file cap (the result
        would be marked truncated); the language isn&apos;t covered for that
        detector (deep code analysis is primarily JS/TS, with regex for Python);
        the issue needs cross-file dataflow that a fast first-pass SAST doesn&apos;t
        trace; or there&apos;s no published advisory/pattern for it yet. What each
        detector does and does <em>not</em> catch is spelled out on{" "}
        <Link href="/docs/detectors" className="text-amber-400 hover:underline">
          Detectors
        </Link>
        , and the caps are on{" "}
        <Link href="/docs/scan-limits" className="text-amber-400 hover:underline">
          Scan limits
        </Link>
        .
      </>
    ),
  },
  {
    q: "Do you store my source code?",
    a: (
      <>
        No. Code is fetched per scan, analyzed in memory, and discarded. Anonymous
        scans persist nothing; signed-in scans save findings (paths, line numbers,
        masked previews) so you have history &mdash; never full file contents,
        never raw secret values. Details on{" "}
        <Link
          href="/docs/security-and-data-handling"
          className="text-amber-400 hover:underline"
        >
          Security &amp; data handling
        </Link>
        .
      </>
    ),
  },
  {
    q: "Can I get findings into GitHub Code Scanning?",
    a: (
      <>
        Yes &mdash; every scan exports SARIF 2.1.0 for upload to GitHub Code
        Scanning, and public repos can wire it into CI with no token. See{" "}
        <Link href="/docs/sarif" className="text-amber-400 hover:underline">
          SARIF export
        </Link>{" "}
        and the{" "}
        <Link href="/docs/quickstart" className="text-amber-400 hover:underline">
          Quickstart
        </Link>
        .
      </>
    ),
  },
]

export default function FaqPage() {
  return (
    <div className="max-w-3xl">
      <DocHeader eyebrow="start here" title="FAQ">
        The questions a careful evaluator asks first.
      </DocHeader>

      <dl className="space-y-8">
        {FAQ.map((item) => (
          <div key={item.q}>
            <dt className="mb-2 font-medium text-slate-100">{item.q}</dt>
            <dd className="text-sm leading-relaxed text-slate-300">{item.a}</dd>
          </div>
        ))}
      </dl>

      <div className="mt-12 border-t border-slate-800/60 pt-8 text-sm text-slate-500">
        <p>
          Question not answered here?{" "}
          <a
            href="https://github.com/silviooerudon/triagerook/issues/new?title=Question"
            target="_blank"
            rel="noopener noreferrer"
            className="text-amber-400 hover:underline"
          >
            Ask on GitHub
          </a>
          .
        </p>
      </div>
    </div>
  )
}
