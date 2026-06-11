import type { Metadata } from "next"
import { DocHeader, Section, Callout, Code } from "../_components/doc-ui"

export const metadata: Metadata = {
  title: "Security & data handling",
  description:
    "Exactly what TriageRook asks for and keeps: GitHub App permissions (no OAuth scopes), what each scan endpoint persists, how secrets are masked before storage, and why your access token never reaches the browser.",
}

// Permissions are declared on the GitHub App itself (see auth.ts) — there is no
// OAuth `scope` parameter. This table mirrors those declared permissions.
const PERMISSIONS: { perm: string; access: string; why: string }[] = [
  {
    perm: "Repository contents",
    access: "Read & write",
    why: "Read is how every scan fetches your file tree and file contents. Write exists for one opt-in action only: opening a fix pull request when you click “Fix” on a finding. Nothing is written unless you ask for that PR.",
  },
  {
    perm: "Pull requests",
    access: "Write",
    why: "Lets the same opt-in “Fix” flow open a PR with the suggested change. Never used during a scan.",
  },
  {
    perm: "Email address",
    access: "Read",
    why: "Identifies your account at sign-in. Your stable GitHub numeric user id (not your username) is the key we store scans under.",
  },
  {
    perm: "Metadata",
    access: "Read",
    why: "Mandatory baseline for any GitHub App: repo names, default branch, visibility. Visibility is what lets us refuse private repos at the door.",
  },
]

export default function SecurityDataPage() {
  return (
    <div className="max-w-3xl">
      <DocHeader eyebrow="trust & data" title="Security & data handling">
        TriageRook is built for developers who read the permission screen before
        they click Authorize. This page is the honest, code-backed version of what
        that screen means: what we can touch, what we keep, and what we throw away.
      </DocHeader>

      <Section title="We authenticate with a GitHub App, not OAuth scopes">
        <p className="mb-4 leading-relaxed text-slate-300">
          Sign-in is backed by the <strong>TriageRook Security</strong> GitHub
          App. A GitHub App does not request the classic OAuth scopes you may have
          seen elsewhere (no <Code>public_repo</Code>, no <Code>repo</Code>).
          Instead, the App declares a fixed set of fine-grained permissions, and
          those are the only things it can ever do:
        </p>

        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-slate-800 text-left">
                <th className="py-2 pr-4 font-mono text-xs uppercase tracking-wider text-slate-500">
                  Permission
                </th>
                <th className="py-2 pr-4 font-mono text-xs uppercase tracking-wider text-slate-500">
                  Access
                </th>
                <th className="py-2 font-mono text-xs uppercase tracking-wider text-slate-500">
                  Why
                </th>
              </tr>
            </thead>
            <tbody>
              {PERMISSIONS.map((p) => (
                <tr
                  key={p.perm}
                  className="border-b border-slate-800/60 align-top"
                >
                  <td className="py-3 pr-4 font-medium text-slate-200">
                    {p.perm}
                  </td>
                  <td className="py-3 pr-4 whitespace-nowrap font-mono text-xs text-amber-300">
                    {p.access}
                  </td>
                  <td className="py-3 leading-relaxed text-slate-400">{p.why}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <Callout variant="info" title="About contents: write">
          <p>
            Contents <Code>write</Code> is the one permission a skeptical reader
            should question, so we will be explicit: it is used by exactly one
            feature &mdash; the <strong>Fix PR</strong> button, which opens a pull
            request with a suggested remediation when you click it. A scan never
            writes to your repository. If you never use Fix, that permission is
            never exercised.
          </p>
        </Callout>
      </Section>

      <Section title="read:org is optional — and we never fake the answer">
        <p className="leading-relaxed text-slate-300">
          One repo-posture signal checks whether an organization enforces
          two-factor authentication. Reading that requires organization-level
          access (<Code>read:org</Code>). It is <strong>not</strong> part of the
          default install, and the IAM risk scanner does not use it at all.
        </p>
        <p className="mt-3 leading-relaxed text-slate-300">
          When we cannot read it, the <Code>mfa-org</Code> signal is marked{" "}
          <Code>unknown</Code> rather than &ldquo;failing.&rdquo; An unknown signal
          is excluded from both the numerator and the denominator of your posture
          score &mdash; its points are withheld, never silently awarded and never
          counted against you. You are told the signal could not be evaluated
          instead of being shown a confident number we did not earn.
        </p>
      </Section>

      <Section title="Public repositories only">
        <p className="leading-relaxed text-slate-300">
          TriageRook only scans public repositories. This is enforced in code, not
          just promised in copy: the authenticated scan endpoint resolves the
          repository&apos;s visibility and refuses with a{" "}
          <Code>403</Code> before any file tree or blob is fetched if the repo is
          private. The check runs at the API boundary, so a private repo&apos;s
          contents are never requested in the first place.
        </p>
      </Section>

      <Section title="What each scan endpoint stores">
        <p className="mb-4 leading-relaxed text-slate-300">
          There are two ways to scan, and they persist very different amounts of
          data.
        </p>

        <Callout variant="ok" title="Anonymous scan — stores nothing">
          <p>
            Paste a public repo URL with no account (
            <Code>/scan-public/&lt;owner&gt;/&lt;repo&gt;</Code>). The result is
            computed and returned to your browser, and that is the end of it. We do
            not write the scan, the findings, or your code to any database.
          </p>
          <p>
            Two things are recorded, neither of them your data: per-hour rate-limit
            counters (keyed by source IP and by repo, to stop abuse), and a single
            structured log line per attempt containing the owner, repo, duration,
            and outcome. That log line deliberately contains{" "}
            <strong>no IP address and no other personal data</strong>.
          </p>
        </Callout>

        <Callout variant="info" title="Signed-in scan — saved to your history">
          <p>
            When you sign in and scan, the full result is saved to your scan
            history (a Supabase <Code>scans</Code> table) so you can revisit it,
            diff it against a later scan, and export SARIF. The stored row is keyed
            to your GitHub numeric user id and holds the repo owner/name, the
            result document, the prioritized findings, and the risk / posture / IAM
            / supply-chain summaries.
          </p>
          <p>
            Every secret inside that stored result is already masked (see below).
            The raw secret value is never part of what gets written.
          </p>
        </Callout>
      </Section>

      <Section title="Secrets are masked before anything is stored">
        <p className="leading-relaxed text-slate-300">
          When a secret pattern matches, the matched value is masked at the moment
          of detection &mdash; before it is attached to a finding, before the
          finding is returned, and before any persistence. Short values (8
          characters or fewer) become all bullets; longer values keep the first and
          last four characters with the middle replaced by bullets, and the line is
          truncated to 200 characters. The masked line is the only form that leaves
          memory.
        </p>
        <Callout variant="info" title="Example">
          <p className="font-mono text-xs text-slate-400">
            AKIAIOSFODNN7EXAMPLE &rarr; AKIA&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;MPLE
          </p>
        </Callout>
        <p className="mt-4 leading-relaxed text-slate-300">
          Optional secret <em>liveness</em> validation (does this key still work?)
          is off by default. It only runs on signed-in scans and only when a
          deployment-level flag is enabled; anonymous scans never trigger it. When
          it does run, the raw value is held in memory for the duration of that
          scan to make the check and is then dropped &mdash; it is never persisted
          and never included in the response body.
        </p>
      </Section>

      <Section title="Your code is read, analyzed, and discarded">
        <p className="leading-relaxed text-slate-300">
          Source code is fetched per scan through the GitHub API, analyzed entirely
          in memory, and never written to storage. There is no clone left on a
          disk, no copy of your files in a database. When the scan function
          returns, the file contents are gone with it.
        </p>
        <Callout variant="ok" title="No execution, no agent">
          <p>
            TriageRook never executes your code. Every detector is static analysis
            &mdash; pattern matching, entropy, AST walks, manifest parsing &mdash;
            run against file text. There is no sandbox running your build, no
            long-lived agent sitting inside your repo, and no background process
            after the scan finishes.
          </p>
        </Callout>
      </Section>

      <Section title="Your GitHub token never reaches the browser">
        <p className="leading-relaxed text-slate-300">
          The GitHub access token lives only on the encrypted session cookie and is
          read server-side. It is deliberately kept off the session object that{" "}
          <Code>/api/auth/session</Code> exposes to any same-origin script, so even
          a successful XSS cannot read it from the session JSON. Server code reads
          it from the encrypted cookie when it needs to call GitHub; it is never
          placed in a response body sent to the client.
        </p>
      </Section>

      <div className="mt-12 border-t border-slate-800/60 pt-8 text-sm text-slate-500">
        <p>
          Think a claim here overstates what the code does? That is a bug we want
          to fix.{" "}
          <a
            href="https://github.com/silviooerudon/triagerook/issues/new?title=Security%20docs%20feedback"
            target="_blank"
            rel="noopener noreferrer"
            className="text-amber-400 hover:underline"
          >
            Open an issue
          </a>
          .
        </p>
      </div>
    </div>
  )
}
