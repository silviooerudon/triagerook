import type { Metadata } from "next"
import { DocHeader, Section, Callout, Code, Pre } from "../_components/doc-ui"

export const metadata: Metadata = {
  title: "Suppressions",
  description:
    "Severities, the likelyTestFixture flag, and the full .repoguardignore syntax — pathGlob plus rule, reason, and expires modifiers — with worked, parser-tested examples.",
}

const SEVERITIES: { sev: string; cls: string; meaning: string }[] = [
  {
    sev: "critical",
    cls: "text-red-300 border-red-500/30 bg-red-500/10",
    meaning:
      "Directly exploitable or a live credential: a hardcoded secret, an injection sink reachable from user input, a public principal on a cloud policy.",
  },
  {
    sev: "high",
    cls: "text-orange-300 border-orange-500/30 bg-orange-500/10",
    meaning:
      "Serious weakness that needs prompt attention but usually needs a condition to exploit — a known-vulnerable dependency, a dangerous misconfiguration.",
  },
  {
    sev: "medium",
    cls: "text-yellow-300 border-yellow-500/30 bg-yellow-500/10",
    meaning:
      "Real hygiene or hardening issue worth fixing; lower blast radius or harder to reach. (Detector inputs that say “moderate” are normalized to medium.)",
  },
  {
    sev: "low",
    cls: "text-slate-400 border-slate-700 bg-slate-800/30",
    meaning:
      "Informational or best-practice nudge. Anything unrecognized is treated as low rather than dropped.",
  },
]

export default function SuppressionsPage() {
  return (
    <div className="max-w-3xl">
      <DocHeader eyebrow="scanning" title="Suppressions">
        Real repos have intentional secrets in fixtures, dependencies you cannot
        upgrade yet, and detector self-references. Suppressions let you silence a
        known finding without turning off the rule everywhere &mdash; checked in
        as a <Code>.repoguardignore</Code> file your whole team can review in a PR.
      </DocHeader>

      <Section title="Severities">
        <p className="mb-4 leading-relaxed text-slate-300">
          Every finding carries one of four severities. They drive ordering, the
          risk score, and the SARIF level on export.
        </p>
        <div className="space-y-3">
          {SEVERITIES.map((s) => (
            <div key={s.sev} className="flex items-start gap-3">
              <span
                className={`mt-0.5 shrink-0 rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider ${s.cls}`}
              >
                {s.sev}
              </span>
              <p className="text-sm leading-relaxed text-slate-400">
                {s.meaning}
              </p>
            </div>
          ))}
        </div>
      </Section>

      <Section title="The likelyTestFixture flag">
        <p className="leading-relaxed text-slate-300">
          A finding in a path that looks like test or example code &mdash;{" "}
          <Code>tests/</Code>, <Code>__tests__/</Code>, <Code>fixtures/</Code>,{" "}
          <Code>mocks/</Code>, <Code>examples/</Code>, <Code>samples/</Code>,{" "}
          <Code>testdata/</Code>, <Code>cypress/</Code>, <Code>e2e/</Code>, or a{" "}
          <Code>*.test.*</Code> / <Code>*.spec.*</Code> /{" "}
          <Code>*_test.go</Code> file &mdash; is tagged{" "}
          <Code>likelyTestFixture</Code>. It is not hidden: it is de-prioritized in
          the risk score and downgraded to <Code>note</Code> level in SARIF, so a
          dummy key in a fixture never blocks a merge gate but is still visible if
          you go looking. To remove it from the list entirely, suppress it.
        </p>
      </Section>

      <Section title=".repoguardignore — where and how">
        <p className="leading-relaxed text-slate-300">
          Put a <Code>.repoguardignore</Code> file at the root of your repository.
          It is fetched best-effort at scan time, does not count against the file
          cap, and a missing or malformed file never fails the scan. One
          suppression per line; blank lines and lines starting with{" "}
          <Code>#</Code> are ignored.
        </p>
        <Pre>{`# pathGlob [rule=glob] [reason="text"] [expires=YYYY-MM-DD]
# Comments start with #`}</Pre>
        <p className="mt-4 leading-relaxed text-slate-300">
          The first token (up to the first space, tab, or <Code>[</Code>) is the{" "}
          <strong>path glob</strong>. Everything after it is optional modifiers in
          square brackets. Path matching uses glob semantics (<Code>*</Code> within
          a segment, <Code>**</Code> across segments, dotfiles included), so{" "}
          <Code>*</Code> on its own matches every path.
        </p>
      </Section>

      <Section title="Modifiers">
        <ul className="space-y-3 text-sm leading-relaxed text-slate-300">
          <li>
            <Code>[rule=glob]</Code> &mdash; restrict the suppression to matching
            rule ids. Globs work here too, so <Code>[rule=secret/*]</Code> covers
            every secret pattern. Omit it and the suppression silences{" "}
            <em>every</em> finding under the path.
          </li>
          <li>
            <Code>[reason=&quot;text&quot;]</Code> &mdash; a note for whoever reads
            the file later. Quote it if it contains spaces.
          </li>
          <li>
            <Code>[expires=YYYY-MM-DD]</Code> &mdash; an expiry date (valid through
            the end of that day, UTC). Forces stale suppressions to be revisited
            (see below). An invalid date is ignored.
          </li>
        </ul>
      </Section>

      <Section title="Rule ids">
        <p className="mb-3 leading-relaxed text-slate-300">
          The <Code>rule</Code> modifier matches against the finding&apos;s rule
          id. The shapes:
        </p>
        <Pre>{`secret/<patternId>          e.g. secret/aws-access-key
entropy/<id>                high-entropy string findings
git-history/<patternId>     secret found in commit history
code/<ruleId>               SAST findings  (also matches code/<cwe>, e.g. code/cwe-89)
iac/<ruleId>                IaC findings   (also matches iac/<category>)
sensitive-file/<kind>       committed sensitive files
dependency/<package>        vulnerable dependency  (also dependency/<ghsa>)
license/<package>           license/compliance findings`}</Pre>
        <p className="mt-3 text-sm leading-relaxed text-slate-400">
          For dependency and license findings, the path is matched against every
          manifest in that ecosystem, so{" "}
          <Code>package.json [rule=dependency/lodash]</Code> also covers a
          transitive hit recorded against the lockfile.
        </p>
      </Section>

      <Section title="Examples (each tested against the real parser)">
        <p className="mb-4 text-sm leading-relaxed text-slate-400">
          Every line below was run through TriageRook&apos;s actual suppression
          parser and matcher while writing this page.
        </p>

        <p className="mb-2 text-sm text-slate-300">
          Silence one secret rule in one file:
        </p>
        <Pre>{`src/config.ts [rule=secret/aws-access-key]`}</Pre>

        <p className="mb-2 mt-6 text-sm text-slate-300">
          Silence <em>everything</em> under a directory (no rule modifier):
        </p>
        <Pre>{`tests/** [reason="intentional fixtures"]`}</Pre>

        <p className="mb-2 mt-6 text-sm text-slate-300">
          Accept one dependency CVE anywhere it appears, with a deadline to
          re-check:
        </p>
        <Pre>{`package.json [rule=dependency/postcss] [reason="upstream Next ships old postcss"] [expires=2026-08-01]`}</Pre>

        <p className="mb-2 mt-6 text-sm text-slate-300">
          Wildcard a whole rule family for a detector self-reference:
        </p>
        <Pre>{`lib/secret-patterns.ts [rule=secret/*] [reason="detector's own pattern library"]`}</Pre>

        <p className="mb-2 mt-6 text-sm text-slate-300">
          Suppress a SAST finding by its CWE alias:
        </p>
        <Pre>{`src/db.ts [rule=code/cwe-89] [reason="parameterized elsewhere"]`}</Pre>
      </Section>

      <Section title="How a match is chosen">
        <p className="leading-relaxed text-slate-300">
          A finding is suppressed when its path matches a suppression&apos;s path
          glob and &mdash; if a <Code>rule</Code> modifier is present &mdash; its
          rule id matches too. When several lines could apply, the most specific
          wins: a line with a <Code>rule</Code> modifier and a literal (non-glob)
          path outranks a broad <Code>*</Code> line, with file order as the
          tiebreaker.
        </p>
      </Section>

      <Section title="When a suppression expires">
        <Callout variant="warn" title="Expired ≠ silently ignored">
          <p>
            Once an <Code>expires</Code> date has passed, the suppression{" "}
            <strong>still applies</strong> (the finding stays out of your main
            list), but it is flagged as expired and the scan surfaces an{" "}
            <strong>&ldquo;expired suppressions&rdquo; banner</strong>. The point is
            to force a deliberate decision &mdash; renew it or remove it &mdash;
            rather than letting a one-time exception quietly hide a finding
            forever.
          </p>
        </Callout>
      </Section>

      <Section title="Known limitation">
        <p className="leading-relaxed text-slate-300">
          Because the path glob ends at the first <Code>[</Code>, a path that
          itself contains a glob character class &mdash; like{" "}
          <Code>tests/file[123].js</Code> &mdash; is cut at the bracket and the
          rest is misread as a modifier. Avoid character classes in the path glob;
          a plain <Code>*</Code> / <Code>**</Code> covers almost every real case.
        </p>
      </Section>

      <div className="mt-12 border-t border-slate-800/60 pt-8 text-sm text-slate-500">
        <p>
          A suppression not matching when you expect it to? Paste the line and the
          finding&apos;s rule id into an{" "}
          <a
            href="https://github.com/silviooerudon/triagerook/issues/new?title=Suppression%20feedback"
            target="_blank"
            rel="noopener noreferrer"
            className="text-amber-400 hover:underline"
          >
            issue
          </a>
          .
        </p>
      </div>
    </div>
  )
}
