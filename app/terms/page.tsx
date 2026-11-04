import type { Metadata } from "next"
import Link from "next/link"
import { LegalPage, LegalSection } from "@/app/components/legal-ui"
import { LEGAL } from "@/lib/legal"

export const metadata: Metadata = {
  title: "Terms of Use",
  description:
    "The rules for using TriageRook: acceptable use, what the scanner does and does not promise, pricing and refunds, liability, and applicable law.",
  alternates: { canonical: "/terms" },
}

const TOC = [
  { id: "about", label: "About these terms" },
  { id: "service", label: "The service" },
  { id: "account", label: "Your account" },
  { id: "acceptable-use", label: "Acceptable use" },
  { id: "results", label: "What scan results do and do not mean" },
  { id: "your-content", label: "Your repositories and fix PRs" },
  { id: "pricing", label: "Pricing" },
  { id: "refunds", label: "Refund policy" },
  { id: "ip", label: "Intellectual property" },
  { id: "warranty", label: "Disclaimer" },
  { id: "liability", label: "Limitation of liability" },
  { id: "termination", label: "Suspension and termination" },
  { id: "changes", label: "Changes" },
  { id: "law", label: "Applicable law and disputes" },
  { id: "contact", label: "Operator details and contact" },
]

export default function TermsPage() {
  const mail = `mailto:${LEGAL.privacyEmail}`
  return (
    <LegalPage
      eyebrow="terms"
      title="Terms of Use"
      lastUpdated={LEGAL.lastUpdated}
      toc={TOC}
      intro={
        <p>
          Plain-language terms for a small, free security tool. Please read them —
          by using TriageRook you agree to them. Nothing here takes away rights you
          have as a consumer under the law of the country where you live.
        </p>
      }
    >
      <LegalSection id="about" title="1. About these terms">
        <p>
          These terms are an agreement between you and {LEGAL.operatorName}, who
          operates TriageRook from {LEGAL.operatorLocation} (&ldquo;we&rdquo;). How we
          handle personal data is described separately in the{" "}
          <Link href="/privacy" className="text-amber-400 hover:underline">Privacy Policy</Link>.
        </p>
      </LegalSection>

      <LegalSection id="service" title="2. The service">
        <p>
          TriageRook performs static, read-only analysis of public GitHub repositories
          and reports possible security issues. It never executes your code. It is
          provided free of charge, during a validation phase, with{" "}
          <strong>no service-level agreement</strong>: features, limits and
          availability may change, and the service may be interrupted. Current limits
          are documented at{" "}
          <Link href="/docs/scan-limits" className="text-amber-400 hover:underline">
            Scan limits
          </Link>
          .
        </p>
      </LegalSection>

      <LegalSection id="account" title="3. Your account">
        <p>
          Signing in uses your GitHub account through the TriageRook Security GitHub
          App. You must be at least 16, and you are responsible for activity under
          your account. You can stop using the service and erase your data at any
          time from{" "}
          <Link href="/dashboard/account" className="text-amber-400 hover:underline">
            Dashboard → Your data
          </Link>
          .
        </p>
      </LegalSection>

      <LegalSection id="acceptable-use" title="4. Acceptable use">
        <p>You agree not to:</p>
        <ul>
          <li>
            use secrets, credentials or other findings that TriageRook reveals in
            repositories you do not own to access any system, or otherwise exploit
            them — report them to the repository owner instead;
          </li>
          <li>
            scan repositories to harass, profile or target individuals, or to harvest
            personal data;
          </li>
          <li>
            circumvent rate limits, run automated bulk scanning, or put unreasonable
            load on TriageRook or GitHub;
          </li>
          <li>
            probe, attack or try to bypass the security of TriageRook itself, except
            through good-faith research reported as described on the{" "}
            <Link href="/security" className="text-amber-400 hover:underline">Security</Link>{" "}
            page;
          </li>
          <li>use the service in breach of GitHub&apos;s terms or of any law.</li>
        </ul>
      </LegalSection>

      <LegalSection id="results" title="5. What scan results do and do not mean">
        <p>
          TriageRook is an aid to triage, not an audit or a certification. Like every
          static analyser it produces <strong>false positives</strong> (issues that
          are not real) and <strong>false negatives</strong> (real issues it misses),
          and large repositories may be scanned only partially, which the report
          flags. A clean result does not mean a repository is secure. Risk, posture,
          IAM and supply-chain scores are heuristics describing a repository, not
          guarantees. Review every finding — and every fix PR — before acting on it.
        </p>
      </LegalSection>

      <LegalSection id="your-content" title="6. Your repositories and fix PRs">
        <p>
          You keep all rights in your code. You give us only the permission needed to
          read it during a scan you request and, if you use the Fix feature, to open a
          pull request with a suggested change on a repository where you installed
          the App. We never merge anything: you decide whether to accept a PR, and you
          are responsible for reviewing and testing it.
        </p>
      </LegalSection>

      <LegalSection id="pricing" title="7. Pricing">
        <p>
          TriageRook is currently <strong>free</strong> and we do not collect any
          payment details. The paid plan shown on{" "}
          <Link href="/pricing" className="text-amber-400 hover:underline">Pricing</Link>{" "}
          is not yet available. If paid plans launch, we will announce the price and
          terms in advance, and nobody will be charged without actively subscribing.
        </p>
      </LegalSection>

      <LegalSection id="refunds" title="8. Refund policy">
        <p>
          Because no payments are taken today, there is nothing to refund. If paid
          plans launch, the following will apply as a minimum, in addition to any
          stronger rights you have by law:
        </p>
        <ul>
          <li>
            <strong>EU/EEA consumers:</strong> a 14-day right of withdrawal from a new
            subscription with a full refund (Directive 2011/83/EU).
          </li>
          <li>
            <strong>Brazilian consumers:</strong> a 7-day right of withdrawal
            (<em>direito de arrependimento</em>) with a full refund, under Art. 49 of
            the Código de Defesa do Consumidor.
          </li>
          <li>
            Everyone: cancel any time, effective at the end of the current billing
            period; and a pro-rata refund if we discontinue a paid service you have
            prepaid.
          </li>
        </ul>
        <p>
          Refund requests will go to{" "}
          <a href={mail} className="text-amber-400 hover:underline">{LEGAL.privacyEmail}</a>{" "}
          and be paid back to the original payment method.
        </p>
      </LegalSection>

      <LegalSection id="ip" title="9. Intellectual property">
        <p>
          The TriageRook name, logo and site content belong to us. The detection rule
          catalogue references public standards such as CWE identifiers, which belong
          to their respective owners. TriageRook is not affiliated with or endorsed by
          GitHub, Inc.; GitHub is a trademark of GitHub, Inc.
        </p>
      </LegalSection>

      <LegalSection id="warranty" title="10. Disclaimer">
        <p>
          To the extent permitted by law, the service is provided &ldquo;as is&rdquo;
          and &ldquo;as available&rdquo;, without warranties of any kind, including
          that it will detect every issue or be uninterrupted or error-free. This does
          not affect statutory guarantees that cannot be excluded for consumers.
        </p>
      </LegalSection>

      <LegalSection id="liability" title="11. Limitation of liability">
        <p>
          As a free service, and to the extent permitted by law, we are not liable for
          indirect or consequential loss, loss of data, profits or business, or for
          security incidents in your own systems, arising from your use of — or
          reliance on — TriageRook. Nothing in these terms limits liability for death
          or personal injury caused by negligence, for fraud, for wilful misconduct or
          gross negligence, or any other liability that cannot be limited by law,
          including under consumer-protection law.
        </p>
      </LegalSection>

      <LegalSection id="termination" title="12. Suspension and termination">
        <p>
          You can stop using TriageRook at any time. We may limit or suspend access
          that breaches these terms or threatens the service or others. We may also
          discontinue the service; if we do, we will give reasonable notice where
          possible so you can export your data.
        </p>
      </LegalSection>

      <LegalSection id="changes" title="13. Changes">
        <p>
          We may update these terms. The date above shows the latest version, and
          material changes will be announced on the site before they take effect.
          Continuing to use the service afterwards means you accept the new terms.
        </p>
      </LegalSection>

      <LegalSection id="law" title="14. Applicable law and disputes">
        <p>
          These terms are governed by the laws of Ireland, and the Irish courts have
          jurisdiction. If you are a consumer, you also keep the protection of the
          mandatory laws of your country of residence and may bring proceedings
          there — for example, consumers in Brazil keep their rights under the
          Código de Defesa do Consumidor and the LGPD, and may sue in their own
          domicile. Please contact us first — most problems are quick to fix.
        </p>
      </LegalSection>

      <LegalSection id="contact" title="15. Operator details and contact">
        <ul>
          <li>Operator: {LEGAL.operatorName} ({LEGAL.operatorDescription})</li>
          <li>Location: {LEGAL.operatorLocation}</li>
          <li>
            Email:{" "}
            <a href={mail} className="text-amber-400 hover:underline">{LEGAL.privacyEmail}</a>
          </li>
        </ul>
      </LegalSection>
    </LegalPage>
  )
}
