import type { Metadata } from "next"
import Link from "next/link"
import { LegalPage, LegalSection, ExtLink } from "@/app/components/legal-ui"
import { LEGAL, SUBPROCESSORS } from "@/lib/legal"

export const metadata: Metadata = {
  title: "Privacy Policy",
  description:
    "What personal data TriageRook collects, why, the legal basis, who processes it, how long it is kept, and how to exercise your rights under the GDPR and Brazil's LGPD.",
  alternates: { canonical: "/privacy" },
}

const TOC = [
  { id: "who", label: "Who is responsible" },
  { id: "what", label: "What we collect" },
  { id: "bases", label: "Why we use it and on what legal basis" },
  { id: "cookies", label: "Cookies, analytics and tracking" },
  { id: "sharing", label: "Who we share data with" },
  { id: "transfers", label: "International transfers" },
  { id: "retention", label: "How long we keep data" },
  { id: "rights", label: "Your rights and how to use them" },
  { id: "repo-data", label: "Personal data inside repositories you scan" },
  { id: "security", label: "Security" },
  { id: "children", label: "Children" },
  { id: "changes", label: "Changes to this policy" },
]

// Cookies set by TriageRook. Every one is strictly necessary for sign-in
// (Auth.js), which is why there is no consent banner — see the
// "cookies" section. If a non-essential cookie is ever added, a consent
// mechanism MUST be added before it ships.
const COOKIES = [
  {
    name: "__Secure-authjs.session-token",
    purpose: "Keeps you signed in. Encrypted; holds your GitHub id and access token, readable only by our server.",
    duration: "Up to 30 days, or until you sign out",
  },
  {
    name: "__Host-authjs.csrf-token",
    purpose: "Protects the sign-in and sign-out forms against cross-site request forgery.",
    duration: "Browser session",
  },
  {
    name: "__Secure-authjs.callback-url",
    purpose: "Remembers which page to return you to after sign-in.",
    duration: "Browser session",
  },
  {
    name: "__Secure-authjs.state / pkce.code_verifier",
    purpose: "Short-lived values that secure the GitHub sign-in handshake.",
    duration: "About 15 minutes",
  },
]

const BASES = [
  {
    purpose: "Provide the service you asked for: sign-in, scanning, saved history, fix PRs",
    data: "GitHub id, username, scan results",
    gdpr: "Contract — Art. 6(1)(b)",
    lgpd: "Execução de contrato — Art. 7, V",
  },
  {
    purpose: "Prevent abuse of anonymous scans (rate limiting)",
    data: "Pseudonymised (keyed-hash) IP address",
    gdpr: "Legitimate interests — Art. 6(1)(f)",
    lgpd: "Legítimo interesse — Art. 7, IX",
  },
  {
    purpose: "Keep the service secure and working (runtime logs, debugging)",
    data: "Request metadata held by our host",
    gdpr: "Legitimate interests — Art. 6(1)(f)",
    lgpd: "Legítimo interesse — Art. 7, IX",
  },
  {
    purpose: "Understand which pages are used, in aggregate",
    data: "Cookieless page-view statistics",
    gdpr: "Legitimate interests — Art. 6(1)(f)",
    lgpd: "Legítimo interesse — Art. 7, IX",
  },
  {
    purpose: "Answer messages and privacy requests",
    data: "Your email address and message",
    gdpr: "Legal obligation / legitimate interests — Art. 6(1)(c)/(f)",
    lgpd: "Obrigação legal / exercício de direitos — Art. 7, II e VI",
  },
]

const RETENTION = [
  { what: "Saved scans and suppressions (signed-in users)", how: "Until you delete them or delete your data from the account page" },
  { what: "Anonymous scan results", how: "Not stored — returned to your browser and discarded" },
  { what: "Rate-limit counters (pseudonymised IP)", how: "About 1 hour of use; stale counters are purged automatically" },
  { what: "Scanned source code", how: "Never stored — held in memory only for the duration of a scan" },
  { what: "Hosting runtime logs", how: "Short-lived, per our host's log retention (days, not months); they never contain IPs from our own log lines" },
  { what: "Emails you send us", how: "As long as needed to resolve your request, then deleted within 12 months" },
]

export default function PrivacyPage() {
  const mail = `mailto:${LEGAL.privacyEmail}`
  return (
    <LegalPage
      eyebrow="privacy"
      title="Privacy Policy"
      lastUpdated={LEGAL.lastUpdated}
      toc={TOC}
      intro={
        <>
          <p>
            TriageRook scans public GitHub repositories for security problems. We
            collect as little personal data as the product allows, we do not sell it,
            we do not show ads, and we do not use your code to train AI models.
          </p>
          <p>
            This policy applies to everyone who uses www.triagerook.com, wherever you
            are. It is written to meet the EU General Data Protection Regulation
            (GDPR) and Brazil&apos;s Lei Geral de Proteção de Dados (LGPD, Lei nº
            13.709/2018). For the technical detail behind each claim, see{" "}
            <Link href="/docs/security-and-data-handling" className="text-amber-400 hover:underline">
              Security &amp; data handling
            </Link>
            .
          </p>
        </>
      }
    >
      <LegalSection id="who" title="1. Who is responsible">
        <p>
          The data controller (<em>controlador</em> under the LGPD) is{" "}
          <strong>{LEGAL.operatorName}</strong>, {LEGAL.operatorDescription} based in{" "}
          {LEGAL.operatorLocation}, who operates TriageRook (&ldquo;we&rdquo;,
          &ldquo;us&rdquo;).
        </p>
        <p>
          Privacy contact, including for the LGPD <em>encarregado</em> role:{" "}
          <a href={mail} className="text-amber-400 hover:underline">
            {LEGAL.privacyEmail}
          </a>
          . As a small-scale operator we have not appointed a formal Data Protection
          Officer; this address reaches the controller directly.
        </p>
      </LegalSection>

      <LegalSection id="what" title="2. What we collect">
        <h3>If you just browse the site</h3>
        <p>
          No account, no cookies. Our host necessarily processes your IP address and
          browser details to deliver each page. We measure page views with Vercel Web
          Analytics, which uses no cookies and no persistent identifiers (see{" "}
          <a href="#cookies" className="text-amber-400 hover:underline">section 4</a>).
        </p>

        <h3>If you scan a repository without signing in</h3>
        <ul>
          <li>The repository owner/name you submit.</li>
          <li>
            A <strong>pseudonymised</strong> form of your IP address — a keyed hash,
            never the raw IP — used only to count scans per hour against abuse.
          </li>
        </ul>
        <p>The scan result itself is sent to your browser and not stored.</p>

        <h3>If you sign in with GitHub</h3>
        <ul>
          <li>
            From GitHub: your numeric user id, username, display name, avatar URL and
            the email address GitHub shares with the App. The id is what we store
            your data under; the rest is kept only inside your encrypted session
            cookie to show who is signed in.
          </li>
          <li>
            Saved scan results: repository name, timestamps, findings (file paths,
            line numbers, rule ids, <strong>masked</strong> previews of detected
            secrets, vulnerable package names) and scores.
          </li>
          <li>Suppressions you create, including any free-text reason you type.</li>
          <li>
            A GitHub access token, kept only inside your encrypted session cookie —
            never in our database and never sent to your browser in readable form.
          </li>
        </ul>

        <h3>If you contact us</h3>
        <p>Your email address and whatever you choose to write.</p>

        <h3>What we never collect</h3>
        <ul>
          <li>Your source code (it is read in memory during a scan and discarded).</li>
          <li>Full values of secrets found in your code.</li>
          <li>Private repositories — scanning them is refused in code.</li>
          <li>Payment details — the service is free and takes no payments.</li>
          <li>Special categories of data (health, religion, biometrics, etc.).</li>
        </ul>
      </LegalSection>

      <LegalSection id="bases" title="3. Why we use it and on what legal basis">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <caption className="sr-only">Purposes of processing and legal bases</caption>
            <thead>
              <tr className="border-b border-slate-700 text-left">
                <th scope="col" className="py-2 pr-4 font-mono text-xs uppercase tracking-wider text-slate-400">Purpose</th>
                <th scope="col" className="py-2 pr-4 font-mono text-xs uppercase tracking-wider text-slate-400">Data</th>
                <th scope="col" className="py-2 pr-4 font-mono text-xs uppercase tracking-wider text-slate-400">GDPR</th>
                <th scope="col" className="py-2 font-mono text-xs uppercase tracking-wider text-slate-400">LGPD</th>
              </tr>
            </thead>
            <tbody>
              {BASES.map((b) => (
                <tr key={b.purpose} className="border-b border-slate-800 align-top">
                  <td className="py-3 pr-4 text-slate-200">{b.purpose}</td>
                  <td className="py-3 pr-4 text-slate-300">{b.data}</td>
                  <td className="py-3 pr-4 text-slate-300">{b.gdpr}</td>
                  <td className="py-3 text-slate-300">{b.lgpd}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p>
          Where we rely on legitimate interests, we have checked that the processing
          is minimal and expected, and you can object at any time (section 8). We do
          not make automated decisions that have legal or similarly significant
          effects on you. Risk scores rate repositories, not people.
        </p>
      </LegalSection>

      <LegalSection id="cookies" title="4. Cookies, analytics and tracking">
        <p>
          TriageRook sets <strong>only strictly necessary cookies</strong>, and only
          once you start signing in. They are exempt from consent under the EU
          ePrivacy rules because the service cannot work without them, which is why
          there is no cookie banner. We will ask for consent before ever adding a
          cookie that is not strictly necessary.
        </p>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <caption className="sr-only">Cookies used by TriageRook</caption>
            <thead>
              <tr className="border-b border-slate-700 text-left">
                <th scope="col" className="py-2 pr-4 font-mono text-xs uppercase tracking-wider text-slate-400">Cookie</th>
                <th scope="col" className="py-2 pr-4 font-mono text-xs uppercase tracking-wider text-slate-400">Purpose</th>
                <th scope="col" className="py-2 font-mono text-xs uppercase tracking-wider text-slate-400">Duration</th>
              </tr>
            </thead>
            <tbody>
              {COOKIES.map((c) => (
                <tr key={c.name} className="border-b border-slate-800 align-top">
                  <td className="py-3 pr-4 font-mono text-xs text-amber-200 break-all">{c.name}</td>
                  <td className="py-3 pr-4 text-slate-300">{c.purpose}</td>
                  <td className="py-3 text-slate-300">{c.duration}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <ul>
          <li>
            <strong>Analytics:</strong> Vercel Web Analytics counts page views without
            cookies, without fingerprinting and without tracking you across sites or
            days. If your browser sends a <em>Global Privacy Control</em> or{" "}
            <em>Do Not Track</em> signal, we do not send analytics events at all.
          </li>
          <li>
            <strong>No</strong> Google Analytics, Meta Pixel, advertising networks,
            session-replay tools, or other third-party tracking scripts.
          </li>
          <li>
            Fonts are self-hosted, so loading a page does not contact Google or any
            font CDN.
          </li>
        </ul>
      </LegalSection>

      <LegalSection id="sharing" title="5. Who we share data with">
        <p>
          We never sell or rent personal data and never share it for advertising.
          We use the providers below to run the service; hosting and database
          providers act as our processors under data-processing agreements.
        </p>
        <ul>
          {SUBPROCESSORS.map((s) => (
            <li key={s.name}>
              <strong>{s.name}</strong> — {s.role}. Data: {s.data}. Location:{" "}
              {s.location}. <ExtLink href={s.url}>Privacy policy</ExtLink>
            </li>
          ))}
        </ul>
        <p>
          If a deployment-level secret <em>liveness</em> check is enabled, a secret
          found in a repository you scan while signed in may be sent once to the
          provider that issued it (for example GitHub or Stripe) to see whether it
          still works. That secret belongs to the repository, not to you, and is
          never stored. Anonymous scans never do this.
        </p>
        <p>
          We may disclose data if required by law or a valid order from a competent
          authority, and only to the extent required.
        </p>
      </LegalSection>

      <LegalSection id="transfers" title="6. International transfers">
        <p>
          Our database is in the EU. Some providers (Vercel, GitHub) are US
          companies and may process request data outside the European Economic Area
          and Brazil. Those transfers rely on the EU–US Data Privacy Framework where
          the provider is certified, and otherwise on the European Commission&apos;s
          Standard Contractual Clauses — safeguards also recognised under LGPD Art.
          33. You can ask us for details.
        </p>
      </LegalSection>

      <LegalSection id="retention" title="7. How long we keep data">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <caption className="sr-only">Retention periods</caption>
            <thead>
              <tr className="border-b border-slate-700 text-left">
                <th scope="col" className="py-2 pr-4 font-mono text-xs uppercase tracking-wider text-slate-400">Data</th>
                <th scope="col" className="py-2 font-mono text-xs uppercase tracking-wider text-slate-400">Kept for</th>
              </tr>
            </thead>
            <tbody>
              {RETENTION.map((r) => (
                <tr key={r.what} className="border-b border-slate-800 align-top">
                  <td className="py-3 pr-4 text-slate-200">{r.what}</td>
                  <td className="py-3 text-slate-300">{r.how}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </LegalSection>

      <LegalSection id="rights" title="8. Your rights and how to use them">
        <p>Under the GDPR and the LGPD (Art. 18) you can:</p>
        <ul>
          <li>confirm whether we process your data and get a copy of it (access);</li>
          <li>receive it in a portable, machine-readable format (portability);</li>
          <li>have inaccurate data corrected;</li>
          <li>have your data deleted (erasure), or anonymised or blocked where excessive;</li>
          <li>object to, or ask us to restrict, processing based on legitimate interests;</li>
          <li>know who we share data with, and withdraw consent where we rely on it;</li>
          <li>complain to a data protection authority.</li>
        </ul>
        <h3>Self-service</h3>
        <p>
          Signed-in users can download all their data and permanently delete it from{" "}
          <Link href="/dashboard/account" className="text-amber-400 hover:underline">
            Dashboard → Your data
          </Link>
          . Deletion erases every saved scan and suppression, revokes TriageRook&apos;s
          GitHub authorization, and signs you out. You can also revoke access at any
          time in your{" "}
          <ExtLink href="https://github.com/settings/apps/authorizations">
            GitHub settings
          </ExtLink>
          .
        </p>
        <h3>By email</h3>
        <p>
          Write to{" "}
          <a href={mail} className="text-amber-400 hover:underline">
            {LEGAL.privacyEmail}
          </a>
          . We may need to confirm you control the GitHub account concerned before
          acting. We answer within one month (GDPR) and provide a full statement
          within 15 days when requested under LGPD Art. 19. Requests are free.
        </p>
        <h3>Complaints</h3>
        <p>
          You can complain to the <ExtLink href={LEGAL.euAuthority.url}>{LEGAL.euAuthority.name}</ExtLink>,
          to your local EU authority, or to the{" "}
          <ExtLink href={LEGAL.brAuthority.url}>{LEGAL.brAuthority.name}</ExtLink>. We
          would appreciate the chance to fix the problem first.
        </p>
      </LegalSection>

      <LegalSection id="repo-data" title="9. Personal data inside repositories you scan">
        <p>
          Public repositories can contain other people&apos;s personal data — for
          example, a git-history finding records the commit author&apos;s name and
          the commit date for the commit that introduced a secret. We process this
          only to show you where a security problem came from, it is already public
          on GitHub, and for signed-in users it is stored only inside your own scan
          history. Please only scan repositories you have a legitimate reason to
          assess (see the <Link href="/terms" className="text-amber-400 hover:underline">Terms</Link>).
        </p>
      </LegalSection>

      <LegalSection id="security" title="10. Security">
        <p>
          HTTPS everywhere with HSTS; encrypted session cookies; the GitHub token is
          never exposed to browser JavaScript; secrets are masked at detection time;
          database row-level security as a safety net; least-privilege GitHub App
          permissions; and public repositories only. If we ever suffer a breach
          likely to put you at risk, we will notify the competent authority and
          affected users as the GDPR (Art. 33–34) and LGPD (Art. 48) require.
        </p>
        <p>
          Found a vulnerability? Please report it privately — see{" "}
          <Link href="/security" className="text-amber-400 hover:underline">Security</Link>.
        </p>
      </LegalSection>

      <LegalSection id="children" title="11. Children">
        <p>
          TriageRook is a developer tool and is not directed at children. You must be
          at least 16 to sign in. If you believe a child has given us personal data,
          contact us and we will delete it.
        </p>
      </LegalSection>

      <LegalSection id="changes" title="12. Changes to this policy">
        <p>
          We will update the date above whenever this policy changes, and give
          signed-in users notice on the site before any change that materially
          reduces their rights or expands what we collect.
        </p>
      </LegalSection>
    </LegalPage>
  )
}
