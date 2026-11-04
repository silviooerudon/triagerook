// Single source of truth for the facts quoted on /privacy, /terms and the
// site footer. Legal copy must never drift from reality, so every page reads
// these values instead of restating them.
//
// Before changing anything here, check that the new value is TRUE today:
// these strings are statements made to users and regulators.

export const LEGAL = {
  // Data controller (GDPR Art. 4(7)) / "controlador" (LGPD Art. 5, VI).
  // TriageRook is operated by an individual, not a company.
  operatorName: "Silvio Junior de Almeida Gazzoli",
  operatorDescription: "an individual developer",
  operatorLocation: "Dublin, Ireland",

  // Channel for privacy requests (GDPR Art. 13(1)(a)/(b), LGPD Art. 41).
  // This mailbox MUST exist and be monitored — data-subject requests that
  // go unanswered are a compliance failure in themselves.
  privacyEmail: "privacy@triagerook.com",

  // Shown as "Last updated" on both legal pages. Bump on any material change.
  lastUpdated: "4 November 2026",

  // Supervisory authorities users may complain to.
  euAuthority: {
    name: "Data Protection Commission (Ireland)",
    url: "https://www.dataprotection.ie",
  },
  brAuthority: {
    name: "Autoridade Nacional de Proteção de Dados (ANPD, Brazil)",
    url: "https://www.gov.br/anpd",
  },
} as const

// Third parties that process personal data on TriageRook's behalf
// (processors / "operadores"), or that we exchange data with. Keep in sync
// with lib/supabase.ts, auth.ts, app/layout.tsx and next.config.ts CSP.
export const SUBPROCESSORS: {
  name: string
  role: string
  data: string
  location: string
  url: string
}[] = [
  {
    name: "Vercel Inc.",
    role: "Application hosting, runtime logs, privacy-friendly page analytics",
    data: "Request metadata (IP address, user agent, URL) while serving each request; aggregated, cookieless page-view statistics",
    location: "Global edge network; company based in the USA",
    url: "https://vercel.com/legal/privacy-policy",
  },
  {
    name: "Supabase Inc.",
    role: "Database",
    data: "Scan history, suppressions, pseudonymised rate-limit counters",
    location: "EU region",
    url: "https://supabase.com/privacy",
  },
  {
    name: "GitHub, Inc.",
    role: "Sign-in provider and source of repository content",
    data: "Your GitHub identity at sign-in; repository files read during a scan",
    location: "USA",
    url: "https://docs.github.com/site-policy/privacy-policies/github-general-privacy-statement",
  },
  {
    name: "Public package databases (OSV.dev, deps.dev, npm, PyPI, RubyGems)",
    role: "Vulnerability, license and supply-chain lookups",
    data: "Package names and versions from scanned manifests only — no personal data",
    location: "USA",
    url: "https://osv.dev",
  },
]
