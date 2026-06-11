// Single source of truth for the /docs sidebar and the hub index. Plain data
// (no "use client") so both the client sidebar and the server sitemap can
// import it without dragging client code into the server bundle.
//
// New pages from later PRs (detectors, posture-score, iam-risk-scanner,
// quickstart, faq, changelog) slot into these sections as they ship.

export type DocLink = {
  href: string
  label: string
  summary: string
}

export type DocSection = {
  title: string
  links: DocLink[]
}

export const DOC_SECTIONS: DocSection[] = [
  {
    title: "Start here",
    links: [
      {
        href: "/docs",
        label: "Overview",
        summary: "What TriageRook is, what these docs cover, and how to read them.",
      },
      {
        href: "/docs/quickstart",
        label: "Quickstart",
        summary: "Scan a repo in about 60 seconds — anonymous, signed in, or in CI.",
      },
      {
        href: "/docs/faq",
        label: "FAQ",
        summary:
          "Timeouts, rate limits, private repos, false positives, and why a scan might miss something.",
      },
    ],
  },
  {
    title: "Trust & data",
    links: [
      {
        href: "/docs/security-and-data-handling",
        label: "Security & data handling",
        summary:
          "The GitHub App permissions we ask for, what each scan endpoint stores, and how secrets are masked.",
      },
    ],
  },
  {
    title: "Scanning",
    links: [
      {
        href: "/docs/scan-limits",
        label: "Scan limits",
        summary:
          "Every per-run cap (files, time, file size, history depth), the paths skipped by design, and why each limit exists.",
      },
      {
        href: "/docs/suppressions",
        label: "Suppressions",
        summary:
          "Severities, the test-fixture flag, and the full .repoguardignore syntax with worked examples.",
      },
    ],
  },
  {
    title: "Reference",
    links: [
      {
        href: "/docs/detectors",
        label: "Detectors",
        summary:
          "The ten independent detectors: what each one finds, how it works, and what it deliberately does not catch.",
      },
      {
        href: "/docs/rules",
        label: "Detection rules",
        summary: "Every rule TriageRook checks, grouped by detection layer.",
      },
      {
        href: "/docs/posture-score",
        label: "Posture score",
        summary:
          "The 17 repo-posture signals, their weights, the A–F scale, and how unknown signals are handled.",
      },
      {
        href: "/docs/iam-risk-scanner",
        label: "IAM risk scanner",
        summary:
          "OIDC trust, privilege escalation, and admin-equivalent checks over IAM policy-as-code, with vulnerable vs fixed examples.",
      },
      {
        href: "/docs/sarif",
        label: "SARIF export",
        summary: "Send findings to GitHub Code Scanning.",
      },
      {
        href: "/docs/changelog",
        label: "Changelog",
        summary: "What shipped, by date, derived from merged pull requests.",
      },
    ],
  },
]

// Flattened list of all doc URLs, for the sitemap.
export const DOC_PATHS: string[] = DOC_SECTIONS.flatMap((s) =>
  s.links.map((l) => l.href),
)
