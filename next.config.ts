import type { NextConfig } from "next";

// Baseline security headers applied to every response.
//
// - Strict-Transport-Security: 2y HSTS preload — RepoGuard is HTTPS-only
// - X-Content-Type-Options: nosniff (browser MIME-sniff defence)
// - X-Frame-Options: DENY (clickjacking — no iframing this app at all)
// - Referrer-Policy: strict-origin-when-cross-origin (URL leak defence)
// - Permissions-Policy: deny features we don't use, includes the
//   interest-cohort opt-out (no FLoC) to keep the privacy stance crisp
// - Content-Security-Policy-Report-Only: starts CSP in observation mode.
//   Browsers will report violations to the console but NOT block the
//   request. Lets us collect violation data and tune the policy before
//   flipping to enforcing mode (Content-Security-Policy proper). Without
//   a nonce-aware middleware, full-strict CSP would have to allow
//   'unsafe-inline' on script-src to keep Next.js RSC + Vercel analytics
//   working, which defeats the purpose. Nonce-aware CSP is the next step.
const CSP_REPORT_ONLY = [
  "default-src 'self'",
  // 'unsafe-inline' / 'unsafe-eval' are allowed for now — Next.js Turbopack
  // emits inline scripts for hydration. The report-only mode logs every
  // such inline so the future enforcing version can replace them with a
  // nonce or hash.
  "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://va.vercel-scripts.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https:",
  "font-src 'self' data:",
  "connect-src 'self' https://api.github.com https://*.supabase.co https://vitals.vercel-insights.com https://va.vercel-scripts.com",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self' https://github.com",
  "object-src 'none'",
  "upgrade-insecure-requests",
].join("; ");

const SECURITY_HEADERS = [
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value:
      "camera=(), microphone=(), geolocation=(), interest-cohort=(), payment=(), usb=()",
  },
  {
    key: "Content-Security-Policy-Report-Only",
    value: CSP_REPORT_ONLY,
  },
];

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: SECURITY_HEADERS,
      },
    ];
  },
};

export default nextConfig;
