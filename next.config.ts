import type { NextConfig } from "next";

// Baseline security headers applied to every response. Intentionally
// excludes Content-Security-Policy for now — CSP in Next.js requires
// a per-request nonce for the React Server Component inline scripts
// (and for the Vercel analytics snippet), which adds enough surface
// to deserve its own change. The other five headers are zero-risk and
// closed the corresponding MEDIUM finding from the pre-distribution
// audit.
//
// - Strict-Transport-Security: 2y HSTS preload — RepoGuard is HTTPS-only
// - X-Content-Type-Options: nosniff (browser MIME-sniff defence)
// - X-Frame-Options: DENY (clickjacking — no iframing this app at all)
// - Referrer-Policy: strict-origin-when-cross-origin (URL leak defence)
// - Permissions-Policy: deny features we don't use, includes the
//   interest-cohort opt-out (no FLoC) to keep the privacy stance crisp
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
