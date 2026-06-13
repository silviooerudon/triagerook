import Link from "next/link"
import type { Metadata } from "next"
import { DocHeader, Section, Callout } from "../_components/doc-ui"
import { DETECTOR_SLUGS, type DetectorSlug } from "@/lib/detectors"

export const metadata: Metadata = {
  title: "Detectors",
  description:
    "The eleven independent detectors TriageRook runs over a repo: what each one finds, the real method it uses (regex, Shannon entropy, AST, OSV, Damerau-Levenshtein, posture signals), and what it deliberately does not catch.",
}

type Detector = {
  n: number
  title: string
  detects: string
  how: string
  doesnt: string
  link?: { href: string; label: string }
}

// Each blurb is derived from the code (lib/scan.ts pipeline, lib/secret-patterns,
// lib/entropy, lib/history, lib/ast, lib/code-vulns, lib/deps + OSV scanners,
// lib/iac*, lib/supply-chain*, lib/posture, lib/iam*, lib/licenses*) and kept
// consistent with the README's "eleven independent detectors" framing.
// Keyed by canonical slug (lib/detectors.ts): the Record<DetectorSlug, …>
// forces this page to cover exactly the eleven detectors the landing page
// does, and the rendered numbering is derived from DETECTOR_SLUGS so the two
// can never disagree on order.
const DOC_DETECTORS: Record<DetectorSlug, Omit<Detector, "n">> = {
  "secret-scanner": {
    title: "Secrets in source code",
    detects:
      "Live-shaped credentials in text files: cloud keys (AWS/Azure/GCP and friends), SCM tokens (GitHub classic/fine-grained/OAuth/App, GitLab, Bitbucket), AI provider keys, payment keys, messaging and monitoring tokens, private-key blocks, and auth-bearing URIs.",
    how: "High-confidence regex patterns, one per known credential format. The matched value is masked the instant it is found, before it is attached to a finding or persisted.",
    doesnt:
      "A credential in a format with no published pattern. Custom/corporate tokens with no fixed shape are the entropy detector's job (below); a value with a truly novel format may be missed by both.",
    link: { href: "/docs/rules", label: "Secret pattern rules" },
  },
  "sensitive-files": {
    title: "Sensitive files committed to the repo",
    detects:
      "Files that should never be in version control regardless of contents: *.pem / *.key, *.pfx / .p12 / .jks / .keystore, SSH private keys, KeePass vaults, .env.production, cloud credential files, kubeconfig, .npmrc with auth, terraform.tfstate, database dumps, .git-credentials, .htpasswd.",
    how: "Filename / path / extension / content-header matching — not a regex over the file body. Only the path is recorded, never the contents.",
    doesnt:
      "A sensitive file hidden under a non-standard name, or a secret embedded inside an otherwise-ordinary file (that is detectors 1 and 3).",
    link: { href: "/docs/rules", label: "Sensitive file rules" },
  },
  entropy: {
    title: "High-entropy secrets in config files",
    detects:
      "Custom secrets in .env, .envrc, .ini, .toml, .yaml, .properties, and .conf files that no regex knows about.",
    how: "Parses KEY=VALUE pairs, discards obvious placeholders (xxx, changeme, URLs, semver, IPs), and flags values with Shannon entropy at or above 4.0 bits/char whose key name looks secret-bearing (password, secret, api_key, token, …).",
    doesnt:
      "High-entropy values whose key name does not look like a secret, or secrets outside the recognized config file types. Tuned to favor few false positives over total coverage.",
    link: { href: "/docs/rules", label: "Secret pattern rules" },
  },
  "git-history": {
    title: "Secrets in recent git history",
    detects:
      "Credentials that were committed and later removed — still leaked, still in the history.",
    how: "Replays up to the 30 most recent commits, extracts the added lines from each patch, and re-runs the full secret pattern library over them. Findings are deduplicated against the current tree so only history-exclusive matches surface, tagged with commit SHA + author + date.",
    doesnt:
      "Anything older than the 30-commit window, individual commit patches larger than 200 KB (skipped), or history that was rewritten away. Best-effort: if GitHub rate-limits the history pass it is skipped and reported, not assumed clean.",
    link: { href: "/docs/scan-limits", label: "Scan limits" },
  },
  "code-sast": {
    title: "Code-level vulnerabilities (SAST)",
    detects:
      "Injection (SQL, command, NoSQL, SSTI, prototype pollution, XXE), XSS, SSRF / open redirect, auth/JWT mistakes, weak crypto, path traversal, dynamic eval, ReDoS, insecure transport, cookie/session hygiene, insecure deserialization, info disclosure — each mapped to a CWE.",
    how: "Two layers run side by side: AST analysis via the TypeScript Compiler API (ts-morph) over JS/TS that tracks user input into dangerous sinks across property hops, plus conservative single-line regex rules for JS/TS and Python where AST would be overkill. A third framework-aware layer fires stack-specific checks only when it detects the framework (Next.js, Express, NestJS, Django, Flask, FastAPI, Spring, Laravel, Rails).",
    doesnt:
      "Deep cross-file/interprocedural dataflow. Coverage is primarily JavaScript/TypeScript; Python is covered by the regex layer; other languages are not analyzed for code vulns.",
    link: { href: "/docs/rules", label: "SAST rules" },
  },
  deps: {
    title: "Vulnerable dependencies (SCA)",
    detects:
      "Known-vulnerable packages across npm, PyPI, Go, RubyGems, Maven/Gradle, and Composer, plus container-image OS-package CVEs. End-of-life Docker base images are flagged statically too.",
    how: "Parses lockfiles/manifests and queries the npm advisory bulk API and OSV.dev, linking each finding to its GHSA/CVE. Container CVEs are ingested from a Trivy SARIF report you run in CI and commit. One shared OSV core, a 500-package cap, and a registry outage marks the detector skipped rather than failing the scan.",
    doesnt:
      "Vulnerabilities with no advisory published yet, versions that cannot be resolved statically (property-interpolated or dynamic ranges), and live image scanning — that is delegated to the Trivy report you provide.",
    link: { href: "/docs/scan-limits", label: "Scan limits" },
  },
  "supply-chain": {
    title: "Supply-chain attacks (typosquatting, install hooks, dependency confusion)",
    detects:
      "Malicious or hijacked dependencies before they run: typosquatted package names, install-time lifecycle-hook abuse in package.json scripts and Python setup.py / pyproject build hooks, and registry signals — dependency confusion (a declared name that 404s on the public registry), freshly-published packages, and suspicious-maintainer flags.",
    how: "Typosquatting uses Damerau-Levenshtein edit distance against popular npm/PyPI names. Lifecycle hooks are pattern-matched for curl|sh, base64 decode-and-execute, env-var exfiltration, and destructive rm -rf chains. Registry signals come from public npm registry metadata.",
    doesnt:
      "Deep behavioral analysis of package source, or ecosystems beyond npm/PyPI for the registry-metadata signals.",
    link: { href: "/docs/rules", label: "Supply-chain rules" },
  },
  "ci-iac": {
    title: "Infrastructure & CI misconfiguration (IaC)",
    detects:
      "Dockerfile hygiene, risky GitHub Actions workflows (pull_request_target with PR checkout, unpinned third-party actions, script injection), Terraform / CloudFormation / Kubernetes / Helm misconfig, and over-privileged cloud IAM declared in code (AWS/GCP/Azure/GitHub scopes).",
    how: "Line- and structure-based checks per file type, each self-guarding on file shape so non-matching YAML/JSON is skipped.",
    doesnt:
      "Misconfig in IaC formats not listed here, or runtime cloud state — these read your committed files, not your live cloud accounts.",
    link: { href: "/docs/rules", label: "IaC & Cloud IAM rules" },
  },
  posture: {
    title: "Repository posture score",
    detects:
      "How the repo is set up rather than a specific bug: branch protection, governance docs, dependency-update hygiene, signed commits, org MFA, secret scanning, least-privilege workflow tokens, release provenance — 17 signals in four groups, graded A–F.",
    how: "Reads repo metadata, files, branch protection / rulesets, and commit verification via the GitHub API, then scores the percentage of assessable signals earned. Signals it cannot inspect are reported as unknown and excluded from the math.",
    doesnt:
      "Penalize you for signals it cannot see (admin-only settings on a public scan show as unknown, not failed).",
    link: { href: "/docs/posture-score", label: "Posture score" },
  },
  "iam-risk": {
    title: "IAM risk scanner",
    detects:
      "Identity-and-access risk in the IAM policy documents you commit: GitHub Actions OIDC trust weaknesses (no Condition, wildcard repo/ref, pull_request trust), privilege-escalation patterns, and admin-equivalent grants.",
    how: "Selects IAM-shaped files from the tree (Terraform, CloudFormation/SAM, JSON policy docs, serverless.yml), extracts policy statements, and runs the three check families over them. Findings deduct from a 100-point score that maps to a low/medium/high/critical level.",
    doesnt:
      "Inspect your live cloud accounts or org settings — it reads policy-as-code, not the AWS/GCP/Azure control plane. (Org MFA enforcement is a posture signal, detector 9, not part of this scanner.)",
  },
  license: {
    title: "Open-source license / compliance risk",
    detects:
      "Legal rather than security risk: strong copyleft (GPL/AGPL/SSPL), weak copyleft (LGPL/MPL/EPL/CDDL), and proprietary/UNLICENSED dependencies in a project that redistributes them.",
    how: "For npm, reads the license field already in package-lock.json (no network). For PyPI/Go/RubyGems it enriches via deps.dev, bounded to 200 packages. Dual licenses with a permissive escape are treated as acceptable; dev-only npm deps are skipped.",
    doesnt:
      "Give legal advice, or resolve license text that a registry does not record. It surfaces the risk; the call is yours.",
  },
}

const DETECTORS: Detector[] = DETECTOR_SLUGS.map((slug, i) => ({
  n: i + 1,
  ...DOC_DETECTORS[slug],
}))

export default function DetectorsPage() {
  return (
    <div className="max-w-3xl">
      <DocHeader eyebrow="reference" title="Detectors">
        TriageRook runs eleven independent detectors over a repo and aggregates the
        results into one prioritized report. This page is the map: what each
        detector finds, the real method behind it, and &mdash; just as important
        &mdash; what it does not catch. For the individual pattern-based rules,
        see the{" "}
        <Link href="/docs/rules" className="text-amber-400 hover:underline">
          rule catalog
        </Link>
        .
      </DocHeader>

      <Callout variant="info" title="Where the granular rules live">
        <p>
          Detectors 1&ndash;3, 5, 7, and 8 are backed by an enumerable rule catalog
          at <Link href="/docs/rules" className="text-amber-400 hover:underline">/docs/rules</Link>
          . Dependencies (6), posture (9), the IAM risk scanner (10), and licenses
          (11) are computed dynamically &mdash; from OSV / npm advisories, GitHub
          API signals, policy parsing, and registry metadata &mdash; so they have
          no fixed rule list.
        </p>
      </Callout>

      {DETECTORS.map((d) => (
        <Section key={d.n} title={`${d.n}. ${d.title}`}>
          <dl className="space-y-3 text-sm leading-relaxed">
            <div>
              <dt className="font-mono text-xs uppercase tracking-wider text-emerald-300">
                Detects
              </dt>
              <dd className="text-slate-300">{d.detects}</dd>
            </div>
            <div>
              <dt className="font-mono text-xs uppercase tracking-wider text-amber-300">
                How
              </dt>
              <dd className="text-slate-300">{d.how}</dd>
            </div>
            <div>
              <dt className="font-mono text-xs uppercase tracking-wider text-orange-300">
                Doesn&apos;t catch
              </dt>
              <dd className="text-slate-300">{d.doesnt}</dd>
            </div>
          </dl>
          {d.link && (
            <p className="mt-3 text-sm">
              <Link
                href={d.link.href}
                className="font-mono text-xs text-amber-400 hover:underline"
              >
                {d.link.label} &rarr;
              </Link>
            </p>
          )}
        </Section>
      ))}

      <Callout variant="warn" title="On SAST depth — the honest version">
        <p>
          Detector 5 is a fast first pass: TypeScript/JavaScript AST rules plus
          targeted regex for other languages. It is not a full dataflow engine. If
          you already run <strong>CodeQL</strong> or <strong>Snyk Code</strong>,
          keep them &mdash; they go deeper on cross-file code analysis. TriageRook
          aims to catch the high-confidence issues in one click with zero setup,
          not to replace a dedicated SAST product. The same honesty is on the{" "}
          <Link href="/compare" className="text-amber-400 hover:underline">
            comparison page
          </Link>
          .
        </p>
      </Callout>

      <div className="mt-12 border-t border-slate-800/60 pt-8 text-sm text-slate-500">
        <p>
          Want a detector or rule we don&apos;t have?{" "}
          <a
            href="https://github.com/silviooerudon/triagerook/issues/new?title=Detector%20request"
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
