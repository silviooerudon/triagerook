import type { Metadata } from "next";
import Link from "next/link";
import { PublicNav } from "@/app/components/public-nav";

export const metadata: Metadata = {
  title: "About",
  description:
    "Who builds RepoGuard, why it exists, current status, and how to get in touch.",
  alternates: { canonical: "/about" },
};

export default function AboutPage() {
  return (
    <>
      <PublicNav />
      <article className="max-w-3xl mx-auto px-6 py-16">
        <div className="font-mono text-xs text-amber-400 mb-3">
          {"// about"}
        </div>
        <h1 className="font-display text-3xl md:text-4xl font-bold tracking-tight mb-3">
          About RepoGuard
        </h1>
        <p className="text-slate-400 mb-12 leading-relaxed">
          A small, opinionated security scanner for solo developers and small
          teams who ship public code. Built in the open, in Dublin.
        </p>

        <Section title="Who builds this">
          <p>
            RepoGuard is built and maintained by{" "}
            <a
              href="https://www.linkedin.com/in/silvio-junior-de-almeida-gazzoli-78453a8a/"
              target="_blank"
              rel="noopener noreferrer"
              className="text-amber-400 hover:underline"
            >
              Silvio Gazzoli
            </a>
            , an IAM/IGA specialist with 10+ years of experience designing
            identity and access controls for regulated environments.
          </p>
          <p className="mt-3">
            The project is not affiliated with GitHub. It is one person, in
            public, with a license that lets you read every line of code.
          </p>
        </Section>

        <Section title="Why it exists">
          <p>
            Most security tooling is priced and shaped for enterprises with a
            security team. Solo developers and small open-source maintainers
            skip it - the friction of installing a CLI, configuring rules, and
            wiring up a pipeline is higher than the perceived risk.
          </p>
          <p className="mt-3">
            RepoGuard tries to fill that gap: sign in with GitHub, pick a repo,
            get a severity-ranked list of findings in under sixty seconds.
            Sensible defaults, no config files, no upsell. The scan a solo dev
            would actually run before pushing.
          </p>
        </Section>

        <Section title="Current status">
          <p>
            <strong>Version 0.9 - public beta.</strong> The product is live and
            free during beta. What works today:
          </p>
          <ul className="list-disc pl-6 space-y-1 mt-3">
            <li>9 detectors covering secrets, dependencies, SAST, IaC, supply chain, posture, and IAM risk</li>
            <li>Public-repo scanning without sign-in (rate-limited)</li>
            <li>Signed-in scans of your public repositories (unlimited)</li>
            <li>SARIF 2.1 export into GitHub Code Scanning</li>
            <li>Auto-fix PRs for clean cases (dependency bumps, secret extraction)</li>
            <li>Per-finding, per-rule, and per-glob suppressions</li>
          </ul>
          <p className="mt-3">
            What is not here yet: private-repo support, team/org accounts, and
            paid tiers. See{" "}
            <Link href="/pricing" className="text-amber-400 hover:underline">
              /pricing
            </Link>{" "}
            for the honest version of the business model.
          </p>
        </Section>

        <Section title="How it is built">
          <p>
            RepoGuard is a Next.js app deployed on Vercel, with scan metadata
            persisted in Supabase (Postgres, EU region). The codebase is open
            source under MIT. Source, issues, and roadmap live on{" "}
            <a
              href="https://github.com/silviooerudon/repoguard"
              target="_blank"
              rel="noopener noreferrer"
              className="text-amber-400 hover:underline"
            >
              GitHub
            </a>
            .
          </p>
          <p className="mt-3">
            For the full breakdown of what is accessed, stored, and protected,
            see{" "}
            <Link href="/security" className="text-amber-400 hover:underline">
              /security
            </Link>
            .
          </p>
        </Section>

        <Section title="Contact">
          <p>
            The fastest ways to reach the project:
          </p>
          <ul className="list-disc pl-6 space-y-2 mt-3">
            <li>
              <strong>Bugs and feature requests:</strong>{" "}
              <a
                href="https://github.com/silviooerudon/repoguard/issues"
                target="_blank"
                rel="noopener noreferrer"
                className="text-amber-400 hover:underline"
              >
                open an issue on GitHub
              </a>
              .
            </li>
            <li>
              <strong>Security disclosure:</strong> see{" "}
              <Link href="/security" className="text-amber-400 hover:underline">
                /security
              </Link>{" "}
              for the reporting channel.
            </li>
            <li>
              <strong>Direct contact:</strong>{" "}
              <a
                href="https://www.linkedin.com/in/silvio-junior-de-almeida-gazzoli-78453a8a/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-amber-400 hover:underline"
              >
                Silvio on LinkedIn
              </a>
              .
            </li>
          </ul>
        </Section>

        <p className="text-xs text-slate-500 mt-16 pt-8 border-t border-slate-800/60 font-mono">
          {"// built in dublin - not affiliated with github - mit license"}
        </p>
      </article>
    </>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="mb-10">
      <h2 className="text-xl font-semibold mb-3">{title}</h2>
      <div className="text-slate-300 leading-relaxed space-y-2">{children}</div>
    </section>
  );
}
