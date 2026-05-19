import type { Metadata } from "next";
import Link from "next/link";
import { PublicNav } from "@/app/components/public-nav";

export const metadata: Metadata = {
  title: "Pricing",
  description:
    "RepoGuard pricing - free during public beta. Honest preview of what paid tiers will look like once they ship.",
  alternates: { canonical: "/pricing" },
};

const CURRENT_TIER_INCLUDES = [
  "All 9 detectors (secrets, deps, SAST, IaC, supply chain, posture, IAM)",
  "Unlimited scans of your public repositories",
  "SARIF 2.1 export into GitHub Code Scanning",
  "Auto-fix PRs for clean cases",
  "Per-finding, per-rule, and per-glob suppressions",
  "Scan history and saved scans",
];

const FAQ: Array<{ q: string; a: string }> = [
  {
    q: "Is RepoGuard free?",
    a: "Yes - fully free during the current beta. No card, no trial timer, no usage gating. Sign in with GitHub and scan any of your public repos.",
  },
  {
    q: "Why publish a pricing page if there is no paid plan yet?",
    a: "Two reasons. First, you deserve to know up front that this project intends to be sustainable rather than acquired-and-killed or pivoted. Second, the eventual paid tier will exist for capabilities that are genuinely more expensive to operate (private repos, team accounts), not to lock away the core scanner.",
  },
  {
    q: "Will the free tier go away?",
    a: "No. The plan is for public-repo scanning to remain free indefinitely. RepoGuard is open source under MIT - you can self-host it. A hosted free tier is the path of least friction, and there is no plan to take it away.",
  },
  {
    q: "When will paid tiers ship?",
    a: "When private-repo support and team accounts are stable enough to charge for. No firm date - the beta is still gathering signal on what people actually value. Sign in and use it; that is the best way to shape what gets built next.",
  },
  {
    q: "How can I support the project today?",
    a: "Use it on your repos, file issues when something is wrong or misleading, and star the GitHub repo if it helped you. The most useful contribution right now is signal, not money.",
  },
];

export default function PricingPage() {
  return (
    <>
      <PublicNav />
      <article className="max-w-3xl mx-auto px-6 py-16">
        <div className="font-mono text-xs text-amber-400 mb-3">
          {"// pricing"}
        </div>
        <h1 className="font-display text-3xl md:text-4xl font-bold tracking-tight mb-3">
          Honest pricing.
        </h1>
        <p className="text-slate-400 mb-12 leading-relaxed">
          RepoGuard is free during public beta. There is no card to enter, no
          trial countdown, and no usage gating. This page exists so you know
          what the business model is before you sign in.
        </p>

        <section className="mb-14">
          <div className="border border-amber-400/40 rounded-lg p-7 bg-slate-900/30">
            <div className="flex items-baseline justify-between flex-wrap gap-3 mb-2">
              <h2 className="font-display text-2xl font-bold tracking-tight">
                Beta
              </h2>
              <span className="font-mono text-xs text-amber-300 uppercase tracking-wider">
                current - available today
              </span>
            </div>
            <div className="flex items-baseline gap-2 mb-5">
              <span className="font-display text-4xl font-bold text-amber-400">
                $0
              </span>
              <span className="font-mono text-xs text-slate-500">
                / forever, while in beta
              </span>
            </div>
            <p className="text-slate-300 leading-relaxed mb-5">
              Sign in with GitHub. Scan any of your public repositories. Export
              to SARIF. Open auto-fix PRs. No card required, no upsell.
            </p>
            <ul className="space-y-2 mb-6">
              {CURRENT_TIER_INCLUDES.map((line) => (
                <li
                  key={line}
                  className="flex items-start gap-3 text-sm text-slate-300"
                >
                  <span className="font-mono text-amber-400 mt-0.5 shrink-0">
                    +
                  </span>
                  <span>{line}</span>
                </li>
              ))}
            </ul>
            <Link
              href="/signin"
              className="inline-block px-4 py-2 border border-amber-400/40 text-amber-300 hover:bg-amber-400 hover:text-slate-950 transition font-mono text-xs"
            >
              sign in with github
            </Link>
          </div>
        </section>

        <section className="mb-14">
          <div className="font-mono text-xs text-amber-400 mb-3">
            {"// coming later"}
          </div>
          <h2 className="font-display text-2xl font-bold tracking-tight mb-3">
            What paid tiers will look like.
          </h2>
          <p className="text-slate-300 leading-relaxed mb-6">
            When the beta ends, a paid tier will exist for capabilities that
            cost real money to operate. No pricing yet - the shape is roughed
            in, the numbers are not.
          </p>

          <div className="grid md:grid-cols-2 gap-px bg-slate-800/40 border border-slate-800/40 rounded-lg overflow-hidden">
            <PlanCard
              title="solo (planned)"
              desc="For a single developer who needs RepoGuard on private repositories. Same scanner, same UX, scoped to your account. Pricing not yet set."
            />
            <PlanCard
              title="team (planned)"
              desc="For small teams who want shared visibility into an org's scans, role-based access, and SSO. Pricing not yet set."
            />
          </div>
          <p className="font-mono text-xs text-slate-500 mt-6">
            {"// public-repo scanning will remain free indefinitely"}
          </p>
        </section>

        <section className="mb-10">
          <div className="font-mono text-xs text-amber-400 mb-3">
            {"// faq"}
          </div>
          <h2 className="font-display text-2xl font-bold tracking-tight mb-6">
            Asked before.
          </h2>
          <div className="border-t border-slate-800/60">
            {FAQ.map((item) => (
              <details
                key={item.q}
                className="group border-b border-slate-800/60"
              >
                <summary className="cursor-pointer flex items-center justify-between gap-6 py-5 list-none">
                  <span className="font-mono text-sm text-slate-200 group-hover:text-amber-300 transition">
                    {item.q}
                  </span>
                  <span className="font-mono text-amber-400 group-open:rotate-45 transition-transform text-lg leading-none shrink-0">
                    +
                  </span>
                </summary>
                <p className="pb-5 pr-10 text-sm text-slate-400 leading-relaxed">
                  {item.a}
                </p>
              </details>
            ))}
          </div>
        </section>

        <p className="text-xs text-slate-500 mt-16 pt-8 border-t border-slate-800/60 font-mono">
          {"// see also: "}
          <Link href="/about" className="hover:text-amber-400 transition">
            /about
          </Link>
          {" - "}
          <Link href="/security" className="hover:text-amber-400 transition">
            /security
          </Link>
        </p>
      </article>
    </>
  );
}

function PlanCard({ title, desc }: { title: string; desc: string }) {
  return (
    <div className="bg-slate-950 p-7">
      <div className="font-mono text-amber-400 text-xs mb-3 tracking-wider">
        ## {title}
      </div>
      <p className="text-slate-300 leading-relaxed text-sm">{desc}</p>
    </div>
  );
}
