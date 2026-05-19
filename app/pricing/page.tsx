import type { Metadata } from "next";
import { PublicNav } from "@/app/components/public-nav";

export const metadata: Metadata = {
  title: "Pricing",
  description:
    "Simple, transparent pricing for RepoGuard. Free during beta.",
  alternates: { canonical: "/pricing" },
};

const FREE_FEATURES = [
  "One repository",
  "Full security scan (all 9 detectors)",
  "Public and private repos",
  "No credit card",
];

const PRO_FEATURES = [
  "Unlimited repositories",
  "All scans persisted with history",
  "Scan diffing (new findings since last scan)",
  "Priority support",
];

const NEVER_DO = [
  "No ads",
  "No selling or sharing your data",
  "No training AI models on your code",
  "No surprise charges - beta users get advance notice",
];

export default function PricingPage() {
  return (
    <>
      <PublicNav />
      <article className="max-w-4xl mx-auto px-6 py-16">
        <div className="font-mono text-xs text-amber-400 mb-3">
          {"// pricing"}
        </div>
        <h1 className="font-display text-3xl md:text-4xl font-bold tracking-tight mb-3">
          Pricing
        </h1>
        <p className="text-slate-400 mb-10 leading-relaxed">
          Simple. No surprises. No data resale.
        </p>

        <aside
          role="note"
          className="mb-12 rounded-md border-l-4 border-sky-500 bg-slate-50 text-slate-900 p-5"
        >
          <p className="font-semibold mb-1">Beta - free for everyone.</p>
          <p className="text-sm leading-relaxed text-slate-700">
            RepoGuard is free during the beta period while I validate real
            usage. Anyone using it now will get advance notice before pricing
            applies.
          </p>
        </aside>

        <div className="grid md:grid-cols-2 gap-6 mb-14">
          <div className="border border-slate-800 rounded-lg p-7 bg-slate-900/40 flex flex-col">
            <div className="flex items-baseline justify-between mb-4">
              <h2 className="font-display text-2xl font-bold tracking-tight">
                Free
              </h2>
            </div>
            <div className="flex items-baseline gap-2 mb-6">
              <span className="font-display text-4xl font-bold text-amber-400">
                EUR 0
              </span>
              <span className="font-mono text-xs text-slate-500">/ month</span>
            </div>
            <ul className="space-y-2 text-sm text-slate-300">
              {FREE_FEATURES.map((line) => (
                <li key={line} className="flex items-start gap-3">
                  <span className="font-mono text-amber-400 mt-0.5 shrink-0">
                    +
                  </span>
                  <span>{line}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="relative border border-slate-800 rounded-lg p-7 bg-slate-900/40 flex flex-col">
            <span className="absolute top-3 right-3 font-mono text-[10px] uppercase tracking-wider text-amber-300 border border-amber-400/40 px-2 py-0.5 rounded">
              Coming after beta
            </span>
            <div className="flex items-baseline justify-between mb-4">
              <h2 className="font-display text-2xl font-bold tracking-tight">
                Pro
              </h2>
            </div>
            <div className="flex items-baseline gap-2 mb-6">
              <span className="font-display text-4xl font-bold text-amber-400">
                EUR 9
              </span>
              <span className="font-mono text-xs text-slate-500">/ month</span>
            </div>
            <ul className="space-y-2 text-sm text-slate-300">
              {PRO_FEATURES.map((line) => (
                <li key={line} className="flex items-start gap-3">
                  <span className="font-mono text-amber-400 mt-0.5 shrink-0">
                    +
                  </span>
                  <span>{line}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        <section className="mb-10">
          <h2 className="font-display text-2xl font-bold tracking-tight mb-5">
            What I will never do
          </h2>
          <ul className="space-y-2 text-slate-300">
            {NEVER_DO.map((line) => (
              <li key={line} className="flex items-start gap-3">
                <span className="font-mono text-amber-400 mt-0.5 shrink-0">
                  -
                </span>
                <span>{line}</span>
              </li>
            ))}
          </ul>
        </section>
      </article>
    </>
  );
}
