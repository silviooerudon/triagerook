import type { Metadata } from "next";
import { PublicNav } from "@/app/components/public-nav";

export const metadata: Metadata = {
  title: "About",
  description:
    "Who builds TriageRook, how to get in touch, and the current project status.",
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
        <h1 className="font-display text-3xl md:text-4xl font-bold tracking-tight mb-8">
          About TriageRook
        </h1>

        <div className="text-slate-300 leading-relaxed space-y-5 mb-12">
          <p>
            TriageRook is built by Silvio Gazzoli, a solo developer based in
            Dublin with 10+ years implementing IAM and IGA at enterprises
            (SailPoint, CyberArk).
          </p>
          <p>
            After a decade watching the same preventable security issues show
            up in audit after audit, I built TriageRook for solo devs,
            freelancers, and small teams who do not have a security team of
            their own.
          </p>
        </div>

        <section className="mb-12">
          <h2 className="font-display text-2xl font-bold tracking-tight mb-4">
            Contact
          </h2>
          <ul className="list-disc pl-6 space-y-2 text-slate-300">
            <li>
              LinkedIn:{" "}
              <a
                href="https://www.linkedin.com/in/silvio-junior-de-almeida-gazzoli-78453a8a"
                target="_blank"
                rel="noopener noreferrer"
                className="text-amber-400 hover:underline break-all"
              >
                linkedin.com/in/silvio-junior-de-almeida-gazzoli-78453a8a
              </a>
            </li>
            <li>
              GitHub:{" "}
              <a
                href="https://github.com/silviooerudon"
                target="_blank"
                rel="noopener noreferrer"
                className="text-amber-400 hover:underline"
              >
                github.com/silviooerudon
              </a>
            </li>
          </ul>
        </section>

        <section className="mb-12">
          <h2 className="font-display text-2xl font-bold tracking-tight mb-4">
            Status
          </h2>
          <p className="text-slate-300 leading-relaxed">
            Free. No SLA. Source code closed for now, planning to open the
            detectors.
          </p>
        </section>
      </article>
    </>
  );
}
