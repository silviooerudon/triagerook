import Link from "next/link"
import { LEGAL } from "@/lib/legal"

// Site-wide legal strip, rendered once from the root layout so every page
// — public, docs and dashboard — links to the Privacy Policy and Terms and
// identifies who operates the service.
export function SiteFooter() {
  const year = new Date().getFullYear()
  return (
    <footer className="mt-auto border-t border-slate-800/60 font-mono text-xs text-slate-400">
      <div className="max-w-6xl mx-auto px-6 py-6 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
        <p>
          © {year} TriageRook · operated by {LEGAL.operatorName}, {LEGAL.operatorLocation}
        </p>
        <nav aria-label="Legal">
          <ul className="flex flex-wrap gap-x-5 gap-y-2">
            <li>
              <Link href="/privacy" className="hover:text-amber-400 underline-offset-2 hover:underline">
                privacy
              </Link>
            </li>
            <li>
              <Link href="/terms" className="hover:text-amber-400 underline-offset-2 hover:underline">
                terms
              </Link>
            </li>
            <li>
              <Link href="/privacy#cookies" className="hover:text-amber-400 underline-offset-2 hover:underline">
                cookies
              </Link>
            </li>
            <li>
              <Link href="/security" className="hover:text-amber-400 underline-offset-2 hover:underline">
                security
              </Link>
            </li>
            <li>
              <a
                href="https://github.com/silviooerudon/triagerook"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-amber-400 underline-offset-2 hover:underline"
              >
                open source (MIT)<span className="sr-only"> (opens in a new tab)</span>
              </a>
            </li>
            <li>
              <a
                href={`mailto:${LEGAL.privacyEmail}`}
                className="hover:text-amber-400 underline-offset-2 hover:underline"
              >
                contact
              </a>
            </li>
          </ul>
        </nav>
      </div>
    </footer>
  )
}
