import type { MetadataRoute } from "next"
import { DOC_PATHS } from "./docs/_nav"
import { getRuleCatalog, ruleIdToSlug } from "@/lib/rule-catalog"

const BASE_URL = "https://www.triagerook.com"

// Public, indexable routes. Authenticated app routes (/dashboard, sign-in flows)
// are intentionally excluded — they're behind auth and shouldn't be crawled.
const STATIC_PATHS = [
  "/",
  "/compare",
  "/about",
  "/security",
]

export default function sitemap(): MetadataRoute.Sitemap {
  const lastModified = new Date()

  // /docs section pages (overview + the trust/scanning/reference pages).
  const docPaths = Array.from(new Set([...DOC_PATHS]))

  // Every statically-generated rule detail page.
  const rulePaths = getRuleCatalog().map(
    (entry) => `/docs/rules/${ruleIdToSlug(entry.id)}`,
  )

  const all = [...STATIC_PATHS, ...docPaths, ...rulePaths]

  return all.map((path) => ({
    url: `${BASE_URL}${path}`,
    lastModified,
  }))
}
