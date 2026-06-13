import { describe, it, expect } from "vitest"
import { DETECTOR_SLUGS, DETECTOR_COUNT } from "@/lib/detectors"

// The landing page (app/page.tsx) and /docs/detectors both render their copy
// from a Record<DetectorSlug, …> keyed off DETECTOR_SLUGS, so the *compiler*
// already guarantees they cover exactly these detectors in this order. These
// runtime checks guard the count itself (cited as "eleven" in prose across the
// README, hero, stat bar, pricing, and docs) and the canonical ordering.
describe("canonical detectors", () => {
  it("there are exactly eleven", () => {
    expect(DETECTOR_COUNT).toBe(11)
    expect(DETECTOR_SLUGS).toHaveLength(11)
  })

  it("slugs are unique", () => {
    expect(new Set(DETECTOR_SLUGS).size).toBe(DETECTOR_SLUGS.length)
  })

  it("keeps supply-chain as #7 and ci-iac (IaC) as #8", () => {
    expect(DETECTOR_SLUGS[6]).toBe("supply-chain")
    expect(DETECTOR_SLUGS[7]).toBe("ci-iac")
  })
})
