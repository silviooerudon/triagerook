import { describe, it, expect } from "vitest"
import { SECRET_PATTERNS } from "@/lib/secret-patterns"

// Fixtures are composed via string concatenation so the source code never
// contains a contiguous secret-shaped literal. The runtime value is
// identical, but GitHub's push-protection and similar scanners see only
// the fragments, which keeps this file safely committable.
const j = (...parts: string[]) => parts.join("")

function patternById(id: string) {
  const p = SECRET_PATTERNS.find((p) => p.id === id)
  if (!p) throw new Error(`Pattern not found: ${id}`)
  return p
}

function matches(id: string, input: string): boolean {
  const p = patternById(id)
  p.regex.lastIndex = 0
  return p.regex.test(input)
}

const GH_BODY_36 = "aBcDeFgHiJkLmNoPqRsTuVwXyZ" + "0123456789"
const STRIPE_BODY_24 = "abcdefghijklmnopqrstuvwx"

describe("SECRET_PATTERNS regex matrix", () => {
  it("covers a non-trivial set of providers", () => {
    expect(SECRET_PATTERNS.length).toBeGreaterThanOrEqual(40)
  })

  it("every pattern declares id, name, severity, description, regex", () => {
    for (const p of SECRET_PATTERNS) {
      expect(p.id).toBeTruthy()
      expect(p.name).toBeTruthy()
      expect(p.severity).toMatch(/critical|high|medium|low/)
      expect(p.description.length).toBeGreaterThan(0)
      expect(p.regex).toBeInstanceOf(RegExp)
    }
  })

  it("pattern ids are unique", () => {
    const ids = SECRET_PATTERNS.map((p) => p.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  describe("positive matches (canonical fixtures)", () => {
    const cases: Array<[string, string]> = [
      ["aws-access-key", j("AKIA", "IOSFODNN7EXAMPLE")],
      ["github-pat", j("ghp", "_", GH_BODY_36)],
      ["github-fine-grained-pat", j("github", "_pat_", "A".repeat(82))],
      ["github-oauth", j("gho", "_", GH_BODY_36)],
      ["github-server-to-server", j("ghs", "_", GH_BODY_36)],
      ["openai-legacy-key", j("sk", "-", "A".repeat(48))],
      ["anthropic-api-key", j("sk", "-ant-", "api03-", "A".repeat(80))],
      ["gcp-api-key", j("AIza", "0".repeat(35))],
      ["digitalocean-token", j("dop", "_v1_", "a".repeat(64))],
      ["stripe-live-secret", j("sk", "_", "live", "_", STRIPE_BODY_24)],
      ["slack-webhook", j("https://hooks.", "slack.com/services/", "T00000000/B00000000/", "A".repeat(24))],
      ["discord-webhook", j("https://discord.com/", "api/webhooks/", "123456789/", "AbCdEf")],
      ["npm-access-token", j("npm", "_", "a".repeat(36))],
      ["sendgrid-key", j("SG.", "A".repeat(22), ".", "A".repeat(43))],
      ["private-key", "-----BEGIN PRIVATE KEY-----"],
      ["private-key", "-----BEGIN RSA PRIVATE KEY-----"],
      ["private-key", "-----BEGIN OPENSSH PRIVATE KEY-----"],
      ["jwt", j("eyJhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiIxMjMifQ", ".", "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")],
    ]

    for (const [id, fixture] of cases) {
      it(`${id} matches a canonical fixture`, () => {
        expect(matches(id, fixture)).toBe(true)
      })
    }
  })

  describe("negative matches (placeholder-shaped strings)", () => {
    const negatives: Array<[string, string, string]> = [
      ["aws-access-key", j("AKIA", "123"), "too short"],
      ["github-pat", j("ghp", "_", "short"), "wrong length"],
      ["openai-legacy-key", j("sk", "-", "tooshort"), "wrong length"],
      ["private-key", "PRIVATE_KEY=abc", "not the BEGIN block marker"],
      ["stripe-live-secret", j("sk", "_", "test", "_", STRIPE_BODY_24), "test prefix, not live"],
    ]

    for (const [id, fixture, why] of negatives) {
      it(`${id} does not match (${why})`, () => {
        expect(matches(id, fixture)).toBe(false)
      })
    }
  })

  it("all regexes are stateful-safe after multiple tests (lastIndex reset)", () => {
    const p = patternById("github-pat")
    const fixture = j("ghp", "_", GH_BODY_36)
    expect(p.regex.test(fixture)).toBe(true)
    p.regex.lastIndex = 0
    expect(p.regex.test(fixture)).toBe(true)
  })
})
