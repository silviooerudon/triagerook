import { describe, it, expect } from "vitest"
import { parseGemfileLock } from "@/lib/ruby-deps"

describe("parseGemfileLock", () => {
  it("parses gems under the specs: block at the 4-space indent", () => {
    const content = `GEM
  remote: https://rubygems.org/
  specs:
    activesupport (7.0.4)
      concurrent-ruby (~> 1.0, >= 1.0.2)
    nokogiri (1.13.10)
      racc (~> 1.4)
    rails (7.0.4)
      actioncable (= 7.0.4)

PLATFORMS
  ruby

DEPENDENCIES
  rails (~> 7.0)
`
    const deps = parseGemfileLock(content)
    expect(deps).toEqual([
      { name: "activesupport", version: "7.0.4", source: "Gemfile.lock" },
      { name: "nokogiri", version: "1.13.10", source: "Gemfile.lock" },
      { name: "rails", version: "7.0.4", source: "Gemfile.lock" },
    ])
  })

  it("skips transitive constraints (deeper indent than top-level spec)", () => {
    // `concurrent-ruby (~> 1.0)` appears under activesupport with 6-space
    // indent — it's a constraint, not a pinned dep. The actual pinned
    // version would appear elsewhere in the same lockfile if present.
    const content = `GEM
  remote: https://rubygems.org/
  specs:
    activesupport (7.0.4)
      concurrent-ruby (~> 1.0)
      i18n (>= 1.6)
`
    const deps = parseGemfileLock(content)
    expect(deps).toEqual([
      { name: "activesupport", version: "7.0.4", source: "Gemfile.lock" },
    ])
  })

  it("returns empty when GEM section is absent", () => {
    const content = `PLATFORMS
  ruby

DEPENDENCIES
  rails
`
    expect(parseGemfileLock(content)).toEqual([])
  })

  it("ignores BUNDLED WITH / RUBY VERSION trailing sections", () => {
    const content = `GEM
  remote: https://rubygems.org/
  specs:
    rails (7.0.4)

RUBY VERSION
   ruby 3.2.2p53

BUNDLED WITH
   2.4.10
`
    const deps = parseGemfileLock(content)
    expect(deps).toEqual([
      { name: "rails", version: "7.0.4", source: "Gemfile.lock" },
    ])
  })

  it("handles gem names with dashes/underscores/digits", () => {
    const content = `GEM
  specs:
    aws-sdk-s3 (1.119.0)
    rack_attack (6.7.0)
    google-protobuf (3.25.1)
`
    const deps = parseGemfileLock(content)
    expect(deps.map((d) => d.name)).toEqual([
      "aws-sdk-s3",
      "rack_attack",
      "google-protobuf",
    ])
  })
})
