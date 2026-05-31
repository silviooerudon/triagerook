import { describe, it, expect } from "vitest"
import { parseComposerLock } from "@/lib/php-deps"

describe("parseComposerLock", () => {
  it("collects packages and packages-dev with the v-prefix stripped", () => {
    const lock = JSON.stringify({
      packages: [
        { name: "monolog/monolog", version: "1.25.0" },
        { name: "guzzlehttp/guzzle", version: "v6.5.2" },
      ],
      "packages-dev": [{ name: "phpunit/phpunit", version: "8.5.1" }],
    })
    const deps = parseComposerLock(lock)
    expect(deps).toContainEqual({
      name: "monolog/monolog",
      version: "1.25.0",
      source: "composer.lock",
    })
    expect(deps).toContainEqual({
      name: "guzzlehttp/guzzle",
      version: "6.5.2",
      source: "composer.lock",
    })
    expect(deps).toContainEqual({
      name: "phpunit/phpunit",
      version: "8.5.1",
      source: "composer.lock",
    })
  })

  it("skips dev-branch aliases and non-concrete versions", () => {
    const lock = JSON.stringify({
      packages: [
        { name: "vendor/wip", version: "dev-main" },
        { name: "vendor/aliased", version: "dev-feature as 2.0.0" },
        { name: "vendor/good", version: "3.1.4" },
      ],
    })
    const deps = parseComposerLock(lock)
    expect(deps.map((d) => d.name)).toEqual(["vendor/good"])
  })

  it("returns [] on malformed JSON without throwing", () => {
    expect(parseComposerLock("{not json")).toEqual([])
    expect(parseComposerLock("")).toEqual([])
  })

  it("tolerates a lockfile with no packages array", () => {
    expect(parseComposerLock(JSON.stringify({ "content-hash": "abc" }))).toEqual([])
  })
})
