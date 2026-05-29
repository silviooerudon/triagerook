import { describe, it, expect } from "vitest"
import { parseLockfile } from "@/lib/deps"

describe("parseLockfile — transitive detection", () => {
  // Regression: `isTransitive` used `path.indexOf("node_modules/", lastIdx + 1)`,
  // which searches *past* the last occurrence and is therefore always -1 — so
  // every package was reported as direct. A nested package path contains
  // "node_modules/" more than once and must be flagged transitive.
  it("flags nested node_modules paths as transitive and top-level as direct", () => {
    const refs = parseLockfile({
      lockfileVersion: 3,
      packages: {
        "": { version: "1.0.0" }, // root — skipped
        "node_modules/express": { version: "4.18.2" },
        "node_modules/express/node_modules/cookie": { version: "0.5.0" },
        "node_modules/lodash": { version: "4.17.21" },
        "node_modules/a/node_modules/b/node_modules/c": { version: "2.0.0" },
      },
    })

    const byName = Object.fromEntries(refs.map((r) => [r.name, r]))

    expect(byName["express"].isTransitive).toBe(false)
    expect(byName["lodash"].isTransitive).toBe(false)
    expect(byName["cookie"].isTransitive).toBe(true)
    // Deeply nested: name is the last component, still transitive.
    expect(byName["c"].isTransitive).toBe(true)
  })

  it("skips the root entry and entries without a version", () => {
    const refs = parseLockfile({
      packages: {
        "": { version: "1.0.0" },
        "node_modules/no-version": {},
        "node_modules/real": { version: "1.2.3" },
      },
    })
    expect(refs.map((r) => r.name)).toEqual(["real"])
  })
})
