import { describe, it, expect } from "vitest"
import { parseGoMod } from "@/lib/go-deps"

describe("parseGoMod", () => {
  it("parses a block-form require with direct + indirect deps", () => {
    const content = `module example.com/myapp

go 1.22

require (
\tgithub.com/gin-gonic/gin v1.9.1
\tgithub.com/stretchr/testify v1.8.4
\tgolang.org/x/crypto v0.17.0 // indirect
)
`
    const deps = parseGoMod(content)
    expect(deps).toEqual([
      { name: "github.com/gin-gonic/gin", version: "1.9.1", source: "go.mod" },
      { name: "github.com/stretchr/testify", version: "1.8.4", source: "go.mod" },
      { name: "golang.org/x/crypto", version: "0.17.0", source: "go.mod" },
    ])
  })

  it("parses single-line requires outside a block", () => {
    const content = `module example.com/x

go 1.22

require github.com/gin-gonic/gin v1.9.1
require github.com/stretchr/testify v1.8.4
`
    const deps = parseGoMod(content)
    expect(deps).toHaveLength(2)
    expect(deps[0].name).toBe("github.com/gin-gonic/gin")
    expect(deps[1].name).toBe("github.com/stretchr/testify")
  })

  it("strips +incompatible from versions for OSV compatibility", () => {
    const content = `module example.com/x

require (
\tgithub.com/aws/aws-sdk-go v1.44.0+incompatible
)
`
    const deps = parseGoMod(content)
    expect(deps[0].version).toBe("1.44.0")
  })

  it("ignores module/go/replace/exclude directives and full-line comments", () => {
    // Only `require` lines should produce deps. Anything else is metadata
    // we don't scan.
    const content = `module example.com/x

go 1.22

// This is a comment
replace github.com/old/pkg => github.com/new/pkg v2.0.0
exclude github.com/buggy/pkg v1.2.3

require github.com/real/pkg v1.0.0
`
    const deps = parseGoMod(content)
    expect(deps).toHaveLength(1)
    expect(deps[0].name).toBe("github.com/real/pkg")
  })

  it("returns empty array for go.mod with no requires", () => {
    const content = `module example.com/empty

go 1.22
`
    expect(parseGoMod(content)).toEqual([])
  })

  it("rejects entries without a v-prefixed version (defensive)", () => {
    // Real go.mod always has v-prefixed semver; this guards against
    // free-form text accidentally being parsed as a dep.
    const content = `module example.com/x

require (
\tgithub.com/legit/pkg v1.0.0
\tnot-a-real-line garbage
)
`
    const deps = parseGoMod(content)
    expect(deps).toEqual([
      { name: "github.com/legit/pkg", version: "1.0.0", source: "go.mod" },
    ])
  })
})
