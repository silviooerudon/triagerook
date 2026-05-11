import { describe, it, expect } from "vitest"
import { applySecretExtract, deriveEnvVarName } from "@/lib/fix-engines/secret-extract"
import type { SecretFinding } from "@/lib/types"

function secretFinding(overrides: Partial<SecretFinding> = {}): SecretFinding {
  return {
    patternId: "stripe-secret-key",
    patternName: "Stripe Secret Key",
    severity: "critical",
    description: "Stripe live secret key",
    filePath: "lib/stripe.ts",
    lineNumber: 3,
    lineContent: 'const stripeKey = "sk_live_abc123def456"',
    likelyTestFixture: false,
    ...overrides,
  }
}

describe("deriveEnvVarName", () => {
  it("converts camelCase identifier to SCREAMING_SNAKE_CASE", () => {
    expect(deriveEnvVarName("stripeKey")).toBe("STRIPE_KEY")
  })

  it("preserves SCREAMING_SNAKE_CASE input as-is", () => {
    expect(deriveEnvVarName("STRIPE_KEY")).toBe("STRIPE_KEY")
  })

  it("converts kebab-case to SCREAMING_SNAKE_CASE", () => {
    expect(deriveEnvVarName("stripe-key")).toBe("STRIPE_KEY")
  })

  it("handles snake_case", () => {
    expect(deriveEnvVarName("stripe_key")).toBe("STRIPE_KEY")
  })
})

describe("applySecretExtract - JS/TS const assignment", () => {
  it("replaces double-quoted literal with process.env.X", () => {
    const fileContent = [
      "// stripe wrapper",
      "",
      'const stripeKey = "sk_live_abc123def456"',
      "export { stripeKey }",
    ].join("\n")

    const result = applySecretExtract({
      finding: secretFinding(),
      fileContent,
      envExampleContent: null,
    })

    expect(result.envVarName).toBe("STRIPE_KEY")
    const codePatch = result.patches.find((p) => p.path === "lib/stripe.ts")
    expect(codePatch).toBeDefined()
    expect(codePatch!.content).toContain('const stripeKey = process.env.STRIPE_KEY')
    expect(codePatch!.content).not.toContain("sk_live_abc123def456")
  })

  it("handles single-quoted literals", () => {
    const fileContent = [
      "",
      "",
      "const stripeKey = 'sk_live_abc123def456'",
    ].join("\n")

    const result = applySecretExtract({
      finding: secretFinding({
        lineContent: "const stripeKey = 'sk_live_abc123def456'",
      }),
      fileContent,
      envExampleContent: null,
    })

    const codePatch = result.patches.find((p) => p.path === "lib/stripe.ts")!
    expect(codePatch.content).toContain("const stripeKey = process.env.STRIPE_KEY")
  })

  it("handles let and var declarations", () => {
    const fileContent = ["", "", 'let stripeKey = "sk_live_abc123def456"'].join("\n")

    const result = applySecretExtract({
      finding: secretFinding({
        lineContent: 'let stripeKey = "sk_live_abc123def456"',
      }),
      fileContent,
      envExampleContent: null,
    })

    const codePatch = result.patches.find((p) => p.path === "lib/stripe.ts")!
    expect(codePatch.content).toContain("let stripeKey = process.env.STRIPE_KEY")
  })

  it("creates .env.example entry when file does not exist yet", () => {
    const fileContent = ["", "", 'const stripeKey = "sk_live_abc123def456"'].join("\n")

    const result = applySecretExtract({
      finding: secretFinding(),
      fileContent,
      envExampleContent: null,
    })

    const envPatch = result.patches.find((p) => p.path === ".env.example")
    expect(envPatch).toBeDefined()
    expect(envPatch!.content).toContain("STRIPE_KEY=")
    expect(envPatch!.content).toContain("# Stripe Secret Key")
  })

  it("appends to existing .env.example without duplicating", () => {
    const fileContent = ["", "", 'const stripeKey = "sk_live_abc123def456"'].join("\n")
    const existingEnv = "DATABASE_URL=postgres://localhost:5432/dev\n"

    const result = applySecretExtract({
      finding: secretFinding(),
      fileContent,
      envExampleContent: existingEnv,
    })

    const envPatch = result.patches.find((p) => p.path === ".env.example")!
    expect(envPatch.content).toContain("DATABASE_URL=postgres://localhost:5432/dev")
    expect(envPatch.content).toContain("STRIPE_KEY=")
  })

  it("does NOT add duplicate when env var already declared", () => {
    const fileContent = ["", "", 'const stripeKey = "sk_live_abc123def456"'].join("\n")
    const existingEnv = "STRIPE_KEY=\nDATABASE_URL=postgres://localhost\n"

    const result = applySecretExtract({
      finding: secretFinding(),
      fileContent,
      envExampleContent: existingEnv,
    })

    const envPatch = result.patches.find((p) => p.path === ".env.example")
    expect(envPatch).toBeUndefined()
  })

  it("throws when line shape is not a supported assignment", () => {
    const fileContent = ["", "", 'someFunc("sk_live_abc123def456")'].join("\n")

    expect(() =>
      applySecretExtract({
        finding: secretFinding({
          lineContent: 'someFunc("sk_live_abc123def456")',
        }),
        fileContent,
        envExampleContent: null,
      })
    ).toThrow(/unsupported|assignment/i)
  })

  it("throws when finding is for an unsupported file extension", () => {
    expect(() =>
      applySecretExtract({
        finding: secretFinding({ filePath: "config/keys.yml" }),
        fileContent: 'stripe_key: "sk_live_abc123def456"',
        envExampleContent: null,
      })
    ).toThrow(/extension|file type/i)
  })
})
