import { describe, it, expect, beforeEach, afterEach } from "vitest"
import {
  validateSecrets,
  isVerifiable,
  isSecretValidationEnabled,
  type FetchLike,
  type SecretWithValue,
} from "@/lib/secret-validation"
import type { SecretFinding } from "@/lib/types"

function secret(patternId: string, rawValue: string): SecretWithValue {
  const finding: SecretFinding = {
    patternId,
    patternName: patternId,
    severity: "critical",
    description: "",
    filePath: "config.ts",
    lineNumber: 1,
    lineContent: "***",
    likelyTestFixture: false,
  }
  return { finding, rawValue }
}

// Fake fetch that maps URL substrings to status codes.
function fakeFetch(routes: Array<{ match: string; status: number }>): FetchLike {
  return async (url) => {
    for (const r of routes) if (url.includes(r.match)) return { status: r.status }
    return { status: 404 }
  }
}

const ORIGINAL = process.env.ENABLE_SECRET_VALIDATION

afterEach(() => {
  if (ORIGINAL === undefined) delete process.env.ENABLE_SECRET_VALIDATION
  else process.env.ENABLE_SECRET_VALIDATION = ORIGINAL
})

describe("isVerifiable", () => {
  it("knows which secret types have validators", () => {
    expect(isVerifiable("github-pat")).toBe(true)
    expect(isVerifiable("stripe-live-secret")).toBe(true)
    expect(isVerifiable("aws-access-key")).toBe(false)
    expect(isVerifiable("nonsense")).toBe(false)
  })
})

describe("gating", () => {
  beforeEach(() => {
    delete process.env.ENABLE_SECRET_VALIDATION
  })

  it("isSecretValidationEnabled reflects the env flag", () => {
    expect(isSecretValidationEnabled()).toBe(false)
    process.env.ENABLE_SECRET_VALIDATION = "true"
    expect(isSecretValidationEnabled()).toBe(true)
  })

  it("marks everything skipped when the env flag is off, even if per-call enabled", async () => {
    const items = [secret("github-pat", "ghp_" + "a".repeat(36))]
    await validateSecrets(items, {
      enabled: true,
      fetchImpl: fakeFetch([{ match: "github.com", status: 200 }]),
    })
    expect(items[0].finding.validation).toBe("skipped")
  })

  it("marks everything skipped when per-call disabled, even if env on", async () => {
    process.env.ENABLE_SECRET_VALIDATION = "true"
    const items = [secret("github-pat", "ghp_" + "a".repeat(36))]
    await validateSecrets(items, {
      enabled: false,
      fetchImpl: fakeFetch([{ match: "github.com", status: 200 }]),
    })
    expect(items[0].finding.validation).toBe("skipped")
  })
})

describe("classification (enabled)", () => {
  beforeEach(() => {
    process.env.ENABLE_SECRET_VALIDATION = "true"
  })

  it("marks a 200 as active", async () => {
    const items = [secret("github-pat", "ghp_" + "a".repeat(36))]
    await validateSecrets(items, {
      enabled: true,
      fetchImpl: fakeFetch([{ match: "api.github.com/user", status: 200 }]),
    })
    expect(items[0].finding.validation).toBe("active")
  })

  it("marks a 401 as inactive", async () => {
    const items = [secret("stripe-live-secret", "sk_live_" + "a".repeat(24))]
    await validateSecrets(items, {
      enabled: true,
      fetchImpl: fakeFetch([{ match: "api.stripe.com", status: 401 }]),
    })
    expect(items[0].finding.validation).toBe("inactive")
  })

  it("marks a 500 as error (genuinely unknown)", async () => {
    const items = [secret("openai-api-key", "sk-" + "a".repeat(40))]
    await validateSecrets(items, {
      enabled: true,
      fetchImpl: fakeFetch([{ match: "api.openai.com", status: 500 }]),
    })
    expect(items[0].finding.validation).toBe("error")
  })

  it("marks an unknown secret type as unverifiable", async () => {
    const items = [secret("aws-access-key", "AKIA" + "A".repeat(16))]
    await validateSecrets(items, {
      enabled: true,
      fetchImpl: fakeFetch([{ match: "x", status: 200 }]),
    })
    expect(items[0].finding.validation).toBe("unverifiable")
  })

  it("marks unverifiable when the token can't be extracted from the raw match", async () => {
    const items = [secret("github-pat", "this has no token in it")]
    await validateSecrets(items, {
      enabled: true,
      fetchImpl: fakeFetch([{ match: "github.com", status: 200 }]),
    })
    expect(items[0].finding.validation).toBe("unverifiable")
  })

  it("extracts the bare token out of surrounding context (npmrc)", async () => {
    const items = [
      secret("npmrc-authtoken", "//registry.npmjs.org/:_authToken=npm_" + "a".repeat(36)),
    ]
    await validateSecrets(items, {
      enabled: true,
      fetchImpl: fakeFetch([{ match: "registry.npmjs.org/-/npm/v1/user", status: 200 }]),
    })
    expect(items[0].finding.validation).toBe("active")
  })

  it("validates a whole batch concurrently", async () => {
    const items = [
      secret("github-pat", "ghp_" + "a".repeat(36)),
      secret("stripe-live-secret", "sk_live_" + "b".repeat(24)),
      secret("openai-api-key", "sk-" + "c".repeat(40)),
    ]
    await validateSecrets(items, {
      enabled: true,
      concurrency: 2,
      fetchImpl: fakeFetch([
        { match: "api.github.com", status: 200 },
        { match: "api.stripe.com", status: 401 },
        { match: "api.openai.com", status: 200 },
      ]),
    })
    expect(items.map((i) => i.finding.validation)).toEqual(["active", "inactive", "active"])
  })

  it("never mutates the rawValue onto the finding (no leak)", async () => {
    const items = [secret("github-pat", "ghp_" + "z".repeat(36))]
    await validateSecrets(items, {
      enabled: true,
      fetchImpl: fakeFetch([{ match: "github.com", status: 200 }]),
    })
    expect(JSON.stringify(items[0].finding)).not.toContain("ghp_")
  })
})
