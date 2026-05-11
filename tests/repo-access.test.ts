import { describe, it, expect } from "vitest"
import { userHasPushAccess } from "@/lib/repo-access"

function fakeFetch(responses: Array<{ status: number; body?: unknown }>) {
  let i = 0
  return async (_input: RequestInfo | URL, _init?: RequestInit) => {
    const r = responses[i++] ?? { status: 500 }
    return new Response(JSON.stringify(r.body ?? {}), {
      status: r.status,
      headers: { "Content-Type": "application/json" },
    })
  }
}

describe("userHasPushAccess", () => {
  it("returns true when GitHub responds 200 with permissions.push=true", async () => {
    const result = await userHasPushAccess("token", "silvio", "repo", {
      fetchImpl: fakeFetch([{ status: 200, body: { permissions: { push: true } } }]),
    })
    expect(result).toBe(true)
  })

  it("returns true when permissions.admin=true even if push is omitted", async () => {
    const result = await userHasPushAccess("token", "silvio", "repo", {
      fetchImpl: fakeFetch([{ status: 200, body: { permissions: { admin: true } } }]),
    })
    expect(result).toBe(true)
  })

  it("returns false when GitHub responds 200 with permissions.push=false", async () => {
    const result = await userHasPushAccess("token", "silvio", "repo", {
      fetchImpl: fakeFetch([{ status: 200, body: { permissions: { push: false } } }]),
    })
    expect(result).toBe(false)
  })

  it("returns false when GitHub responds 200 without a permissions field", async () => {
    const result = await userHasPushAccess("token", "silvio", "repo", {
      fetchImpl: fakeFetch([{ status: 200, body: {} }]),
    })
    expect(result).toBe(false)
  })

  it("returns false on 404 (repo invisible to this user)", async () => {
    const result = await userHasPushAccess("token", "silvio", "private-repo", {
      fetchImpl: fakeFetch([{ status: 404, body: { message: "Not Found" } }]),
    })
    expect(result).toBe(false)
  })

  it("returns false on 403 (forbidden)", async () => {
    const result = await userHasPushAccess("token", "silvio", "repo", {
      fetchImpl: fakeFetch([{ status: 403 }]),
    })
    expect(result).toBe(false)
  })

  it("returns false when fetch itself throws", async () => {
    const result = await userHasPushAccess("token", "silvio", "repo", {
      fetchImpl: async () => {
        throw new Error("network down")
      },
    })
    expect(result).toBe(false)
  })

  it("rejects unsafe owner/repo before issuing any HTTP call", async () => {
    let called = false
    const fetchSpy = async () => {
      called = true
      return new Response("{}", { status: 200 })
    }
    expect(
      await userHasPushAccess("token", "../etc", "repo", { fetchImpl: fetchSpy }),
    ).toBe(false)
    expect(called).toBe(false)
  })

  it("rejects empty token before issuing any HTTP call", async () => {
    let called = false
    const fetchSpy = async () => {
      called = true
      return new Response("{}", { status: 200 })
    }
    expect(
      await userHasPushAccess("", "silvio", "repo", { fetchImpl: fetchSpy }),
    ).toBe(false)
    expect(called).toBe(false)
  })
})
