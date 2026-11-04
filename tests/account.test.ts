import { describe, it, expect, beforeEach, vi } from "vitest"

// Records every Supabase call so tests can assert that export/erasure is
// always scoped to the session user's id and touches every user table.
const { calls, authMock, state } = vi.hoisted(() => {
  const calls: { table: string; op: string; filters: [string, string, unknown][] }[] = []
  const authMock = vi.fn()
  const state: { rows: unknown[]; error: { message: string } | null } = {
    rows: [],
    error: null,
  }
  return { calls, authMock, state }
})

vi.mock("@/auth", () => ({ auth: () => authMock() }))

vi.mock("@/lib/supabase", () => {
  function from(table: string) {
    const rec = { table, op: "select", filters: [] as [string, string, unknown][] }
    calls.push(rec)
    const result = () => Promise.resolve({ data: state.rows, error: state.error, count: state.rows.length })
    const chain: Record<string, unknown> = {
      select: () => chain,
      delete: () => {
        rec.op = "delete"
        return chain
      },
      eq: (col: string, val: unknown) => {
        rec.filters.push(["eq", col, val])
        return chain
      },
      order: () => chain,
      range: () => result(),
      then: (res: (v: unknown) => unknown, rej: (e: unknown) => unknown) =>
        result().then(res, rej),
    }
    return chain
  }
  return { supabase: { from } }
})

import { deleteUserData, exportUserData, USER_OWNED_TABLES } from "@/lib/account"
import { GET as exportGet } from "@/app/api/account/export/route"

const USER_ID = "227823977"

beforeEach(() => {
  calls.length = 0
  authMock.mockReset()
  state.rows = []
  state.error = null
})

describe("deleteUserData", () => {
  it("deletes from every user-owned table, filtered by user_id", async () => {
    await deleteUserData(USER_ID)
    const deletes = calls.filter((c) => c.op === "delete")
    expect(deletes.map((d) => d.table).sort()).toEqual([...USER_OWNED_TABLES].sort())
    for (const d of deletes) {
      expect(d.filters).toEqual([["eq", "user_id", USER_ID]])
    }
  })

  it("refuses an empty user id (would otherwise match nothing — or everything)", async () => {
    await expect(deleteUserData("")).rejects.toThrow()
    expect(calls).toHaveLength(0)
  })

  it("surfaces database errors instead of reporting success", async () => {
    state.error = { message: "boom" }
    await expect(deleteUserData(USER_ID)).rejects.toThrow(/boom/)
  })
})

describe("exportUserData", () => {
  it("reads only the user's rows from every table", async () => {
    state.rows = [{ id: "a", user_id: USER_ID }]
    const out = await exportUserData(USER_ID)
    expect(Object.keys(out.data).sort()).toEqual([...USER_OWNED_TABLES].sort())
    for (const c of calls) {
      expect(c.op).toBe("select")
      expect(c.filters).toEqual([["eq", "user_id", USER_ID]])
    }
  })
})

describe("GET /api/account/export", () => {
  it("returns 401 without a session and touches no data", async () => {
    authMock.mockResolvedValue(null)
    const res = await exportGet()
    expect(res.status).toBe(401)
    expect(calls).toHaveLength(0)
  })

  it("returns an uncacheable JSON attachment for the session user", async () => {
    authMock.mockResolvedValue({ user: { id: USER_ID } })
    const res = await exportGet()
    expect(res.status).toBe(200)
    expect(res.headers.get("Cache-Control")).toContain("no-store")
    expect(res.headers.get("Content-Disposition")).toMatch(/^attachment;/)
    const body = await res.json()
    expect(body.userId).toBe(USER_ID)
  })
})
