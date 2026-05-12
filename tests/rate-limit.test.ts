import { describe, it, expect } from "vitest"
import {
  checkAndIncrement,
  type RateLimitStorage,
  type RateLimitRecord,
} from "@/lib/rate-limit"

function inMemoryStorage(): RateLimitStorage {
  const store = new Map<string, RateLimitRecord>()
  return {
    async get(key) {
      return store.get(key) ?? null
    },
    async upsert(key, record) {
      store.set(key, record)
    },
  }
}

const POLICY = { limit: 3, windowMs: 60_000 }

describe("checkAndIncrement", () => {
  it("allows the first request and creates a fresh window", async () => {
    const storage = inMemoryStorage()
    const result = await checkAndIncrement("ip-1", POLICY, {
      storage,
      now: new Date("2026-05-11T12:00:00Z"),
    })
    expect(result.allowed).toBe(true)
    expect(result.remaining).toBe(2)
  })

  it("allows up to the limit within the same window", async () => {
    const storage = inMemoryStorage()
    const fixedNow = new Date("2026-05-11T12:00:00Z")
    const r1 = await checkAndIncrement("ip-1", POLICY, { storage, now: fixedNow })
    const r2 = await checkAndIncrement("ip-1", POLICY, { storage, now: fixedNow })
    const r3 = await checkAndIncrement("ip-1", POLICY, { storage, now: fixedNow })
    expect([r1.allowed, r2.allowed, r3.allowed]).toEqual([true, true, true])
    expect([r1.remaining, r2.remaining, r3.remaining]).toEqual([2, 1, 0])
  })

  it("denies the (limit+1)-th request in the same window", async () => {
    const storage = inMemoryStorage()
    const fixedNow = new Date("2026-05-11T12:00:00Z")
    await checkAndIncrement("ip-1", POLICY, { storage, now: fixedNow })
    await checkAndIncrement("ip-1", POLICY, { storage, now: fixedNow })
    await checkAndIncrement("ip-1", POLICY, { storage, now: fixedNow })
    const r4 = await checkAndIncrement("ip-1", POLICY, { storage, now: fixedNow })
    expect(r4.allowed).toBe(false)
    expect(r4.remaining).toBe(0)
    expect(r4.retryAfterSeconds).toBeGreaterThan(0)
  })

  it("resets the counter when the window expires", async () => {
    const storage = inMemoryStorage()
    const t0 = new Date("2026-05-11T12:00:00Z")
    const tLater = new Date("2026-05-11T12:02:00Z")
    await checkAndIncrement("ip-1", POLICY, { storage, now: t0 })
    await checkAndIncrement("ip-1", POLICY, { storage, now: t0 })
    await checkAndIncrement("ip-1", POLICY, { storage, now: t0 })
    const r4 = await checkAndIncrement("ip-1", POLICY, { storage, now: tLater })
    expect(r4.allowed).toBe(true)
    expect(r4.remaining).toBe(POLICY.limit - 1)
  })

  it("tracks counters per key independently", async () => {
    const storage = inMemoryStorage()
    const now = new Date("2026-05-11T12:00:00Z")
    await checkAndIncrement("ip-1", POLICY, { storage, now })
    await checkAndIncrement("ip-1", POLICY, { storage, now })
    await checkAndIncrement("ip-1", POLICY, { storage, now })
    const overIp1 = await checkAndIncrement("ip-1", POLICY, { storage, now })
    const ip2 = await checkAndIncrement("ip-2", POLICY, { storage, now })
    expect(overIp1.allowed).toBe(false)
    expect(ip2.allowed).toBe(true)
  })

  it("fails open when storage throws (does not break the request flow)", async () => {
    const storage: RateLimitStorage = {
      async get() {
        throw new Error("DB down")
      },
      async upsert() {
        /* unreachable */
      },
    }
    const r = await checkAndIncrement("ip-1", POLICY, {
      storage,
      now: new Date(),
    })
    expect(r.allowed).toBe(true)
  })
})
