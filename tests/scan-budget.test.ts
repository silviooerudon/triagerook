import { describe, it, expect, beforeEach, afterEach } from "vitest"
import {
  DEFAULTS,
  LIMITS,
  getMaxFilesToScan,
  getMaxScanTimeMs,
  parsePositiveIntInRange,
} from "@/lib/scan-budget"

describe("parsePositiveIntInRange", () => {
  it("returns the default when raw is undefined", () => {
    expect(parsePositiveIntInRange(undefined, 100, 1000)).toBe(100)
  })

  it("returns the default when raw is empty string", () => {
    expect(parsePositiveIntInRange("", 100, 1000)).toBe(100)
  })

  it("returns the default when raw is not a number", () => {
    expect(parsePositiveIntInRange("not-a-number", 100, 1000)).toBe(100)
  })

  it("returns the default for zero or negative values", () => {
    expect(parsePositiveIntInRange("0", 100, 1000)).toBe(100)
    expect(parsePositiveIntInRange("-5", 100, 1000)).toBe(100)
  })

  it("parses a valid positive integer", () => {
    expect(parsePositiveIntInRange("500", 100, 1000)).toBe(500)
  })

  it("caps at the absolute max when raw exceeds it", () => {
    expect(parsePositiveIntInRange("99999", 100, 1000)).toBe(1000)
  })

  it("strips trailing junk via parseInt (loose mode)", () => {
    // parseInt allows trailing non-numeric chars; the function inherits
    // that behavior. Document it rather than fight it.
    expect(parsePositiveIntInRange("500abc", 100, 1000)).toBe(500)
  })
})

// Tests below mutate process.env. Each test restores the original value
// so the env stays clean across the file.

describe("getMaxFilesToScan — env override", () => {
  const original = process.env.SCAN_MAX_FILES
  afterEach(() => {
    if (original === undefined) delete process.env.SCAN_MAX_FILES
    else process.env.SCAN_MAX_FILES = original
  })

  it("returns DEFAULTS.files when SCAN_MAX_FILES is unset", () => {
    delete process.env.SCAN_MAX_FILES
    expect(getMaxFilesToScan()).toBe(DEFAULTS.files)
  })

  it("returns the env value when valid", () => {
    process.env.SCAN_MAX_FILES = "2500"
    expect(getMaxFilesToScan()).toBe(2500)
  })

  it("falls back to default on garbage env value", () => {
    process.env.SCAN_MAX_FILES = "not-a-number"
    expect(getMaxFilesToScan()).toBe(DEFAULTS.files)
  })

  it("caps at LIMITS.files even when the env asks for more", () => {
    process.env.SCAN_MAX_FILES = "1000000"
    expect(getMaxFilesToScan()).toBe(LIMITS.files)
  })
})

describe("getMaxScanTimeMs — env override", () => {
  const original = process.env.SCAN_MAX_TIME_MS
  afterEach(() => {
    if (original === undefined) delete process.env.SCAN_MAX_TIME_MS
    else process.env.SCAN_MAX_TIME_MS = original
  })

  it("returns DEFAULTS.timeMs when SCAN_MAX_TIME_MS is unset", () => {
    delete process.env.SCAN_MAX_TIME_MS
    expect(getMaxScanTimeMs()).toBe(DEFAULTS.timeMs)
  })

  it("returns the env value when valid (e.g., Pro tier bumping to 280s)", () => {
    process.env.SCAN_MAX_TIME_MS = "280000"
    expect(getMaxScanTimeMs()).toBe(280000)
  })

  it("caps at LIMITS.timeMs to keep 10s headroom below Vercel Pro 300s hard limit", () => {
    process.env.SCAN_MAX_TIME_MS = "300000"
    expect(getMaxScanTimeMs()).toBe(LIMITS.timeMs)
    expect(LIMITS.timeMs).toBeLessThan(300_000)
  })
})

describe("DEFAULTS sanity", () => {
  it("ships safe Hobby-tier defaults out of the box", () => {
    // If these change, double-check the function timeout on Vercel
    // Hobby (60s) — the time budget must stay well below it, and the
    // file budget must be reachable within that time.
    expect(DEFAULTS.files).toBe(1000)
    expect(DEFAULTS.timeMs).toBe(55_000)
    expect(DEFAULTS.timeMs).toBeLessThan(60_000)
  })
})
