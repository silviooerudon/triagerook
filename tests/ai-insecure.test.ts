import { describe, it, expect } from "vitest"
import { scanAiInsecure, AI_INSECURE_RULES } from "@/lib/ai-insecure"

function ids(content: string, path = "app.js"): string[] {
  return scanAiInsecure(content, path, false).map((f) => f.ruleId)
}

describe("scanAiInsecure — placeholder credentials", () => {
  it("flags your-api-key / INSERT_API_KEY_HERE / change-me placeholders", () => {
    expect(ids('const key = "your-api-key"')).toContain("ai-placeholder-credential")
    expect(ids('API_KEY = "INSERT_API_KEY_HERE"', "config.py")).toContain(
      "ai-placeholder-credential",
    )
    expect(ids('const pw = "change-me"')).toContain("ai-placeholder-credential")
    expect(ids('token = "sk-xxxxxxxx"', "config.py")).toContain("ai-placeholder-credential")
  })

  it("masks the placeholder literal in lineContent", () => {
    const out = scanAiInsecure('const key = "your-api-key-here"', "app.js", false)
    const f = out.find((x) => x.ruleId === "ai-placeholder-credential")
    expect(f?.lineContent).toContain("REDACTED")
    expect(f?.lineContent).not.toContain("your-api-key-here")
  })

  it("does NOT flag a real-looking env read", () => {
    expect(ids("const key = process.env.API_KEY")).not.toContain("ai-placeholder-credential")
  })
})

describe("scanAiInsecure — deferred security TODO", () => {
  it("flags a TODO that defers auth/validation", () => {
    expect(ids("// TODO: add authentication here")).toContain("ai-todo-security")
    expect(ids("# FIXME: validate the user input", "views.py")).toContain("ai-todo-security")
    expect(ids("// TODO: check authorization before delete")).toContain("ai-todo-security")
  })

  it("does NOT flag an unrelated TODO", () => {
    expect(ids("// TODO: rename this variable")).not.toContain("ai-todo-security")
  })
})

describe("scanAiInsecure — not-for-production disclaimers", () => {
  it("flags generated disclaimers", () => {
    expect(ids("// In a real application, you would hash the password")).toContain(
      "ai-demo-disclaimer",
    )
    expect(ids("# For demonstration purposes only", "x.py")).toContain("ai-demo-disclaimer")
    expect(ids("// This is a simplified example")).toContain("ai-demo-disclaimer")
    expect(ids("// Don't do this in production")).toContain("ai-demo-disclaimer")
  })

  it("does NOT flag ordinary prose", () => {
    expect(ids("// returns the application config")).not.toContain("ai-demo-disclaimer")
  })
})

describe("scanAiInsecure — swallowed exceptions", () => {
  it("flags bare except: pass (Python)", () => {
    expect(ids("    except: pass", "x.py")).toContain("ai-bare-except-pass")
    expect(ids("    except Exception: pass", "x.py")).toContain("ai-bare-except-pass")
  })

  it("flags empty catch {} (JS)", () => {
    expect(ids("try { risky() } catch (e) {}")).toContain("ai-empty-catch")
    expect(ids("} catch {}")).toContain("ai-empty-catch")
  })

  it("does NOT flag a catch that handles the error", () => {
    expect(ids("} catch (e) { logger.error(e) }")).not.toContain("ai-empty-catch")
  })
})

describe("scanAiInsecure — hygiene", () => {
  it("ignores files outside the source allowlist", () => {
    expect(scanAiInsecure("TODO: add auth", "notes.txt", false)).toEqual([])
  })

  it("propagates the test-fixture flag", () => {
    const out = scanAiInsecure('const k = "your-api-key"', "app.js", true)
    expect(out[0]?.likelyTestFixture).toBe(true)
  })

  it("does not flag its own rule prose (self-reference guard)", () => {
    // Lines shaped like this detector's own definitions must be skipped.
    expect(
      ids('description: "in a real application you would validate this",'),
    ).not.toContain("ai-demo-disclaimer")
    expect(ids('name: "TODO: add authorization",')).not.toContain("ai-todo-security")
  })

  it("every rule carries the ai-generated category and a CWE", () => {
    for (const r of AI_INSECURE_RULES) {
      expect(r.category).toBe("ai-generated")
      expect(r.cwe).toMatch(/^CWE-\d+$/)
    }
  })
})
