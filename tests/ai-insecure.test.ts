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

  it("matches the changeme/change-me placeholder as a whole token only", () => {
    expect(ids('const pw = "changeme"')).toContain("ai-placeholder-credential")
    expect(ids('password = "change-me"', "x.py")).toContain("ai-placeholder-credential")
  })

  it("matches an sk- placeholder where the x-run is followed by more chars", () => {
    // Regression: `\bsk-x{6,}\b` (trailing \b) wrongly required a boundary after
    // the x-run, missing the canonical `sk-xxxx<more>` placeholder shape. (Suffix
    // kept obviously-fake so push-protection doesn't read it as a real key.)
    expect(ids('const key = "sk-xxxxxxxxxxxxFAKEPLACEHOLDER"')).toContain(
      "ai-placeholder-credential",
    )
  })

  it("matches plural placeholder tokens without re-admitting longer words", () => {
    expect(ids('const yourSecrets = load("your-secrets")')).toContain("ai-placeholder-credential")
    expect(ids("placeholder_keys = {}", "x.py")).toContain("ai-placeholder-credential")
    // still NOT matching the longer-word substrings
    expect(ids("const placeholderKeyboard = init()")).not.toContain("ai-placeholder-credential")
    expect(ids("secretary = User()", "x.py")).not.toContain("ai-placeholder-credential")
  })

  it("does NOT substring-match placeholder tokens inside longer identifiers", () => {
    // Word-boundary regression: these must NOT fire ai-placeholder-credential.
    expect(ids("const placeholderKeyboardShortcut = registerKey()")).not.toContain(
      "ai-placeholder-credential",
    )
    expect(ids("import { your_tokenizer } from './nlp'")).not.toContain(
      "ai-placeholder-credential",
    )
    expect(ids("function replaceThisNode(n) { return n }")).not.toContain(
      "ai-placeholder-credential",
    )
  })

  it("redacts an unquoted real secret token from lineContent", () => {
    const out = scanAiInsecure("API_KEY = sk_live_abcdefABCDEF123456  # change-me", "x.py", false)
    const f = out.find((x) => x.ruleId === "ai-placeholder-credential")
    expect(f).toBeTruthy()
    expect(f?.lineContent).not.toContain("sk_live_abcdefABCDEF123456")
    expect(f?.lineContent).toContain("REDACTED")
  })

  it("flags bare except: pass even with a trailing comment", () => {
    expect(ids("    except: pass  # ignore errors", "x.py")).toContain("ai-bare-except-pass")
  })

  it("does NOT flag a bare run of x's (order-id / format placeholders)", () => {
    // Regression: a generic `x{12,}` token flagged LLM-prompt format examples
    // like "order ID (format: xxxx-xxxxxxxxxxxxxxxx)" on juice-shop (13 FPs).
    expect(ids("// format: xxxx-xxxxxxxxxxxxxxxx", "routes/chat.ts")).not.toContain(
      "ai-placeholder-credential",
    )
    // sk-prefixed placeholders are specific enough to keep.
    expect(ids('const k = "sk-xxxxxxxx"')).toContain("ai-placeholder-credential")
  })

  it("does NOT match 'change_me' as a substring of a longer identifier", () => {
    // Regression: django/django produced 39 false positives because
    // `change[-_]?me` matched the "change_me" prefix of "change_message".
    expect(ids("change_message = json.dumps(payload)", "models.py")).not.toContain(
      "ai-placeholder-credential",
    )
    expect(ids("def construct_change_message(self, request):", "options.py")).not.toContain(
      "ai-placeholder-credential",
    )
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
