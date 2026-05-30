import { describe, it, expect } from "vitest"
import { scanBusinessLogic, BIZ_LOGIC_RULES } from "@/lib/biz-logic"

function ids(content: string, path = "app.js"): string[] {
  return scanBusinessLogic(content, path, false).map((f) => f.ruleId)
}

describe("scanBusinessLogic — mass assignment", () => {
  it("flags an ORM update fed the whole request body (JS)", () => {
    expect(ids("await User.update(req.body, { where: { id } })")).toContain(
      "mass-assignment-orm-js",
    )
  })

  it("flags new Model(req.body) (JS)", () => {
    expect(ids("const u = new User(req.body)")).toContain("mass-assignment-new-model-js")
  })

  it("flags **request.data splat into create (Python)", () => {
    expect(ids("User.objects.create(**request.data)", "views.py")).toContain(
      "mass-assignment-py",
    )
  })

  it("does NOT flag an explicit field list", () => {
    expect(ids("await User.update({ name: req.body.name }, { where: { id } })")).not.toContain(
      "mass-assignment-orm-js",
    )
  })
})

describe("scanBusinessLogic — privilege escalation", () => {
  it("flags role assigned from request body (JS)", () => {
    expect(ids("const role = req.body.role")).toContain("privilege-from-client-js")
    expect(ids("user.isAdmin = req.body.isAdmin")).toContain("privilege-from-client-js")
  })

  it("flags is_staff assigned from request (Python)", () => {
    expect(ids("user.is_staff = request.data['is_staff']", "views.py")).toContain(
      "privilege-from-client-py",
    )
  })

  it("does NOT flag a role derived from the session", () => {
    expect(ids("const role = req.session.user.role")).not.toContain("privilege-from-client-js")
  })
})

describe("scanBusinessLogic — payment tampering", () => {
  it("flags charge amount taken from the client (JS)", () => {
    expect(ids("stripe.charges.create({ amount: req.body.amount })")).toContain(
      "payment-amount-from-client-js",
    )
  })

  it("flags amount taken from request (Python)", () => {
    expect(ids("amount = request.data['amount']", "checkout.py")).toContain(
      "payment-amount-from-client-py",
    )
  })

  it("does NOT flag an amount computed server-side", () => {
    expect(ids("const amount = cart.totalCents")).not.toContain(
      "payment-amount-from-client-js",
    )
  })

  it("does NOT flag amount: req.body in a logging/serialization call", () => {
    // Structured logging of a request field isn't payment tampering.
    expect(ids("logger.info({ amount: req.body.amount, userId: req.user.id })")).not.toContain(
      "payment-amount-from-client-js",
    )
    expect(ids("console.log({ price: req.body.price })")).not.toContain(
      "payment-amount-from-client-js",
    )
    // but a real charge still fires
    expect(ids("stripe.charges.create({ amount: req.body.amount })")).toContain(
      "payment-amount-from-client-js",
    )
  })

  it("does NOT over-suppress a real charge wrapped in res.json or a fluent .error/.info", () => {
    // The suppressor must only skip logging calls ON a logger object, not any
    // line that happens to contain res.json / .error( / .info(.
    expect(ids("return res.json(await charge({ amount: req.body.amount }))")).toContain(
      "payment-amount-from-client-js",
    )
    expect(ids("gateway.charge({ amount: req.body.amount }).error(handleErr)")).toContain(
      "payment-amount-from-client-js",
    )
  })
})

describe("scanBusinessLogic — IDOR", () => {
  it("flags findById with a client id (JS)", () => {
    expect(ids("const doc = await Order.findById(req.params.id)")).toContain(
      "idor-direct-lookup-js",
    )
  })

  it("flags .objects.get(pk=request...) (Python)", () => {
    expect(ids("order = Order.objects.get(pk=request.GET['id'])", "views.py")).toContain(
      "idor-direct-lookup-py",
    )
  })

  it("does NOT flag a lookup scoped to the session user", () => {
    expect(
      ids("const doc = await Order.findOne({ _id: req.params.id, owner: req.user.id })"),
    ).not.toContain("idor-direct-lookup-js")
  })
})

describe("scanBusinessLogic — hygiene", () => {
  it("skips comment lines (language-aware)", () => {
    expect(ids("// const role = req.body.role")).toEqual([])
    expect(ids("# user.is_staff = request.data['x']", "views.py")).toEqual([])
  })

  it("does NOT treat a JS '#' line as a comment (ES private field)", () => {
    // `#` is a comment in Python but a private class field in JS/TS, so a
    // privilege assignment in a private field must still be scanned.
    expect(ids("#role = req.body.role", "user.js")).toContain("privilege-from-client-js")
  })

  it("ignores non-code files", () => {
    expect(scanBusinessLogic("amount: req.body.amount", "README.md", false)).toEqual([])
  })

  it("propagates the test-fixture flag", () => {
    const out = scanBusinessLogic("const role = req.body.role", "app.js", true)
    expect(out[0]?.likelyTestFixture).toBe(true)
  })

  it("every rule carries a CWE and a category", () => {
    for (const r of BIZ_LOGIC_RULES) {
      expect(r.cwe).toMatch(/^CWE-\d+$/)
      expect(["access-control", "business-logic"]).toContain(r.category)
    }
  })
})
