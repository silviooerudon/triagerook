import { describe, it, expect, beforeEach, vi } from "vitest"

// vi.mock() factories are hoisted ABOVE all other imports in the test
// file, so we can't reference top-level variables inside them. vi.hoisted
// gives us a stash that runs at the same hoist level so the mocks can
// share state with the test bodies below.
const { authMock, supabaseState, deleteSuppressionMock } = vi.hoisted(() => {
  const authMock = vi.fn()
  const supabaseState: { data?: unknown; error?: unknown } = {
    data: null,
    error: null,
  }
  const deleteSuppressionMock = vi.fn()
  return { authMock, supabaseState, deleteSuppressionMock }
})

function setSupabaseResult(r: { data?: unknown; error?: unknown }) {
  supabaseState.data = r.data
  supabaseState.error = r.error
}

vi.mock("@/auth", () => ({
  auth: () => authMock(),
  // The fix routes also call getAccessToken — provide a default that
  // each test can override.
  getAccessToken: () => Promise.resolve("user-access-token"),
}))

// Supabase chain mock. The terminal call (.single() or .returns()) is
// what fulfills with { data, error }. Intermediate links (from, select,
// eq, in) all return the chain so any call shape composes.
vi.mock("@/lib/supabase", () => {
  const chain: Record<string, unknown> = {}
  ;["from", "select", "eq", "in"].forEach((m) => {
    chain[m] = () => chain
  })
  chain.single = () =>
    Promise.resolve({ data: supabaseState.data, error: supabaseState.error })
  chain.returns = () =>
    Promise.resolve({ data: supabaseState.data, error: supabaseState.error })
  return { supabase: chain }
})

// db-suppressions has its own helper layer; mock just the function the
// DELETE route calls.
vi.mock("@/lib/db-suppressions", () => ({
  deleteSuppression: (...args: unknown[]) => deleteSuppressionMock(...args),
}))

// Fix routes hit several lib functions. Mock the GitHub-side ones with
// simple resolved values so we can focus on the route-level auth gate.
vi.mock("@/lib/octokit-app", async () => {
  const actual =
    await vi.importActual<typeof import("@/lib/octokit-app")>("@/lib/octokit-app")
  return {
    ...actual,
    getInstallationTokenForRepo: vi.fn().mockResolvedValue("install-token"),
    getFileContent: vi.fn().mockResolvedValue("file content"),
    getRepoDefaultBranch: vi.fn().mockResolvedValue("main"),
    createPullRequestFromPatches: vi.fn().mockResolvedValue({
      url: "https://github.com/x/y/pull/1",
      number: 1,
    }),
  }
})

vi.mock("@/lib/repo-access", () => ({
  userHasPushAccess: vi.fn().mockResolvedValue(true),
}))

vi.mock("@/lib/fix-engines", () => ({
  findingSupportsFix: () => "dep-bump",
  runFixEngine: () => ({
    kind: "dep-bump",
    summary: "Bump lodash from 4.17.20 to 4.17.21",
    patches: [{ path: "package.json", content: "{}" }],
  }),
}))

// Imports happen AFTER vi.mock declarations.
import { GET as scanGet } from "@/app/api/scans/[id]/route"
import { GET as sarifGet } from "@/app/api/scans/[id]/sarif/route"
import { GET as diffGet } from "@/app/api/scans/diff/route"
import { DELETE as suppressionsDelete } from "@/app/api/suppressions/[id]/route"
import { POST as fixPreviewPost } from "@/app/api/findings/fix-preview/route"
import { POST as fixPost } from "@/app/api/findings/fix/route"

const USER_ID = "227823977"
const OTHER_USER_ID = "999000111"

function signedInAs(userId: string) {
  authMock.mockResolvedValue({ user: { id: userId } })
}

function notSignedIn() {
  authMock.mockResolvedValue(null)
}

beforeEach(() => {
  authMock.mockReset()
  deleteSuppressionMock.mockReset()
  setSupabaseResult({ data: null, error: null })
})

// ────────────────────────────  /api/scans/[id]  ─────────────────────────────

describe("GET /api/scans/[id] — auth + ownership", () => {
  const id = "scan-uuid-123"
  const ownScan = {
    id,
    owner: "silviooerudon",
    repo: "rg-fix-test",
    scanned_at: "2026-05-13T10:00:00Z",
    result: null,
    duration_ms: 1234,
    files_scanned: 10,
    secrets_count: 0,
    deps_count: 0,
    user_id: USER_ID,
    risk_score: 5,
    risk_breakdown: [],
    prioritized_findings: [],
    suppressed_count: 0,
    posture_score: null,
    posture_grade: null,
    posture_breakdown: null,
    posture_quick_wins: null,
    iam_score: null,
    iam_level: null,
    iam_breakdown: null,
    iam_findings: null,
    iam_files_scanned: null,
    supply_chain_score: null,
    supply_chain_level: null,
    supply_chain_breakdown: null,
    supply_chain_findings: null,
    supply_chain_scanned: null,
  }

  it("returns 401 when no session", async () => {
    notSignedIn()
    const res = await scanGet(new Request("http://x"), {
      params: Promise.resolve({ id }),
    })
    expect(res.status).toBe(401)
  })

  it("returns 404 when the scan does not exist", async () => {
    signedInAs(USER_ID)
    setSupabaseResult({ data: null, error: { message: "no rows" } })
    const res = await scanGet(new Request("http://x"), {
      params: Promise.resolve({ id }),
    })
    expect(res.status).toBe(404)
  })

  it("returns 403 when scan belongs to a different user", async () => {
    signedInAs(USER_ID)
    setSupabaseResult({ data: { ...ownScan, user_id: OTHER_USER_ID }, error: null })
    const res = await scanGet(new Request("http://x"), {
      params: Promise.resolve({ id }),
    })
    expect(res.status).toBe(403)
  })

  it("returns 200 + scan payload (without leaking user_id) on the happy path", async () => {
    signedInAs(USER_ID)
    setSupabaseResult({ data: ownScan, error: null })
    const res = await scanGet(new Request("http://x"), {
      params: Promise.resolve({ id }),
    })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.scan.id).toBe(id)
    expect(body.scan).not.toHaveProperty("user_id")
  })
})

// ──────────────────────  /api/scans/[id]/sarif  ──────────────────────────

describe("GET /api/scans/[id]/sarif — auth + ownership", () => {
  const id = "scan-uuid-sarif"
  const sarifRow = {
    owner: "silviooerudon",
    repo: "rg-fix-test",
    scanned_at: "2026-05-13T10:00:00Z",
    user_id: USER_ID,
    result: null,
    prioritized_findings: [],
    risk_score: 0,
  }

  it("returns 401 when no session", async () => {
    notSignedIn()
    const res = await sarifGet(new Request("http://x"), {
      params: Promise.resolve({ id }),
    })
    expect(res.status).toBe(401)
  })

  it("returns 404 when scan not found", async () => {
    signedInAs(USER_ID)
    setSupabaseResult({ data: null, error: { message: "no rows" } })
    const res = await sarifGet(new Request("http://x"), {
      params: Promise.resolve({ id }),
    })
    expect(res.status).toBe(404)
  })

  it("returns 403 when scan belongs to another user", async () => {
    signedInAs(USER_ID)
    setSupabaseResult({
      data: { ...sarifRow, user_id: OTHER_USER_ID },
      error: null,
    })
    const res = await sarifGet(new Request("http://x"), {
      params: Promise.resolve({ id }),
    })
    expect(res.status).toBe(403)
  })

  it("returns 200 + SARIF content-type on the happy path", async () => {
    signedInAs(USER_ID)
    setSupabaseResult({ data: sarifRow, error: null })
    const res = await sarifGet(new Request("http://x"), {
      params: Promise.resolve({ id }),
    })
    expect(res.status).toBe(200)
    expect(res.headers.get("content-type")).toBe("application/sarif+json")
    // Content-Disposition must include a download filename so the browser
    // saves rather than rendering the JSON inline.
    expect(res.headers.get("content-disposition")).toMatch(/^attachment;/)
  })
})

// ────────────────────────  /api/scans/diff  ──────────────────────────────

describe("GET /api/scans/diff — auth + ownership", () => {
  const fromId = "scan-from"
  const toId = "scan-to"

  function diffUrl(params: Record<string, string>): Request {
    const url = new URL("http://x/api/scans/diff")
    for (const [k, v] of Object.entries(params)) {
      url.searchParams.set(k, v)
    }
    return new Request(url.toString())
  }

  it("returns 401 when no session", async () => {
    notSignedIn()
    const res = await diffGet(diffUrl({ from: fromId, to: toId }))
    expect(res.status).toBe(401)
  })

  it("returns 400 when from/to are missing or identical", async () => {
    signedInAs(USER_ID)
    expect((await diffGet(diffUrl({}))).status).toBe(400)
    expect((await diffGet(diffUrl({ from: fromId, to: fromId }))).status).toBe(400)
  })

  it("returns 404 when one of the scans does not exist", async () => {
    signedInAs(USER_ID)
    setSupabaseResult({ data: [], error: null })
    const res = await diffGet(diffUrl({ from: fromId, to: toId }))
    expect(res.status).toBe(404)
  })

  it("returns 403 when one of the scans belongs to another user", async () => {
    signedInAs(USER_ID)
    setSupabaseResult({
      data: [
        {
          id: fromId,
          owner: "x",
          repo: "y",
          scanned_at: "2026-05-13T10:00:00Z",
          user_id: USER_ID,
          risk_score: 5,
          risk_breakdown: null,
          prioritized_findings: null,
          result: null,
        },
        {
          id: toId,
          owner: "x",
          repo: "y",
          scanned_at: "2026-05-13T11:00:00Z",
          user_id: OTHER_USER_ID, // belongs to someone else
          risk_score: 5,
          risk_breakdown: null,
          prioritized_findings: null,
          result: null,
        },
      ],
      error: null,
    })
    const res = await diffGet(diffUrl({ from: fromId, to: toId }))
    expect(res.status).toBe(403)
  })

  it("returns 400 when scans are from different repos", async () => {
    signedInAs(USER_ID)
    setSupabaseResult({
      data: [
        {
          id: fromId,
          owner: "x",
          repo: "y",
          scanned_at: "2026-05-13T10:00:00Z",
          user_id: USER_ID,
          risk_score: 5,
          risk_breakdown: null,
          prioritized_findings: null,
          result: null,
        },
        {
          id: toId,
          owner: "x",
          repo: "OTHER",
          scanned_at: "2026-05-13T11:00:00Z",
          user_id: USER_ID,
          risk_score: 5,
          risk_breakdown: null,
          prioritized_findings: null,
          result: null,
        },
      ],
      error: null,
    })
    const res = await diffGet(diffUrl({ from: fromId, to: toId }))
    expect(res.status).toBe(400)
  })
})

// ──────────────────────  DELETE /api/suppressions/[id]  ──────────────────

describe("DELETE /api/suppressions/[id] — auth + ownership", () => {
  const id = "supp-uuid"

  it("returns 401 when no session", async () => {
    notSignedIn()
    const res = await suppressionsDelete(new Request("http://x"), {
      params: Promise.resolve({ id }),
    })
    expect(res.status).toBe(401)
  })

  it("returns 404 when delete reports no row (own row not found OR foreign row)", async () => {
    signedInAs(USER_ID)
    deleteSuppressionMock.mockResolvedValue(false)
    const res = await suppressionsDelete(new Request("http://x"), {
      params: Promise.resolve({ id }),
    })
    expect(res.status).toBe(404)
    // The helper must be called with the AUTH user id, not the URL param —
    // that is the ownership gate. Verifies we're not relying on a foreign
    // user_id sneaking in via the path.
    expect(deleteSuppressionMock).toHaveBeenCalledWith(USER_ID, id)
  })

  it("returns 200 when deletion succeeds", async () => {
    signedInAs(USER_ID)
    deleteSuppressionMock.mockResolvedValue(true)
    const res = await suppressionsDelete(new Request("http://x"), {
      params: Promise.resolve({ id }),
    })
    expect(res.status).toBe(200)
  })
})

// ──────────────────────  POST /api/findings/fix*  ───────────────────────

describe("POST /api/findings/fix-preview + fix — auth gate", () => {
  const body = {
    owner: "silviooerudon",
    repo: "rg-fix-test",
    finding: {
      kind: "dependency" as const,
      score: 50,
      data: {
        package: "lodash",
        version: "4.17.20",
        severity: "high" as const,
        vulnerable_versions: "<4.17.21",
        source: "package.json",
        ghsa: null,
        url: null,
        cvss_score: null,
      },
    },
  }

  function bodyRequest(): Request {
    return new Request("http://x", {
      method: "POST",
      body: JSON.stringify(body),
      headers: { "content-type": "application/json" },
    })
  }

  it("fix-preview returns 401 when no session", async () => {
    notSignedIn()
    const res = await fixPreviewPost(bodyRequest())
    expect(res.status).toBe(401)
  })

  it("fix returns 401 when no session", async () => {
    notSignedIn()
    const res = await fixPost(bodyRequest())
    expect(res.status).toBe(401)
  })

  it("fix-preview returns 400 on invalid JSON body even with valid session", async () => {
    signedInAs(USER_ID)
    const bad = new Request("http://x", { method: "POST", body: "not json" })
    const res = await fixPreviewPost(bad)
    expect(res.status).toBe(400)
  })

  it("fix returns 400 on invalid JSON body even with valid session", async () => {
    signedInAs(USER_ID)
    const bad = new Request("http://x", { method: "POST", body: "not json" })
    const res = await fixPost(bad)
    expect(res.status).toBe(400)
  })
})
