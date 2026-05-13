import { auth } from "@/auth"
import { getUserId } from "@/lib/auth-utils"
import {
  listSuppressions,
  listAllUserSuppressions,
  createSuppression,
  type DbSuppression,
} from "@/lib/db-suppressions"
import { isSafeOwnerRepo } from "@/lib/path-validation"
import { NextResponse } from "next/server"

export const dynamic = "force-dynamic"

export async function GET(request: Request) {
  const session = await auth()
  const userId = getUserId(session)
  if (!userId) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const url = new URL(request.url)
  const owner = url.searchParams.get("owner")
  const repo = url.searchParams.get("repo")

  let rows: DbSuppression[]
  try {
    if (owner && repo) {
      if (!isSafeOwnerRepo(owner) || !isSafeOwnerRepo(repo)) {
        return NextResponse.json({ error: "Invalid owner or repo" }, { status: 400 })
      }
      rows = await listSuppressions(userId, owner, repo)
    } else {
      rows = await listAllUserSuppressions(userId)
    }
  } catch (err) {
    console.error("[suppressions] list failed:", err)
    return NextResponse.json({ error: "Failed to list suppressions" }, { status: 500 })
  }

  return NextResponse.json({ suppressions: rows })
}

type CreateBody = {
  owner?: string
  repo?: string
  pathGlob?: string
  ruleGlob?: string | null
  reason?: string | null
  expiresAt?: string | null
}

export async function POST(request: Request) {
  const session = await auth()
  const userId = getUserId(session)
  if (!userId) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  let body: CreateBody
  try {
    body = (await request.json()) as CreateBody
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 })
  }

  const { owner, repo, pathGlob } = body
  if (!owner || !repo || !pathGlob) {
    return NextResponse.json(
      { error: "Missing required fields: owner, repo, pathGlob" },
      { status: 400 },
    )
  }
  if (!isSafeOwnerRepo(owner) || !isSafeOwnerRepo(repo)) {
    return NextResponse.json({ error: "Invalid owner or repo" }, { status: 400 })
  }
  if (pathGlob.length > 500) {
    return NextResponse.json({ error: "pathGlob too long" }, { status: 400 })
  }
  if (body.ruleGlob && body.ruleGlob.length > 200) {
    return NextResponse.json({ error: "ruleGlob too long" }, { status: 400 })
  }
  if (body.reason && body.reason.length > 1000) {
    return NextResponse.json({ error: "reason too long" }, { status: 400 })
  }

  // expiresAt accepted as either YYYY-MM-DD or full ISO 8601. Anything
  // else is rejected to keep storage clean.
  if (body.expiresAt) {
    const parsed = new Date(body.expiresAt)
    if (Number.isNaN(parsed.getTime())) {
      return NextResponse.json({ error: "Invalid expiresAt" }, { status: 400 })
    }
  }

  try {
    const row = await createSuppression({
      userId,
      owner,
      repo,
      pathGlob,
      ruleGlob: body.ruleGlob ?? null,
      reason: body.reason ?? null,
      expiresAt: body.expiresAt ?? null,
    })
    return NextResponse.json({ suppression: row }, { status: 201 })
  } catch (err) {
    console.error("[suppressions] insert failed:", err)
    return NextResponse.json({ error: "Failed to create suppression" }, { status: 500 })
  }
}
