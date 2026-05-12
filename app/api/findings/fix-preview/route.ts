import { auth } from "@/auth"
import { NextResponse } from "next/server"
import { prepareFixContext, type FixContextRequestBody } from "@/lib/fix-context"

export const dynamic = "force-dynamic"

export async function POST(request: Request) {
  const session = await auth()
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  let body: FixContextRequestBody
  try {
    body = (await request.json()) as FixContextRequestBody
  } catch {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 })
  }

  const outcome = await prepareFixContext(session, body, "fix-preview")
  if (!outcome.ok) {
    return NextResponse.json({ error: outcome.error }, { status: outcome.status })
  }

  const { engineResult, defaultBranch } = outcome.ctx
  return NextResponse.json({
    kind: engineResult.kind,
    summary: engineResult.summary,
    patches: engineResult.patches,
    baseBranch: defaultBranch,
  })
}
