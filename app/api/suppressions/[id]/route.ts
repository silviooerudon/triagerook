import { auth } from "@/auth"
import { getUserId } from "@/lib/auth-utils"
import { deleteSuppression } from "@/lib/db-suppressions"
import { NextResponse } from "next/server"

export const dynamic = "force-dynamic"

type RouteParams = {
  params: Promise<{ id: string }>
}

export async function DELETE(_request: Request, { params }: RouteParams) {
  const session = await auth()
  const userId = getUserId(session)
  if (!userId) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  const { id } = await params

  try {
    const deleted = await deleteSuppression(userId, id)
    if (!deleted) {
      // Either the row doesn't exist or it belongs to someone else.
      // Don't distinguish — both 404 from the user's perspective.
      return NextResponse.json({ error: "Not found" }, { status: 404 })
    }
    return NextResponse.json({ ok: true })
  } catch (err) {
    console.error("[suppressions/:id] delete failed:", err)
    return NextResponse.json({ error: "Failed to delete suppression" }, { status: 500 })
  }
}
