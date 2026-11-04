import { auth } from "@/auth"
import { getUserId } from "@/lib/auth-utils"
import { exportUserData } from "@/lib/account"
import { NextResponse } from "next/server"

export const dynamic = "force-dynamic"

// GET /api/account/export — downloads every row TriageRook stores for the
// signed-in user as JSON (GDPR Art. 15/20, LGPD Art. 18 II/V).
//
// GET is safe here: it changes nothing, and the browser's same-origin
// policy stops a third-party page from reading the response body.
export async function GET() {
  const session = await auth()
  const userId = getUserId(session)
  if (!userId) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  try {
    const payload = await exportUserData(userId)
    const date = payload.exportedAt.slice(0, 10)
    return new NextResponse(JSON.stringify(payload, null, 2), {
      status: 200,
      headers: {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Disposition": `attachment; filename="triagerook-data-${date}.json"`,
        // Personal data: never let a shared cache or the browser's
        // back/forward cache keep a copy.
        "Cache-Control": "no-store, private",
      },
    })
  } catch (err) {
    console.error("[account/export] failed:", err instanceof Error ? err.message : err)
    return NextResponse.json({ error: "Failed to export data" }, { status: 500 })
  }
}
