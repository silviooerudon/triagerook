import { auth } from "@/auth"
import { supabase } from "@/lib/supabase"
import { getUserId } from "@/lib/auth-utils"
import { NextResponse } from "next/server"

export async function GET() {
  // 1. Check authentication
  const session = await auth()
  const userId = getUserId(session)
  if (!userId) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
  }

  // 2. Fetch user's scans (most recent first, cap at 50)
  const { data, error } = await supabase
    .from("scans")
    .select("id, owner, repo, scanned_at, secrets_count, deps_count, files_scanned, duration_ms")
    .eq("user_id", userId)
    .order("scanned_at", { ascending: false })
    .limit(50)

  if (error) {
    console.error("[scans] Failed to fetch:", error.message)
    return NextResponse.json({ error: "Failed to fetch scans" }, { status: 500 })
  }

  return NextResponse.json({ scans: data ?? [] })
}