import { ImageResponse } from "next/og"
import { supabase } from "@/lib/supabase"

export const runtime = "nodejs"
export const alt = "RepoGuard scan summary"
export const size = { width: 1200, height: 630 }
export const contentType = "image/png"

type ScanRow = {
  scanned_at: string
  risk_score: number | null
  secrets_count: number | null
  deps_count: number | null
  files_scanned: number | null
}

async function fetchLatestScan(owner: string, repo: string): Promise<ScanRow | null> {
  try {
    const { data, error } = await supabase
      .from("scans")
      .select("scanned_at, risk_score, secrets_count, deps_count, files_scanned")
      .eq("owner", owner)
      .eq("repo", repo)
      .order("scanned_at", { ascending: false })
      .limit(1)
      .maybeSingle()
    if (error) return null
    return data
  } catch {
    return null
  }
}

function riskLabel(score: number | null): { text: string; color: string } {
  if (score === null) return { text: "—", color: "#94a3b8" }
  if (score >= 70) return { text: "high risk", color: "#f97316" }
  if (score >= 40) return { text: "moderate", color: "#facc15" }
  if (score > 0) return { text: "low risk", color: "#38bdf8" }
  return { text: "clean", color: "#22c55e" }
}

type PageProps = {
  params: Promise<{ owner: string; repo: string }>
}

export default async function PublicScanOG({ params }: PageProps) {
  const { owner, repo } = await params
  const scan = await fetchLatestScan(owner, repo)
  const findingsTotal =
    (scan?.secrets_count ?? 0) + (scan?.deps_count ?? 0)
  const risk = riskLabel(scan?.risk_score ?? null)

  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          backgroundColor: "#0f172a",
          backgroundImage:
            "radial-gradient(circle at 10% 0%, rgba(251, 191, 36, 0.12), transparent 50%), radial-gradient(circle at 95% 100%, rgba(59, 130, 246, 0.12), transparent 50%)",
          padding: "64px 72px",
          fontFamily: "ui-sans-serif, system-ui, sans-serif",
          color: "#e2e8f0",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 16,
            fontSize: 28,
            fontWeight: 600,
            letterSpacing: "0.04em",
            color: "#fbbf24",
          }}
        >
          <span
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              width: 44,
              height: 44,
              borderRadius: 10,
              background: "#fbbf24",
              color: "#0f172a",
              fontWeight: 800,
              fontSize: 24,
            }}
          >
            R
          </span>
          REPOGUARD
        </div>

        <div
          style={{
            display: "flex",
            flexDirection: "column",
            marginTop: 56,
            flex: 1,
          }}
        >
          <div
            style={{
              fontSize: 28,
              color: "#94a3b8",
              marginBottom: 12,
              display: "flex",
            }}
          >
            {scan ? "Security scan" : "Free GitHub security scan"}
          </div>
          <div
            style={{
              fontSize: 72,
              fontWeight: 700,
              color: "#f8fafc",
              lineHeight: 1.05,
              display: "flex",
              flexWrap: "wrap",
              gap: "0 16px",
            }}
          >
            <span>{owner}</span>
            <span style={{ color: "#475569" }}>/</span>
            <span>{repo}</span>
          </div>
        </div>

        {scan ? (
          <div
            style={{
              display: "flex",
              gap: 24,
              marginTop: 16,
            }}
          >
            <Stat label="Findings" value={String(findingsTotal)} />
            <Stat
              label="Risk"
              value={scan.risk_score !== null ? String(scan.risk_score) : "—"}
              accent={risk.color}
              suffix={risk.text}
            />
            <Stat
              label="Files"
              value={String(scan.files_scanned ?? 0)}
            />
          </div>
        ) : (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              fontSize: 26,
              color: "#cbd5e1",
              marginTop: 16,
            }}
          >
            Secrets · vulns · supply-chain · IaC · IAM — in under 60s
          </div>
        )}
      </div>
    ),
    size,
  )
}

function Stat({
  label,
  value,
  suffix,
  accent,
}: {
  label: string
  value: string
  suffix?: string
  accent?: string
}) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        padding: "20px 28px",
        background: "rgba(15, 23, 42, 0.6)",
        border: "1px solid rgba(148, 163, 184, 0.25)",
        borderRadius: 14,
        minWidth: 160,
      }}
    >
      <span
        style={{
          fontSize: 18,
          color: "#94a3b8",
          textTransform: "uppercase",
          letterSpacing: "0.08em",
          display: "flex",
        }}
      >
        {label}
      </span>
      <span
        style={{
          fontSize: 52,
          fontWeight: 700,
          color: accent ?? "#f8fafc",
          marginTop: 4,
          display: "flex",
        }}
      >
        {value}
      </span>
      {suffix && (
        <span
          style={{
            fontSize: 20,
            color: accent ?? "#cbd5e1",
            marginTop: 2,
            display: "flex",
          }}
        >
          {suffix}
        </span>
      )}
    </div>
  )
}
