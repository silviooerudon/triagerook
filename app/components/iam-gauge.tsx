type IamGaugeProps = {
  score: number
  level: string
  degraded?: boolean
  size?: number
}

// IAM score follows health semantics (100 = lowest risk, 0 = critical risk),
// matching RiskGauge / SupplyChainGauge / PostureGauge. The visible label is
// kept on the same health/quality vocabulary as the others so a user glancing
// at four gauges side-by-side reads them in one direction.
function colorForLevel(level: string): string {
  if (level === "low") return "#22c55e"
  if (level === "medium") return "#eab308"
  if (level === "high") return "#f97316"
  if (level === "critical") return "#ef4444"
  return "#9ca3af"
}

function levelLabel(level: string): string {
  if (level === "low") return "Excellent"
  if (level === "medium") return "Needs attention"
  if (level === "high") return "High risk"
  if (level === "critical") return "Critical"
  return level
}

export function IamGauge({ score, level, degraded, size = 160 }: IamGaugeProps) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)))
  const stroke = Math.max(8, Math.round(size * 0.08))
  const radius = (size - stroke) / 2
  const cx = size / 2
  const cy = size / 2
  const sweepDeg = 270
  const circumference = 2 * Math.PI * radius
  const arcLength = circumference * (sweepDeg / 360)
  const progress = arcLength * (clamped / 100)
  const gap = circumference - arcLength
  const rotation = 135
  const color = colorForLevel(level)

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          viewBox={"0 0 " + size + " " + size}
          style={{ transform: "rotate(" + rotation + "deg)" }}
        >
          <circle
            cx={cx}
            cy={cy}
            r={radius}
            fill="none"
            stroke="#1f2937"
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={arcLength + " " + gap}
          />
          <circle
            cx={cx}
            cy={cy}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={progress + " " + (circumference - progress)}
            style={{ transition: "stroke-dasharray 300ms ease, stroke 300ms ease" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="font-bold text-white leading-none"
            style={{ fontSize: Math.round(size * 0.32) }}
          >
            {clamped}
          </span>
          <span
            className="text-slate-500 mt-1"
            style={{ fontSize: Math.round(size * 0.13) }}
          >
            / 100
          </span>
        </div>
      </div>
      <div
        className="mt-2 text-xs uppercase tracking-wider font-semibold"
        style={{ color: degraded ? "#9ca3af" : color }}
      >
        {degraded ? "Partial data" : levelLabel(level)}
      </div>
    </div>
  )
}

export default IamGauge
