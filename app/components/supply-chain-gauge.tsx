type SupplyChainGaugeProps = {
  score: number
  level: string
  size?: number
}

function colorForLevel(level: string): string {
  if (level === "excellent") return "#22c55e"
  if (level === "good") return "#3b82f6"
  if (level === "needs-attention") return "#eab308"
  if (level === "critical") return "#ef4444"
  return "#9ca3af"
}

function levelLabel(level: string): string {
  if (level === "excellent") return "EXCELLENT"
  if (level === "good") return "GOOD"
  if (level === "needs-attention") return "NEEDS ATTENTION"
  if (level === "critical") return "CRITICAL"
  return level.toUpperCase()
}

export function SupplyChainGauge({ score, level, size = 160 }: SupplyChainGaugeProps) {
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
            className="text-gray-500 mt-1"
            style={{ fontSize: Math.round(size * 0.13) }}
          >
            / 100
          </span>
        </div>
      </div>
      <div
        className="mt-2 text-xs uppercase tracking-wider font-semibold"
        style={{ color }}
      >
        {levelLabel(level)}
      </div>
    </div>
  )
}

export default SupplyChainGauge
