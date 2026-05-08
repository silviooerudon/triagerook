type RiskGaugeProps = {
  // `score` is the consolidated penalty from scoreRepo (0..100, capped).
  // High penalty = high risk. We display the inverse (healthScore = 100 - penalty)
  // so the gauge reads the same way as Posture/IAM/SupplyChain: 100 = clean.
  // We deliberately do NOT change the underlying contract (DB column, API field)
  // to avoid breaking existing rows or consumers.
  score: number
  size?: number
}

function colorForHealth(health: number): string {
  if (health >= 90) return "#22c55e"
  if (health >= 70) return "#3b82f6"
  if (health >= 50) return "#eab308"
  return "#ef4444"
}

function labelForHealth(health: number): string {
  if (health >= 90) return "Excellent"
  if (health >= 70) return "Good"
  if (health >= 50) return "Needs attention"
  return "Critical"
}

export function RiskGauge({ score, size = 160 }: RiskGaugeProps) {
  const penalty = Math.max(0, Math.min(100, Math.round(score)))
  const health = 100 - penalty

  const stroke = Math.max(8, Math.round(size * 0.08))
  const radius = (size - stroke) / 2
  const cx = size / 2
  const cy = size / 2

  const sweepDeg = 270
  const circumference = 2 * Math.PI * radius
  const arcLength = circumference * (sweepDeg / 360)
  const progress = arcLength * (health / 100)
  const gap = circumference - arcLength

  const rotation = 135

  const color = colorForHealth(health)
  const label = labelForHealth(health)

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
          style={{ transform: `rotate(${rotation}deg)` }}
        >
          <circle
            cx={cx}
            cy={cy}
            r={radius}
            fill="none"
            stroke="#1f2937"
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={`${arcLength} ${gap}`}
          />
          <circle
            cx={cx}
            cy={cy}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={`${progress} ${circumference - progress}`}
            style={{ transition: "stroke-dasharray 300ms ease, stroke 300ms ease" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="font-bold text-white leading-none"
            style={{ fontSize: Math.round(size * 0.32) }}
          >
            {health}
          </span>
          <span
            className="text-gray-500 mt-1"
            style={{ fontSize: Math.round(size * 0.1) }}
          >
            / 100
          </span>
        </div>
      </div>
      <div
        className="mt-2 text-xs uppercase tracking-wider font-semibold"
        style={{ color }}
      >
        {label}
      </div>
    </div>
  )
}

export default RiskGauge
