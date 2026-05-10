type PostureGaugeProps = {
  score: number
  grade: string
  degraded?: boolean
  size?: number
}

function colorForScore(score: number): string {
  if (score >= 90) return "#22c55e"
  if (score >= 75) return "#3b82f6"
  if (score >= 60) return "#eab308"
  if (score >= 40) return "#f97316"
  return "#ef4444"
}

export function PostureGauge({ score, grade, degraded, size = 160 }: PostureGaugeProps) {
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
  const color = colorForScore(clamped)

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
            style={{ fontSize: Math.round(size * 0.4) }}
          >
            {grade}
          </span>
          <span
            className="text-slate-500 mt-1"
            style={{ fontSize: Math.round(size * 0.13) }}
          >
            {clamped} / 100
          </span>
        </div>
      </div>
      <div
        className="mt-2 text-xs uppercase tracking-wider font-semibold"
        style={{ color: degraded ? "#9ca3af" : color }}
      >
        {degraded ? "Partial data" : "Repo posture"}
      </div>
    </div>
  )
}

export default PostureGauge
