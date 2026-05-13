type ViewToggleButtonProps = {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}

export function ViewToggleButton({
  active,
  onClick,
  children,
}: ViewToggleButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`text-xs px-3 py-1.5 rounded-full border transition ${
        active
          ? "bg-amber-400/15 border-amber-400/30 text-amber-300"
          : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200"
      }`}
    >
      {children}
    </button>
  )
}
