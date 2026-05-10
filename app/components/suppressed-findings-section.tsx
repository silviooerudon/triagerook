import type { SuppressedFinding } from "@/lib/suppressions"
import { SuppressedFindingItem } from "./suppressed-finding-item"

type Props = { items: SuppressedFinding[] }

export function SuppressedFindingsSection({ items }: Props) {
  if (items.length === 0) return null
  return (
    <details
      id="suppressed-section"
      className="bg-slate-900 border border-slate-800 rounded-xl p-5 group"
    >
      <summary className="cursor-pointer flex items-center justify-between gap-3 list-none">
        <h2 className="text-xl font-semibold">
          Suppressed{" "}
          <span className="text-slate-500 font-normal">({items.length})</span>
        </h2>
        <span className="text-slate-500 text-sm group-open:hidden">Show</span>
        <span className="text-slate-500 text-sm hidden group-open:inline">Hide</span>
      </summary>
      <p className="text-xs text-slate-500 mt-3 mb-4">
        Findings hidden by your <code className="font-mono">.repoguardignore</code>{" "}
        rules. Listed here for transparency - they don&apos;t affect the risk score.
      </p>
      <div className="space-y-3">
        {items.map((item, i) => (
          <SuppressedFindingItem key={i} item={item} />
        ))}
      </div>
    </details>
  )
}