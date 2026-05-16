"use client"

import { useEffect, useRef } from "react"

// Focus-trap + auto-focus hook for modal dialogs. While the modal is
// open, Tab cycles within the modal's focusable descendants and
// Shift+Tab cycles backwards. The first focusable element receives
// focus on open. When the modal closes, focus is returned to the
// element that triggered the open so keyboard users land back where
// they were.
//
// Pairs with `role="dialog"` + `aria-modal="true"` on the dialog
// container. The Esc handler is intentionally NOT part of this hook —
// each caller wires its own close handler so the modal can clean up
// internal state (form drafts, error toasts) at the same time.
export function useModalFocus(open: boolean) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const returnFocusRef = useRef<HTMLElement | null>(null)

  useEffect(() => {
    if (!open) return
    returnFocusRef.current = document.activeElement as HTMLElement | null

    const container = containerRef.current
    if (!container) return

    const focusables = getFocusables(container)
    if (focusables.length > 0) {
      focusables[0].focus()
    }

    function handler(e: KeyboardEvent) {
      if (e.key !== "Tab" || !container) return
      const items = getFocusables(container)
      if (items.length === 0) {
        e.preventDefault()
        return
      }
      const first = items[0]
      const last = items[items.length - 1]
      const active = document.activeElement as HTMLElement | null

      if (e.shiftKey) {
        if (active === first || !container.contains(active)) {
          e.preventDefault()
          last.focus()
        }
      } else {
        if (active === last) {
          e.preventDefault()
          first.focus()
        }
      }
    }

    document.addEventListener("keydown", handler)
    return () => {
      document.removeEventListener("keydown", handler)
      // Return focus to the trigger element when the modal closes,
      // but only if the trigger still exists in the DOM and the user
      // hasn't already moved focus elsewhere intentionally.
      const ret = returnFocusRef.current
      if (ret && document.contains(ret)) {
        ret.focus()
      }
    }
  }, [open])

  return containerRef
}

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'

function getFocusables(container: HTMLElement): HTMLElement[] {
  return Array.from(
    container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
  ).filter((el) => !el.hasAttribute("hidden") && el.offsetParent !== null)
}
