"use client"

import { Analytics, type BeforeSendEvent } from "@vercel/analytics/next"

// Vercel Web Analytics is already cookieless. This wrapper goes further:
//   - honours Global Privacy Control and Do Not Track by sending nothing;
//   - strips query strings and fragments, so values like ?next=… or
//     ?error=… never reach the analytics provider.
// The Privacy Policy (/privacy#cookies) promises both — keep them in sync.
function userOptedOut(): boolean {
  if (typeof navigator === "undefined") return false
  const nav = navigator as Navigator & { globalPrivacyControl?: boolean }
  return nav.globalPrivacyControl === true || nav.doNotTrack === "1"
}

function beforeSend(event: BeforeSendEvent): BeforeSendEvent | null {
  if (userOptedOut()) return null
  try {
    const url = new URL(event.url)
    url.search = ""
    url.hash = ""
    return { ...event, url: url.toString() }
  } catch {
    return null
  }
}

export function PrivacyAnalytics() {
  return <Analytics beforeSend={beforeSend} />
}
