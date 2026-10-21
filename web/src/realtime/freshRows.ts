import { useSyncExternalStore } from 'react'

// Which list rows changed in the last FRESH_MS (docs/CLUSTER_INSIGHT_SPECS.md
// CI-U8). A row that a live event just patched, or that arrived and was
// shown, gets `.row-fresh` for two seconds so the eye finds what moved; the
// CSS drops the animation under prefers-reduced-motion. Module state, not
// React state: the live-event handler that marks a row runs outside any
// component.

export const FRESH_MS = 2000

const expiry = new Map<string, number>()
const listeners = new Set<() => void>()
let snapshot: ReadonlySet<string> = new Set()

function publish() {
  snapshot = new Set(expiry.keys())
  for (const l of listeners) l()
}

/** Marks rows as just changed; each clears itself FRESH_MS later. */
export function markFresh(ids: Iterable<string>, now: number = Date.now()): void {
  let changed = false
  for (const id of ids) {
    expiry.set(id, now + FRESH_MS)
    changed = true
    setTimeout(() => {
      const at = expiry.get(id)
      if (at !== undefined && at <= Date.now()) {
        expiry.delete(id)
        publish()
      }
    }, FRESH_MS + 20)
  }
  if (changed) publish()
}

/** Test hook: forget every mark. */
export function clearFresh(): void {
  expiry.clear()
  publish()
}

function subscribe(l: () => void) {
  listeners.add(l)
  return () => listeners.delete(l)
}

/** The ids currently fresh; re-renders when the set changes. */
export function useFreshIds(): ReadonlySet<string> {
  return useSyncExternalStore(subscribe, () => snapshot, () => snapshot)
}
