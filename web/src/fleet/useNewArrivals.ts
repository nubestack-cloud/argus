import { useCallback, useLayoutEffect, useRef, useState, type RefObject } from 'react'
import { markFresh } from '../realtime/freshRows'

// "N new — show" (docs/CLUSTER_INSIGHT_SPECS.md CI-U8). When a live refresh
// brings rows the reader has not seen while they are scrolled down the list,
// inserting them would shift every row under the reader's eye. Instead they
// are held back and counted in a bar; "show" lets them in, scrolls to the
// top and marks them fresh. At the top of the list nothing is held — new
// rows simply appear, marked fresh.
//
// Only rows that are new to the SAME query count: a filter, sort or search
// change (a new `scope`) starts over, so the rows a filter brings in are
// never mistaken for arrivals.

/** Ids in `ids` not yet in `known`, in list order. */
export function newIds(ids: readonly string[], known: ReadonlySet<string>): string[] {
  return ids.filter((id) => !known.has(id))
}

/** The reader is "scrolled away" when the list's top edge has left the
 *  viewport — container-agnostic, so it holds whichever element scrolls. */
export function isScrolledPast(el: Element | null): boolean {
  if (!el) return false
  return el.getBoundingClientRect().top < 0
}

export function useNewArrivals<T extends { id: string }>({
  rows,
  scope,
  settled,
  anchorRef,
}: {
  rows: readonly T[]
  /** Identity of the server query; a change starts over. */
  scope: string
  /** False while the rows are a placeholder from the previous scope. */
  settled: boolean
  anchorRef: RefObject<Element | null>
}) {
  const knownRef = useRef<{ scope: string; ids: Set<string> } | null>(null)
  const [held, setHeld] = useState<ReadonlySet<string>>(new Set())
  const idsKey = rows.map((r) => r.id).join(',')

  useLayoutEffect(() => {
    if (!settled) return
    const ids = idsKey ? idsKey.split(',') : []
    const known = knownRef.current
    if (!known || known.scope !== scope) {
      knownRef.current = { scope, ids: new Set(ids) }
      setHeld((h) => (h.size ? new Set() : h))
      return
    }
    const arrived = newIds(ids, known.ids).filter((id) => !held.has(id))
    if (arrived.length === 0) return
    if (isScrolledPast(anchorRef.current)) {
      setHeld((h) => new Set([...h, ...arrived]))
    } else {
      for (const id of arrived) known.ids.add(id)
      markFresh(arrived)
    }
  }, [idsKey, scope, settled, anchorRef, held])

  const showHeld = useCallback(() => {
    const known = knownRef.current
    if (known) for (const id of held) known.ids.add(id)
    markFresh(held)
    setHeld(new Set())
    anchorRef.current?.scrollIntoView?.({ block: 'start' })
  }, [held, anchorRef])

  const visible = held.size ? rows.filter((r) => !held.has(r.id)) : rows
  // A held id the server has since dropped is not "new" any more.
  const heldCount = held.size ? rows.filter((r) => held.has(r.id)).length : 0
  return { visible, heldCount, showHeld }
}
