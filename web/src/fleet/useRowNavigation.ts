import { useCallback, useId, useState, type KeyboardEvent as ReactKeyboardEvent, type MouseEvent as ReactMouseEvent } from 'react'
import { useRegisterShortcuts } from '../keyboard/useShortcuts'

// Keyboard row navigation for a `.list-table` (docs/CLUSTER_INSIGHT_SPECS.md
// CI-U6). j/k are page-scoped shortcuts in the app registry, so they never
// fire while typing in a filter and the "?" overlay lists them. The active
// row takes real DOM focus (tabIndex -1, roving), which is what draws the
// :focus-visible ring and makes a screen reader announce the row — no
// aria-activedescendant bookkeeping needed. Arrow keys and Enter are handled
// on the focused row itself: registering Enter globally would swallow it on
// every button and link on the page.

/** The index one step from `current`, clamped to the list. -1 (nothing
 *  active yet) steps to the first row in either direction. */
export function stepIndex(current: number, delta: 1 | -1, count: number): number {
  if (count <= 0) return -1
  if (current < 0) return 0
  return Math.min(count - 1, Math.max(0, current + delta))
}

/** True when a click landed on something that acts on its own (a link, a
 *  button, a checkbox, a disclosure) — a row click must not also fire then. */
export function isInteractiveClick(target: EventTarget | null): boolean {
  return !!(target as HTMLElement | null)?.closest?.('a, button, input, select, textarea, summary, label, [role="menu"], [role="menuitem"]')
}

export function useRowNavigation({
  count,
  onOpen,
  enabled = true,
  clickToOpen = false,
}: {
  count: number
  onOpen: (index: number) => void
  enabled?: boolean
  /** A click anywhere on the row that is not a control opens it, as Enter
   *  does. Opt-in so a page whose rows already carry their own click
   *  behaviour keeps it. */
  clickToOpen?: boolean
}) {
  const [active, setActive] = useState(-1)
  // The rows' container is found by id rather than a ref: rowProps is
  // called during render, and nothing here may read a ref then.
  const containerId = useId()
  const current = active >= count ? count - 1 : active

  const focusRow = useCallback((index: number) => {
    setActive(index)
    const el = document.getElementById(containerId)?.querySelector<HTMLElement>(`[data-row-index="${index}"]`)
    el?.focus()
    el?.scrollIntoView?.({ block: 'nearest' })
  }, [containerId])

  const move = useCallback(
    (delta: 1 | -1) => {
      const next = stepIndex(current, delta, count)
      if (next >= 0) focusRow(next)
    },
    [current, count, focusRow],
  )

  useRegisterShortcuts([
    { id: 'list-next', keys: 'j', scope: 'page', category: 'Lists', description: 'Next row', enabled: enabled && count > 0, handler: () => move(1) },
    { id: 'list-prev', keys: 'k', scope: 'page', category: 'Lists', description: 'Previous row', enabled: enabled && count > 0, handler: () => move(-1) },
    // Listed for the help overlay; handled on the focused row (see above).
    { id: 'list-open', keys: 'Enter', scope: 'page', category: 'Lists', description: 'Open the focused row', enabled: false, handler: () => {} },
  ])

  const rowProps = (index: number) => ({
    'data-row-index': index,
    tabIndex: index === current || (current < 0 && index === 0) ? 0 : -1,
    onFocus: (e: { target: EventTarget; currentTarget: EventTarget }) => {
      if (e.target === e.currentTarget) setActive(index)
    },
    onKeyDown: (e: ReactKeyboardEvent<HTMLElement>) => {
      if (e.target !== e.currentTarget) return
      if (e.key === 'Enter') {
        e.preventDefault()
        onOpen(index)
      } else if (e.key === 'ArrowDown') {
        e.preventDefault()
        focusRow(stepIndex(index, 1, count))
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        focusRow(stepIndex(index, -1, count))
      }
    },
    'aria-current': index === current ? ('true' as const) : undefined,
    // Only present when asked for, so spreading rowProps never overrides a
    // row's own onClick with undefined.
    ...(clickToOpen
      ? {
          onClick: (e: ReactMouseEvent<HTMLElement>) => {
            if (isInteractiveClick(e.target)) return
            // Selecting text in a row is not a request to open it.
            if (window.getSelection?.()?.toString()) return
            setActive(index)
            onOpen(index)
          },
        }
      : {}),
  })

  /** Spread onto the element holding the rows (a tbody, or a wrapper). */
  const containerProps = { id: containerId }
  return { activeIndex: current, containerProps, rowProps, setActive }
}
