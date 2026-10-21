import { useCallback, useEffect, useId, useLayoutEffect, useRef, useState, type ReactNode } from 'react'
import { ChevronIcon } from './icons'

export interface TabDef {
  id: string
  label: ReactNode
  // A tab the viewer cannot use stays visible and says why (disabled, not
  // hidden — argus-design-system's access rules).
  disabledReason?: string
  /** Starts a new group: a thin rule is drawn before this tab. */
  groupStart?: boolean
}

// Tabs is a WAI-ARIA tablist with roving focus (arrow keys, Home/End).
// The caller owns the active id — normally a `?tab=` URL parameter — and
// renders only the active panel, so a tab's query runs the first time it
// is shown rather than on mount.
//
// Every tab stays on one row. When the row is wider than its container it
// scrolls sideways, with a ‹ / › button at whichever end has more tabs, and
// the active tab is scrolled into view. This replaced a "More" menu (owner,
// 2026-10-11): a menu hid the less-used tabs behind a click and made people
// think a tab had gone. Order the tabs by importance instead (the object
// panel's order is insight/model.ts tabsFor) so the ones that scroll out of
// sight are the least needed, not the hidden ones.
export function Tabs({
  tabs,
  active,
  onChange,
  label,
  aside,
  children,
}: {
  tabs: TabDef[]
  active: string
  onChange: (id: string) => void
  label: string
  /** Shown at the right end of the tab row, outside the tablist — a page's
   *  "as of" stamp, say, so it costs no row of its own. */
  aside?: ReactNode
  children: ReactNode
}) {
  const base = useId()
  const refs = useRef<Record<string, HTMLButtonElement | null>>({})
  const listRef = useRef<HTMLDivElement>(null)
  const [edges, setEdges] = useState({ left: false, right: false })
  const enabled = tabs.filter((t) => !t.disabledReason)

  // Roving focus follows the active tab. Focus is moved now AND again after
  // the caller's re-render: the caller usually stores the active id in the
  // URL, and that update re-renders everything above this row — the focus
  // must still be on the newly active tab when it settles.
  const pendingFocus = useRef<string | null>(null)
  const activate = (id: string) => {
    pendingFocus.current = id
    onChange(id)
    refs.current[id]?.focus()
  }
  const move = (from: string, delta: number) => {
    if (enabled.length === 0) return
    const i = enabled.findIndex((t) => t.id === from)
    const next = enabled[(i + delta + enabled.length) % enabled.length]
    activate(next.id)
  }
  useEffect(() => {
    if (pendingFocus.current && pendingFocus.current === active) {
      const el = refs.current[active]
      if (el && document.activeElement !== el) el.focus()
      pendingFocus.current = null
    }
  })

  // Which ends have tabs scrolled out of view. A 1px tolerance absorbs
  // sub-pixel widths, which otherwise leave a › showing at the very end.
  const measure = useCallback(() => {
    const el = listRef.current
    if (!el) return
    const left = el.scrollLeft > 1
    const right = el.scrollLeft + el.clientWidth < el.scrollWidth - 1
    setEdges((prev) => (prev.left === left && prev.right === right ? prev : { left, right }))
  }, [])

  useLayoutEffect(() => {
    measure()
  }, [measure, tabs.length])

  useEffect(() => {
    const el = listRef.current
    if (!el) return
    el.addEventListener('scroll', measure, { passive: true })
    const ro = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(measure)
    ro?.observe(el)
    return () => {
      el.removeEventListener('scroll', measure)
      ro?.disconnect()
    }
  }, [measure])

  // Keep the active tab visible, including one chosen from the URL.
  useEffect(() => {
    refs.current[active]?.scrollIntoView?.({ block: 'nearest', inline: 'nearest' })
  }, [active])

  const scrollBy = (direction: 1 | -1) => {
    const el = listRef.current
    if (!el) return
    el.scrollBy({ left: direction * Math.max(120, el.clientWidth * 0.7), behavior: 'smooth' })
  }

  return (
    <div>
      <div className="tabs-bar">
        {/* Pointer conveniences, out of the tab order: a keyboard user moves
            through every tab with the arrow keys, which also scrolls. */}
        {edges.left && (
          <button type="button" className="tabs-scroll tabs-scroll-left" tabIndex={-1} aria-label="Scroll tabs left" onClick={() => scrollBy(-1)}>
            <ChevronIcon size={14} direction="left" />
          </button>
        )}
        <div className="tabs" role="tablist" aria-label={label} ref={listRef}>
          {tabs.map((t) => (
            <button
              key={t.id}
              ref={(el) => {
                refs.current[t.id] = el
              }}
              type="button"
              role="tab"
              id={`${base}-tab-${t.id}`}
              aria-selected={t.id === active}
              aria-controls={`${base}-panel`}
              tabIndex={t.id === active ? 0 : -1}
              className={t.groupStart ? 'tabs-tab tabs-tab-group' : 'tabs-tab'}
              disabled={Boolean(t.disabledReason)}
              title={t.disabledReason}
              onClick={() => onChange(t.id)}
              onKeyDown={(e) => {
                if (e.key === 'ArrowRight') move(t.id, 1)
                else if (e.key === 'ArrowLeft') move(t.id, -1)
                else if (e.key === 'Home' && enabled[0]) activate(enabled[0].id)
                else if (e.key === 'End' && enabled.length) activate(enabled[enabled.length - 1].id)
                else return
                e.preventDefault()
              }}
            >
              {t.label}
            </button>
          ))}
        </div>
        {edges.right && (
          <button type="button" className="tabs-scroll tabs-scroll-right" tabIndex={-1} aria-label="Scroll tabs right" onClick={() => scrollBy(1)}>
            <ChevronIcon size={14} direction="right" />
          </button>
        )}
        {aside && <div className="tabs-aside">{aside}</div>}
      </div>
      <div role="tabpanel" id={`${base}-panel`} aria-labelledby={`${base}-tab-${active}`}>
        {children}
      </div>
    </div>
  )
}
