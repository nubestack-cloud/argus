import { useEffect, useId, useRef, useState, type ReactNode } from 'react'

const WIDTH_KEY = 'argus.sidePanelWidth'
const MIN_WIDTH = 420
const DEFAULT_WIDTH = 720

function readWidth(): number {
  try {
    const v = Number(window.localStorage.getItem(WIDTH_KEY))
    return Number.isFinite(v) && v >= MIN_WIDTH ? v : DEFAULT_WIDTH
  } catch {
    return DEFAULT_WIDTH
  }
}

// SidePanel is the right-anchored inspector (docs/CLUSTER_INSIGHT_SPECS.md
// CI-F3): it opens over a list or page without navigating away, so the
// opener keeps its scroll position, filters and selection (CI-U7). The
// caller owns open state — normally a `?panel=` URL parameter — so a link
// or refresh reproduces it. Esc closes; focus moves into the panel on open
// and back to whatever had it on close. The width is a per-viewer
// convenience kept in localStorage; storage being unavailable is harmless.
export function SidePanel({
  title,
  subtitle,
  onClose,
  actions,
  children,
}: {
  title: ReactNode
  subtitle?: ReactNode
  onClose: () => void
  actions?: ReactNode
  children: ReactNode
}) {
  const titleId = useId()
  const panelRef = useRef<HTMLElement>(null)
  const [width, setWidth] = useState(readWidth)

  // The latest onClose, read at the moment Esc is pressed. The focus effect
  // below must run once per opening, not once per onClose identity: callers
  // build onClose from the URL setter, which changes on every URL update —
  // so switching a tab (?ptab=) used to re-run the effect, hand focus back to
  // the opener and then to the panel, and the keyboard user lost their place
  // on the tab row.
  const onCloseRef = useRef(onClose)
  useEffect(() => {
    onCloseRef.current = onClose
  }, [onClose])

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null
    panelRef.current?.focus()
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation()
        onCloseRef.current()
      }
    }
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('keydown', onKey)
      previous?.focus?.()
    }
  }, [])

  const startResize = (e: React.PointerEvent) => {
    e.preventDefault()
    const onMove = (ev: PointerEvent) => {
      const next = Math.max(MIN_WIDTH, Math.min(window.innerWidth - 40, window.innerWidth - ev.clientX))
      setWidth(next)
    }
    const onUp = () => {
      window.removeEventListener('pointermove', onMove)
      window.removeEventListener('pointerup', onUp)
      setWidth((w) => {
        try {
          window.localStorage.setItem(WIDTH_KEY, String(Math.round(w)))
        } catch {
          // per-viewer convenience only
        }
        return w
      })
    }
    window.addEventListener('pointermove', onMove)
    window.addEventListener('pointerup', onUp)
  }

  const nudge = (delta: number) => {
    setWidth((w) => {
      const next = Math.max(MIN_WIDTH, Math.min(window.innerWidth - 40, w + delta))
      try {
        window.localStorage.setItem(WIDTH_KEY, String(Math.round(next)))
      } catch {
        // per-viewer convenience only
      }
      return next
    })
  }

  return (
    <>
      <div className="side-panel-backdrop" onClick={onClose} aria-hidden="true" />
      <aside
        ref={panelRef}
        className="side-panel"
        role="dialog"
        aria-modal="false"
        aria-labelledby={titleId}
        tabIndex={-1}
        style={{ ['--side-panel-width' as string]: `${width}px` }}
      >
        <button
          type="button"
          className="side-panel-resize"
          aria-label="Resize panel (left and right arrow keys)"
          onPointerDown={startResize}
          onKeyDown={(e) => {
            if (e.key === 'ArrowLeft') nudge(40)
            if (e.key === 'ArrowRight') nudge(-40)
          }}
        />
        <header className="side-panel-header">
          <h2 className="side-panel-title" id={titleId}>
            {title}
            {subtitle && <span className="side-panel-subtitle">{subtitle}</span>}
          </h2>
          {actions}
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close panel">
            ×
          </button>
        </header>
        <div className="side-panel-body">{children}</div>
      </aside>
    </>
  )
}
