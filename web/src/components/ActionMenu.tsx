import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { ChevronIcon, MoreIcon } from './icons'

// Replaces a growing row of always-visible action buttons (Accept/
// Decommission/Rename/Quick view on ClustersPage, Reset password/Disable
// on UsersPage) with a single "⋮" trigger and a dropdown list — direct,
// explicit user feedback (bugs-and-fixes.txt item 24: "we cannot keep
// placing buttons like this, it creates clutter"). Deliberately takes a
// plain `items` array rather than arbitrary children: an item is just a
// label + callback, never a component with its own hidden state, because
// this menu's contents unmount the moment it closes (see below) — any
// confirm/result modal an action needs must be owned by the row/page that
// renders this menu, not by something living inside it.
export interface ActionMenuItem {
  label: string
  onClick: () => void
  disabled?: boolean
  disabledReason?: string
  danger?: boolean
}

// Rendered via a portal to document.body, positioned with `fixed`
// coordinates computed from the trigger's own bounding rect — never a
// plain CSS-relative dropdown nested inside the table. Every table this
// app has lives inside a `.table-scroll` div with `overflow-x: auto`
// (index.css), and a menu positioned relative to a cell inside that
// container would get clipped exactly the way this app's own tooltip bugs
// already did once (bugs-and-fixes.txt items 2/19) — a portal sidesteps
// that clipping context entirely, the same reasoning HelpTip's own fix
// eventually adopted.
// `label` turns the "⋮" trigger into a named button — "Close out ▾". A table row
// has a column header and a row of context telling you what a bare glyph acts
// on; a page-level header has neither, and an unlabelled ⋮ beside "Analyze
// incident" gives no clue that resolve/dismiss/tolerate are behind it. The
// grouping argument is the same one that made this component exist (three
// buttons of equal weight read as three equal options); only the trigger's
// discoverability differs, so it is a prop rather than a second component.
export function ActionMenu({
  ariaLabel,
  label,
  items,
}: {
  ariaLabel: string
  label?: string
  items: ActionMenuItem[]
}) {
  const [open, setOpen] = useState(false)
  const [coords, setCoords] = useState<{ top: number; right: number } | null>(null)
  const triggerRef = useRef<HTMLButtonElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return

    function updatePosition() {
      const rect = triggerRef.current?.getBoundingClientRect()
      if (!rect) return
      // Right-aligned to the trigger (menus opening from a rightmost
      // "Actions" column would otherwise overflow the viewport if
      // left-aligned) and just below it, with a small gap.
      setCoords({ top: rect.bottom + 4, right: window.innerWidth - rect.right })
    }
    updatePosition()

    function onPointerDown(e: MouseEvent) {
      const target = e.target as Node
      if (triggerRef.current?.contains(target) || menuRef.current?.contains(target)) return
      setOpen(false)
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false)
    }
    // Closing on scroll/resize rather than re-tracking every frame — a menu
    // that follows the trigger while a table scrolls under it is more
    // complexity than a "click again to reopen where you are now" menu is
    // worth for this app's own scale (a handful of rows, not a virtualized
    // thousand-row grid).
    function onDismiss() {
      setOpen(false)
    }

    window.addEventListener('resize', onDismiss)
    window.addEventListener('scroll', onDismiss, true)
    document.addEventListener('mousedown', onPointerDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      window.removeEventListener('resize', onDismiss)
      window.removeEventListener('scroll', onDismiss, true)
      document.removeEventListener('mousedown', onPointerDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open])

  return (
    <div className="action-menu">
      <button
        type="button"
        ref={triggerRef}
        className={label ? 'secondary action-menu-trigger' : 'icon-button'}
        // aria-label only on the icon-only trigger: on the labelled one the
        // visible text is already the accessible name, and overriding it with a
        // different string is the mismatch that breaks voice control ("click
        // Close out" would find nothing).
        aria-label={label ? undefined : ariaLabel}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        {label ? (
          <>
            {label}
            <ChevronIcon size={12} direction="down" />
          </>
        ) : (
          <MoreIcon />
        )}
      </button>
      {open &&
        coords &&
        createPortal(
          <div
            ref={menuRef}
            className="action-menu-popover"
            role="menu"
            aria-label={ariaLabel}
            style={{ top: coords.top, right: coords.right }}
          >
            {items.map((item) => (
              <button
                key={item.label}
                type="button"
                role="menuitem"
                className={item.danger ? 'action-menu-item-danger' : undefined}
                disabled={item.disabled}
                title={item.disabledReason}
                onClick={() => {
                  setOpen(false)
                  item.onClick()
                }}
              >
                {item.label}
              </button>
            ))}
          </div>,
          document.body,
        )}
    </div>
  )
}
