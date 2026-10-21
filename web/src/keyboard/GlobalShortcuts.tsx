import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Dialog } from '../components/Dialog'
import type { KeyboardShortcut, ShortcutCategory } from './context'
import { formatKeys } from './keys'
import { GO_TO, findPageFilter } from './bindings'
import { useActiveShortcuts, useIsMacKeyboard, useOverlayOpen, useRegisterShortcuts } from './useShortcuts'

// The app-wide bindings (docs/CLUSTER_INSIGHT_SPECS.md CI-S18): "g" then a
// letter to jump to a page, "/" to focus the page's filter, "?" for the list
// of every shortcut active right now. Mounted once inside the signed-in
// layout. None fires while typing in a field (the registry's rule).

const CATEGORY_ORDER: ShortcutCategory[] = ['General', 'Navigation', 'Lists', 'Panel']

export function ShortcutHelp({ shortcuts, mac, onClose }: { shortcuts: KeyboardShortcut[]; mac: boolean; onClose: () => void }) {
  return (
    <Dialog title="Keyboard shortcuts" onClose={onClose}>
      <p className="text-muted">Shortcuts do not fire while you are typing in a field, except the palette.</p>
      {CATEGORY_ORDER.map((cat) => {
        const items = shortcuts.filter((s) => s.category === cat)
        if (items.length === 0) return null
        return (
          <section key={cat} aria-label={cat}>
            <h3 className="shortcut-help-group">{cat}</h3>
            <dl className="shortcut-help-list">
              {items.map((s) => (
                <div key={s.id} className="fleet-counts-row">
                  <dt>
                    <kbd className="shortcut-key">{formatKeys(s.keys, mac)}</kbd>
                  </dt>
                  <dd>{s.description}</dd>
                </div>
              ))}
            </dl>
          </section>
        )
      })}
    </Dialog>
  )
}

// The account menu opens the shortcut list by dispatching this event.
export const OPEN_SHORTCUTS_EVENT = 'argus:open-shortcuts'

export function GlobalShortcuts() {
  const navigate = useNavigate()
  const [helpOpen, setHelpOpen] = useState(false)
  useEffect(() => {
    const onOpen = () => setHelpOpen(true)
    window.addEventListener(OPEN_SHORTCUTS_EVENT, onOpen)
    return () => window.removeEventListener(OPEN_SHORTCUTS_EVENT, onOpen)
  }, [])
  const shortcuts = useActiveShortcuts()
  const mac = useIsMacKeyboard()
  useOverlayOpen(helpOpen)

  useRegisterShortcuts([
    ...GO_TO.map((g) => ({
      id: `go-${g.to}`,
      keys: g.keys,
      scope: 'global' as const,
      category: 'Navigation' as const,
      description: `Go to ${g.label}`,
      handler: () => navigate(g.to),
    })),
    {
      id: 'focus-filter',
      keys: '/',
      scope: 'global',
      category: 'General',
      description: "Focus this page's filter",
      handler: () => findPageFilter()?.focus(),
    },
    {
      id: 'shortcut-help',
      keys: '?',
      scope: 'global',
      category: 'General',
      description: 'Show keyboard shortcuts',
      handler: () => setHelpOpen((o) => !o),
    },
  ])

  return helpOpen ? <ShortcutHelp shortcuts={shortcuts} mac={mac} onClose={() => setHelpOpen(false)} /> : null
}
