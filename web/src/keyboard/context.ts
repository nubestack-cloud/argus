import { createContext } from 'react'
import type { ShortcutSpec } from './keys'

export type ShortcutCategory = 'General' | 'Navigation' | 'Lists' | 'Panel'

export interface KeyboardShortcut extends ShortcutSpec {
  /** Human-readable description for the help overlay. */
  description: string
  /** Help-overlay grouping. */
  category: ShortcutCategory
  handler: (e: KeyboardEvent) => void
}

export interface KeyboardShortcutContextValue {
  registerShortcut: (shortcut: KeyboardShortcut) => () => void
  /** Every registered shortcut, deduplicated by id, for the help overlay. */
  activeShortcuts: KeyboardShortcut[]
  /** Marks one overlay open; the returned function marks it closed. Counted,
   *  so a dialog opened over the palette does not re-enable page keys when
   *  it closes first. */
  openOverlay: () => () => void
  mac: boolean
}

export const KeyboardShortcutContext = createContext<KeyboardShortcutContextValue | null>(null)
