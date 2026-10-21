import { useContext, useEffect, useRef } from 'react'
import { KeyboardShortcutContext, type KeyboardShortcut } from './context'

/**
 * Registers shortcuts for the lifetime of the calling component. Handlers are
 * read through a ref, so passing new closures each render does not
 * re-register; changing an id, key string, scope, `enabled` or
 * `allowInInputs` does.
 */
export function useRegisterShortcuts(shortcuts: KeyboardShortcut[]): void {
  const ctx = useContext(KeyboardShortcutContext)
  const register = ctx?.registerShortcut
  const handlersRef = useRef(new Map<string, KeyboardShortcut['handler']>())
  const specsRef = useRef(shortcuts)
  // Runs before the registration effect below (effects run in order), so a
  // fresh registration already sees this render's specs and handlers.
  useEffect(() => {
    specsRef.current = shortcuts
    handlersRef.current = new Map(shortcuts.map(s => [s.id, s.handler]))
  })

  const signature = shortcuts.map(s => `${s.id}:${s.keys}:${s.scope}:${s.enabled}:${s.allowInInputs}`).join('|')

  useEffect(() => {
    if (!register) {
      if (import.meta.env.DEV && specsRef.current.length > 0) {
        console.warn('useRegisterShortcuts called outside KeyboardShortcutProvider; shortcuts will not fire')
      }
      return
    }
    const cleanups = specsRef.current.map(s =>
      register({ ...s, handler: e => handlersRef.current.get(s.id)?.(e) }),
    )
    return () => cleanups.forEach(fn => fn())
  }, [register, signature])
}

/**
 * Suppresses page and side-panel shortcuts while `open` — for a dialog or the
 * command palette covering the page. Global and overlay-scoped shortcuts keep
 * firing.
 */
export function useOverlayOpen(open: boolean): void {
  const openOverlay = useContext(KeyboardShortcutContext)?.openOverlay
  useEffect(() => {
    if (!open || !openOverlay) return
    return openOverlay()
  }, [open, openOverlay])
}

/** Every registered shortcut, deduplicated by id and sorted for display. */
export function useActiveShortcuts(): KeyboardShortcut[] {
  return useContext(KeyboardShortcutContext)?.activeShortcuts ?? []
}

/** Whether key strings should be displayed with macOS symbols. */
export function useIsMacKeyboard(): boolean {
  return useContext(KeyboardShortcutContext)?.mac ?? false
}
