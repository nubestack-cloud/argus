import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { KeyboardShortcutContext, type KeyboardShortcut } from './context'
import { isMacPlatform, resolveKeydown, SCOPE_PRIORITY, SEQUENCE_TIMEOUT_MS, suppressionLevel } from './keys'

interface Registered extends KeyboardShortcut {
  registrationId: number
}

/**
 * The app-wide shortcut registry: one document keydown listener resolving
 * against every registered shortcut (see resolveKeydown for the rules).
 * `mac` overrides platform detection, for tests.
 */
export function KeyboardShortcutProvider({ children, mac }: { children: ReactNode; mac?: boolean }) {
  const isMac = mac ?? isMacPlatform()
  const shortcutsRef = useRef<Map<number, Registered>>(new Map())
  const nextIdRef = useRef(0)
  // Snapshot of registrations for rendering the help list; the keydown
  // listener reads the ref so it never re-subscribes.
  const [registered, setRegistered] = useState<Registered[]>([])
  const pendingRef = useRef<string | null>(null)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const overlayCountRef = useRef(0)

  const registerShortcut = useCallback((shortcut: KeyboardShortcut) => {
    const registrationId = nextIdRef.current++
    shortcutsRef.current.set(registrationId, { ...shortcut, registrationId })
    setRegistered([...shortcutsRef.current.values()])
    return () => {
      shortcutsRef.current.delete(registrationId)
      setRegistered([...shortcutsRef.current.values()])
    }
  }, [])

  const openOverlay = useCallback(() => {
    overlayCountRef.current++
    let closed = false
    return () => {
      if (closed) return
      closed = true
      overlayCountRef.current = Math.max(0, overlayCountRef.current - 1)
    }
  }, [])

  useEffect(() => {
    const clearTimer = () => {
      if (timerRef.current) clearTimeout(timerRef.current)
      timerRef.current = null
    }
    const onKeyDown = (e: KeyboardEvent) => {
      // Registration order is the tie-break within a scope.
      const shortcuts = [...shortcutsRef.current.values()].sort((a, b) => a.registrationId - b.registrationId)
      const { fire, pending } = resolveKeydown(e, shortcuts, {
        pending: pendingRef.current,
        suppression: suppressionLevel(e.target, e.key),
        overlayOpen: overlayCountRef.current > 0,
        mac: isMac,
      })
      clearTimer()
      pendingRef.current = pending
      if (pending) {
        timerRef.current = setTimeout(() => {
          pendingRef.current = null
          timerRef.current = null
        }, SEQUENCE_TIMEOUT_MS)
      }
      if (!fire) return
      e.preventDefault()
      try {
        fire.handler(e)
      } catch (err) {
        // One faulty handler must not take every other shortcut down with it.
        console.error(`keyboard shortcut "${fire.id}" failed:`, err)
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      clearTimer()
    }
  }, [isMac])

  // Includes disabled shortcuts: the help overlay shows what exists, and should
  // not flicker as transient state toggles `enabled`.
  const activeShortcuts = useMemo(() => {
    const byId = new Map<string, KeyboardShortcut>()
    for (const { registrationId: _id, ...s } of registered) {
      const existing = byId.get(s.id)
      if (!existing || SCOPE_PRIORITY[s.scope] > SCOPE_PRIORITY[existing.scope]) byId.set(s.id, s)
    }
    return [...byId.values()].sort((a, b) =>
      a.category !== b.category ? a.category.localeCompare(b.category) : a.keys.localeCompare(b.keys),
    )
  }, [registered])

  const value = useMemo(
    () => ({ registerShortcut, activeShortcuts, openOverlay, mac: isMac }),
    [registerShortcut, activeShortcuts, openOverlay, isMac],
  )

  return <KeyboardShortcutContext.Provider value={value}>{children}</KeyboardShortcutContext.Provider>
}
