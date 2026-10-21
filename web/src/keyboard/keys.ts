// Key-string parsing and keydown resolution for the shortcut registry. Pure —
// no DOM listener, no React — so every matching rule is pinned by tests and the
// provider only owns timers and handler calls.
//
// Key strings:
//   "k", "?", "/", "Escape"  one key
//   "Mod+k"                  Cmd on macOS, Ctrl elsewhere
//   "Ctrl+k", "Meta+k", "Alt+x", "Shift+N"  literal modifiers
//   "g i"                    two-key sequence (second key within 500 ms)

/** Where a shortcut was registered. Higher priority wins when two match. */
export type ShortcutScope = 'global' | 'page' | 'panel' | 'overlay'

export const SCOPE_PRIORITY: Record<ShortcutScope, number> = {
  global: 0,
  page: 1,
  panel: 2,
  overlay: 3,
}

/** Scopes that keep firing while an overlay (dialog, palette) is open: the
 *  overlay's own keys and app-wide ones such as Mod+k. Page and side-panel
 *  keys belong to what the overlay covers and are suppressed. */
const SCOPES_ACTIVE_UNDER_OVERLAY: ReadonlySet<ShortcutScope> = new Set(['global', 'overlay'])

export const SEQUENCE_TIMEOUT_MS = 500

export interface KeyMatcher {
  /** One key, or two for a sequence such as ["g", "i"]. */
  sequence: string[]
  ctrlKey?: boolean
  metaKey?: boolean
  shiftKey?: boolean
  altKey?: boolean
}

/** The KeyboardEvent fields matching reads. */
export interface KeyEventLike {
  key: string
  ctrlKey: boolean
  metaKey: boolean
  shiftKey: boolean
  altKey: boolean
}

/** The shortcut fields resolution reads. */
export interface ShortcutSpec {
  id: string
  keys: string
  scope: ShortcutScope
  enabled?: boolean
  /** Fire even when focus is in a text input. Only for modifier chords such as
   *  Mod+k that cannot collide with typing. */
  allowInInputs?: boolean
}

export function isMacPlatform(nav: { platform?: string; userAgent?: string } | undefined = globalThis.navigator): boolean {
  if (!nav) return false
  return /Mac|iPhone|iPad|iPod/.test(nav.platform || nav.userAgent || '')
}

export function parseKeys(keys: string, mac: boolean): KeyMatcher {
  if (keys.includes(' ') && !keys.includes('+')) {
    return { sequence: keys.split(' ').filter(Boolean) }
  }
  const matcher: KeyMatcher = { sequence: [] }
  for (const part of keys.split('+')) {
    const lower = part.trim().toLowerCase()
    if (lower === 'mod') {
      if (mac) matcher.metaKey = true
      else matcher.ctrlKey = true
    } else if (lower === 'meta' || lower === 'cmd') matcher.metaKey = true
    else if (lower === 'ctrl') matcher.ctrlKey = true
    else if (lower === 'shift') matcher.shiftKey = true
    else if (lower === 'alt') matcher.altKey = true
    else matcher.sequence = [part.trim()]
  }
  return matcher
}

/**
 * Whether `e` completes `matcher`. For a two-key sequence `firstKey` is the key
 * pressed before this one. A single key must match exactly in its modifiers:
 * "k" does not fire on Ctrl+k, and a plain lowercase letter does not fire with
 * Shift held — but Shift-produced symbols ("?", "+") do.
 */
const EXACT_MODIFIERS = ['metaKey', 'ctrlKey', 'altKey'] as const

export function matchesKey(e: KeyEventLike, matcher: KeyMatcher, firstKey: string | null): boolean {
  if (matcher.sequence.length === 2) {
    return firstKey === matcher.sequence[0] && e.key === matcher.sequence[1]
  }
  if (matcher.sequence.length !== 1) return false
  const key = matcher.sequence[0]
  if (e.key !== key && e.key.toLowerCase() !== key.toLowerCase()) return false
  // An uppercase letter ("N") needs Shift.
  if (key.length === 1 && key === key.toUpperCase() && key !== key.toLowerCase() && !e.shiftKey) return false
  // Meta, Ctrl and Alt must be exactly as the binding says, held or not;
  // Shift only has to be held when the binding names it (symbols need it).
  for (const mod of EXACT_MODIFIERS) {
    if (Boolean(matcher[mod]) !== e[mod]) return false
  }
  if (matcher.shiftKey && !e.shiftKey) return false
  if (matcher.shiftKey === undefined && e.shiftKey && key.length === 1 && key >= 'a' && key <= 'z') return false
  return true
}

/**
 * How much the focused element suppresses shortcuts:
 *   none — nothing focused that owns typing; every shortcut may fire
 *   soft — a text input, textarea, select or contenteditable; only
 *          `allowInInputs` shortcuts (and Escape) fire
 *   hard — an element marked `data-keyboard-owner` that runs its own key
 *          handling; only Escape fires
 */
export type SuppressionLevel = 'none' | 'soft' | 'hard'

export function suppressionLevel(target: EventTarget | null, key: string): SuppressionLevel {
  if (key === 'Escape') return 'none'
  if (!target || typeof (target as Element).closest !== 'function') return 'none'
  const el = target as HTMLElement
  if (el.closest('[data-keyboard-owner]')) return 'hard'
  const tag = el.tagName
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return 'soft'
  if (el.isContentEditable) return 'soft'
  return 'none'
}

/** Enabled shortcuts eligible right now, highest scope priority first. The sort
 *  is stable, so within a scope the earliest registration wins. */
export function eligibleShortcuts<S extends ShortcutSpec>(shortcuts: readonly S[], overlayOpen: boolean): S[] {
  return shortcuts
    .filter(s => s.enabled !== false)
    .filter(s => !overlayOpen || SCOPES_ACTIVE_UNDER_OVERLAY.has(s.scope))
    .sort((a, b) => SCOPE_PRIORITY[b.scope] - SCOPE_PRIORITY[a.scope])
}

export interface KeydownContext {
  /** First key of a sequence pressed within the timeout, if any. */
  pending: string | null
  suppression: SuppressionLevel
  overlayOpen: boolean
  mac: boolean
}

export interface KeydownResolution<S> {
  /** The shortcut to fire, or null. */
  fire: S | null
  /** The sequence first key to remember for the next keydown, or null. */
  pending: string | null
}

/**
 * Decides what one keydown does. A pending first key is consumed by this
 * keydown whether or not a sequence completes; an unmatched second key is then
 * judged as a single key in its own right. A key that starts any registered
 * sequence is held as pending instead of firing a lower-priority single key.
 */
export function resolveKeydown<S extends ShortcutSpec>(
  e: KeyEventLike,
  shortcuts: readonly S[],
  ctx: KeydownContext,
): KeydownResolution<S> {
  const active = eligibleShortcuts(shortcuts, ctx.overlayOpen)
  const suppressed = ctx.suppression !== 'none'

  if (ctx.pending && !suppressed) {
    for (const s of active) {
      const m = parseKeys(s.keys, ctx.mac)
      if (m.sequence.length === 2 && matchesKey(e, m, ctx.pending)) return { fire: s, pending: null }
    }
  }

  for (const s of active) {
    const m = parseKeys(s.keys, ctx.mac)
    if (m.sequence.length === 2) {
      if (!suppressed && e.key === m.sequence[0] && !e.metaKey && !e.ctrlKey && !e.altKey) {
        return { fire: null, pending: e.key }
      }
      continue
    }
    if (e.key === 'Escape' && s.keys === 'Escape') return { fire: s, pending: null }
    if (suppressed && !(s.allowInInputs && ctx.suppression === 'soft')) continue
    if (matchesKey(e, m, null)) return { fire: s, pending: null }
  }
  return { fire: null, pending: null }
}

const KEY_NAMES: Record<string, string> = {
  escape: 'Esc',
  arrowup: '↑',
  arrowdown: '↓',
  arrowleft: '←',
  arrowright: '→',
  enter: 'Enter',
}

/**
 * Display text for a key string, as the platform names it: "Mod+k" is "⌘K" on
 * macOS and "Ctrl+K" elsewhere; "g i" reads "g then i".
 */
export function formatKeys(keys: string, mac: boolean): string {
  const m = parseKeys(keys, mac)
  if (m.sequence.length === 2) return `${m.sequence[0]} then ${m.sequence[1]}`
  const key = m.sequence[0] ?? ''
  const shown = KEY_NAMES[key.toLowerCase()] ?? (key.length === 1 && (m.ctrlKey || m.metaKey || m.altKey) ? key.toUpperCase() : key)
  if (mac) {
    return `${m.ctrlKey ? '⌃' : ''}${m.altKey ? '⌥' : ''}${m.shiftKey ? '⇧' : ''}${m.metaKey ? '⌘' : ''}${shown}`
  }
  const parts: string[] = []
  if (m.ctrlKey) parts.push('Ctrl')
  if (m.altKey) parts.push('Alt')
  if (m.shiftKey) parts.push('Shift')
  if (m.metaKey) parts.push('Meta')
  parts.push(shown)
  return parts.join('+')
}
