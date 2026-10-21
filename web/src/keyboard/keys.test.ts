import { describe, expect, it } from 'vitest'
import {
  eligibleShortcuts,
  formatKeys,
  isMacPlatform,
  matchesKey,
  parseKeys,
  resolveKeydown,
  suppressionLevel,
  type KeyEventLike,
  type KeydownContext,
  type ShortcutSpec,
} from './keys'

const key = (k: string, mods: Partial<KeyEventLike> = {}): KeyEventLike => ({
  key: k,
  ctrlKey: false,
  metaKey: false,
  shiftKey: false,
  altKey: false,
  ...mods,
})

const ctx = (o: Partial<KeydownContext> = {}): KeydownContext => ({
  pending: null,
  suppression: 'none',
  overlayOpen: false,
  mac: false,
  ...o,
})

describe('parseKeys', () => {
  it('maps Mod to Meta on macOS and Ctrl elsewhere', () => {
    expect(parseKeys('Mod+k', true)).toEqual({ sequence: ['k'], metaKey: true })
    expect(parseKeys('Mod+k', false)).toEqual({ sequence: ['k'], ctrlKey: true })
  })

  it('reads literal modifiers', () => {
    expect(parseKeys('Ctrl+Shift+d', true)).toEqual({ sequence: ['d'], ctrlKey: true, shiftKey: true })
    expect(parseKeys('Alt+x', false)).toEqual({ sequence: ['x'], altKey: true })
  })

  it('splits a space-separated sequence', () => {
    expect(parseKeys('g i', false)).toEqual({ sequence: ['g', 'i'] })
  })

  it('keeps single keys, including symbols and named keys', () => {
    expect(parseKeys('?', false).sequence).toEqual(['?'])
    expect(parseKeys('/', false).sequence).toEqual(['/'])
    expect(parseKeys('Escape', false).sequence).toEqual(['Escape'])
  })
})

describe('matchesKey', () => {
  it('requires the exact modifiers of a chord', () => {
    const modK = parseKeys('Mod+k', false)
    expect(matchesKey(key('k', { ctrlKey: true }), modK, null)).toBe(true)
    expect(matchesKey(key('k'), modK, null)).toBe(false)
    expect(matchesKey(key('k', { metaKey: true }), modK, null)).toBe(false)
  })

  it('does not fire a plain key when a modifier is held', () => {
    const k = parseKeys('k', false)
    expect(matchesKey(key('k', { ctrlKey: true }), k, null)).toBe(false)
    expect(matchesKey(key('k', { altKey: true }), k, null)).toBe(false)
    expect(matchesKey(key('K', { shiftKey: true }), k, null)).toBe(false)
  })

  it('accepts Shift-produced symbols without an explicit Shift', () => {
    expect(matchesKey(key('?', { shiftKey: true }), parseKeys('?', false), null)).toBe(true)
  })

  it('requires Shift for an uppercase letter', () => {
    const n = parseKeys('N', false)
    expect(matchesKey(key('N', { shiftKey: true }), n, null)).toBe(true)
    expect(matchesKey(key('n'), n, null)).toBe(false)
  })

  it('completes a sequence only after its first key', () => {
    const gi = parseKeys('g i', false)
    expect(matchesKey(key('i'), gi, 'g')).toBe(true)
    expect(matchesKey(key('i'), gi, null)).toBe(false)
    expect(matchesKey(key('o'), gi, 'g')).toBe(false)
  })
})

describe('suppressionLevel', () => {
  it('is soft in text fields and contenteditable, hard in a keyboard owner, none elsewhere', () => {
    const input = document.createElement('input')
    const textarea = document.createElement('textarea')
    const select = document.createElement('select')
    const owner = document.createElement('div')
    owner.setAttribute('data-keyboard-owner', '')
    const inside = document.createElement('span')
    owner.appendChild(inside)
    const button = document.createElement('button')
    expect(suppressionLevel(input, 'a')).toBe('soft')
    expect(suppressionLevel(textarea, 'a')).toBe('soft')
    expect(suppressionLevel(select, 'a')).toBe('soft')
    expect(suppressionLevel(inside, 'a')).toBe('hard')
    expect(suppressionLevel(button, 'a')).toBe('none')
    expect(suppressionLevel(null, 'a')).toBe('none')
  })

  it('never suppresses Escape', () => {
    expect(suppressionLevel(document.createElement('input'), 'Escape')).toBe('none')
  })
})

describe('eligibleShortcuts', () => {
  const s = (id: string, scope: ShortcutSpec['scope'], enabled?: boolean): ShortcutSpec => ({ id, keys: id, scope, enabled })

  it('orders by scope priority and drops disabled shortcuts', () => {
    const out = eligibleShortcuts([s('a', 'global'), s('b', 'overlay'), s('c', 'page'), s('d', 'panel', false)], false)
    expect(out.map(x => x.id)).toEqual(['b', 'c', 'a'])
  })

  it('keeps only global and overlay scopes while an overlay is open', () => {
    const out = eligibleShortcuts([s('a', 'global'), s('b', 'overlay'), s('c', 'page'), s('d', 'panel')], true)
    expect(out.map(x => x.id)).toEqual(['b', 'a'])
  })
})

describe('resolveKeydown', () => {
  const palette: ShortcutSpec = { id: 'palette', keys: 'Mod+k', scope: 'global', allowInInputs: true }
  const help: ShortcutSpec = { id: 'help', keys: '?', scope: 'global' }
  const goIncidents: ShortcutSpec = { id: 'go-incidents', keys: 'g i', scope: 'global' }
  const goOverview: ShortcutSpec = { id: 'go-overview', keys: 'g o', scope: 'global' }
  const close: ShortcutSpec = { id: 'close', keys: 'Escape', scope: 'panel' }
  const filter: ShortcutSpec = { id: 'filter', keys: '/', scope: 'page' }
  const all = [palette, help, goIncidents, goOverview, close, filter]

  it('holds a sequence first key as pending, then fires the completed sequence', () => {
    const first = resolveKeydown(key('g'), all, ctx())
    expect(first).toEqual({ fire: null, pending: 'g' })
    const second = resolveKeydown(key('i'), all, ctx({ pending: 'g' }))
    expect(second).toEqual({ fire: goIncidents, pending: null })
    expect(resolveKeydown(key('o'), all, ctx({ pending: 'g' })).fire).toBe(goOverview)
  })

  it('judges an unmatched second key as a single key', () => {
    expect(resolveKeydown(key('/'), all, ctx({ pending: 'g' }))).toEqual({ fire: filter, pending: null })
  })

  it('does not start a sequence with a modifier held', () => {
    expect(resolveKeydown(key('g', { ctrlKey: true }), all, ctx())).toEqual({ fire: null, pending: null })
  })

  it('fires Mod+k with the platform modifier', () => {
    expect(resolveKeydown(key('k', { metaKey: true }), all, ctx({ mac: true })).fire).toBe(palette)
    expect(resolveKeydown(key('k', { ctrlKey: true }), all, ctx({ mac: false })).fire).toBe(palette)
    expect(resolveKeydown(key('k', { ctrlKey: true }), all, ctx({ mac: true })).fire).toBeNull()
  })

  it('fires only allowInInputs shortcuts and Escape inside a text input', () => {
    const inInput = ctx({ suppression: 'soft' })
    expect(resolveKeydown(key('?', { shiftKey: true }), all, inInput).fire).toBeNull()
    expect(resolveKeydown(key('g'), all, inInput)).toEqual({ fire: null, pending: null })
    expect(resolveKeydown(key('k', { ctrlKey: true }), all, inInput).fire).toBe(palette)
    expect(resolveKeydown(key('Escape'), all, inInput).fire).toBe(close)
  })

  it('does not complete a sequence typed into an input', () => {
    expect(resolveKeydown(key('i'), all, ctx({ pending: 'g', suppression: 'soft' })).fire).toBeNull()
  })

  it('fires nothing but Escape inside a keyboard owner, even allowInInputs', () => {
    const owned = ctx({ suppression: 'hard' })
    expect(resolveKeydown(key('k', { ctrlKey: true }), all, owned).fire).toBeNull()
    expect(resolveKeydown(key('Escape'), all, owned).fire).toBe(close)
  })

  it('lets the higher-priority scope win when two shortcuts share a key', () => {
    const pageSlash: ShortcutSpec = { id: 'page-slash', keys: '/', scope: 'page' }
    const overlaySlash: ShortcutSpec = { id: 'overlay-slash', keys: '/', scope: 'overlay' }
    expect(resolveKeydown(key('/'), [pageSlash, overlaySlash], ctx()).fire).toBe(overlaySlash)
  })

  it('suppresses page and panel keys while an overlay is open', () => {
    const open = ctx({ overlayOpen: true })
    expect(resolveKeydown(key('/'), all, open).fire).toBeNull()
    expect(resolveKeydown(key('Escape'), all, open).fire).toBeNull()
    expect(resolveKeydown(key('k', { ctrlKey: true }), all, open).fire).toBe(palette)
  })
})

describe('formatKeys', () => {
  it('names the platform modifier', () => {
    expect(formatKeys('Mod+k', true)).toBe('⌘K')
    expect(formatKeys('Mod+k', false)).toBe('Ctrl+K')
  })

  it('reads sequences and named keys in words', () => {
    expect(formatKeys('g i', false)).toBe('g then i')
    expect(formatKeys('Escape', false)).toBe('Esc')
    expect(formatKeys('?', true)).toBe('?')
  })
})

describe('isMacPlatform', () => {
  it('detects macOS and iOS from platform or user agent', () => {
    expect(isMacPlatform({ platform: 'MacIntel' })).toBe(true)
    expect(isMacPlatform({ platform: '', userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)' })).toBe(true)
    expect(isMacPlatform({ platform: 'Linux x86_64' })).toBe(false)
    expect(isMacPlatform(undefined)).toBe(false)
  })
})
