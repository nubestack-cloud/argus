import { act, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { KeyboardShortcut } from './context'
import { KeyboardShortcutProvider } from './shortcuts'
import { useActiveShortcuts, useOverlayOpen, useRegisterShortcuts } from './useShortcuts'

function Registrar({ shortcuts }: { shortcuts: KeyboardShortcut[] }) {
  useRegisterShortcuts(shortcuts)
  return null
}

function Overlay({ open }: { open: boolean }) {
  useOverlayOpen(open)
  return null
}

function HelpList() {
  const shortcuts = useActiveShortcuts()
  return (
    <ul>
      {shortcuts.map(s => (
        <li key={s.id}>{`${s.keys}: ${s.description}`}</li>
      ))}
    </ul>
  )
}

const shortcut = (o: Partial<KeyboardShortcut> & Pick<KeyboardShortcut, 'id' | 'keys'>): KeyboardShortcut => ({
  description: o.id,
  category: 'General',
  scope: 'global',
  handler: () => {},
  ...o,
})

describe('KeyboardShortcutProvider', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it('fires a two-key sequence within the timeout and not after it', () => {
    const handler = vi.fn()
    render(
      <KeyboardShortcutProvider mac={false}>
        <Registrar shortcuts={[shortcut({ id: 'go-incidents', keys: 'g i', handler })]} />
      </KeyboardShortcutProvider>,
    )
    fireEvent.keyDown(document, { key: 'g' })
    fireEvent.keyDown(document, { key: 'i' })
    expect(handler).toHaveBeenCalledTimes(1)

    fireEvent.keyDown(document, { key: 'g' })
    act(() => {
      vi.advanceTimersByTime(600)
    })
    fireEvent.keyDown(document, { key: 'i' })
    expect(handler).toHaveBeenCalledTimes(1)
  })

  it('fires Mod+k from inside an input when allowInInputs, and plain keys never', () => {
    const palette = vi.fn()
    const help = vi.fn()
    render(
      <KeyboardShortcutProvider mac={false}>
        <Registrar
          shortcuts={[
            shortcut({ id: 'palette', keys: 'Mod+k', allowInInputs: true, handler: palette }),
            shortcut({ id: 'help', keys: '?', handler: help }),
          ]}
        />
        <input aria-label="filter" />
      </KeyboardShortcutProvider>,
    )
    const input = screen.getByLabelText('filter')
    fireEvent.keyDown(input, { key: '?', shiftKey: true })
    expect(help).not.toHaveBeenCalled()
    fireEvent.keyDown(input, { key: 'k', ctrlKey: true })
    expect(palette).toHaveBeenCalledTimes(1)
    fireEvent.keyDown(document.body, { key: '?', shiftKey: true })
    expect(help).toHaveBeenCalledTimes(1)
  })

  it('prevents the browser default only when a shortcut fired', () => {
    render(
      <KeyboardShortcutProvider mac>
        <Registrar shortcuts={[shortcut({ id: 'palette', keys: 'Mod+k' })]} />
      </KeyboardShortcutProvider>,
    )
    expect(fireEvent.keyDown(document, { key: 'k', metaKey: true })).toBe(false)
    expect(fireEvent.keyDown(document, { key: 'x' })).toBe(true)
  })

  it('suppresses page shortcuts while any overlay is open', () => {
    const filter = vi.fn()
    const { rerender } = render(
      <KeyboardShortcutProvider mac={false}>
        <Registrar shortcuts={[shortcut({ id: 'filter', keys: '/', scope: 'page', handler: filter })]} />
        <Overlay open />
        <Overlay open />
      </KeyboardShortcutProvider>,
    )
    fireEvent.keyDown(document, { key: '/' })
    expect(filter).not.toHaveBeenCalled()

    rerender(
      <KeyboardShortcutProvider mac={false}>
        <Registrar shortcuts={[shortcut({ id: 'filter', keys: '/', scope: 'page', handler: filter })]} />
        <Overlay open={false} />
        <Overlay open />
      </KeyboardShortcutProvider>,
    )
    fireEvent.keyDown(document, { key: '/' })
    expect(filter).not.toHaveBeenCalled()

    rerender(
      <KeyboardShortcutProvider mac={false}>
        <Registrar shortcuts={[shortcut({ id: 'filter', keys: '/', scope: 'page', handler: filter })]} />
        <Overlay open={false} />
        <Overlay open={false} />
      </KeyboardShortcutProvider>,
    )
    fireEvent.keyDown(document, { key: '/' })
    expect(filter).toHaveBeenCalledTimes(1)
  })

  it('calls the latest handler without re-registering, and deregisters on unmount', () => {
    const first = vi.fn()
    const second = vi.fn()
    const { rerender } = render(
      <KeyboardShortcutProvider mac={false}>
        <Registrar shortcuts={[shortcut({ id: 'help', keys: '?', handler: first })]} />
      </KeyboardShortcutProvider>,
    )
    rerender(
      <KeyboardShortcutProvider mac={false}>
        <Registrar shortcuts={[shortcut({ id: 'help', keys: '?', handler: second })]} />
      </KeyboardShortcutProvider>,
    )
    fireEvent.keyDown(document, { key: '?' })
    expect(first).not.toHaveBeenCalled()
    expect(second).toHaveBeenCalledTimes(1)

    rerender(<KeyboardShortcutProvider mac={false}>{null}</KeyboardShortcutProvider>)
    fireEvent.keyDown(document, { key: '?' })
    expect(second).toHaveBeenCalledTimes(1)
  })

  it('keeps other shortcuts working when a handler throws', () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {})
    const ok = vi.fn()
    render(
      <KeyboardShortcutProvider mac={false}>
        <Registrar
          shortcuts={[
            shortcut({ id: 'boom', keys: 'b', handler: () => { throw new Error('boom') } }),
            shortcut({ id: 'ok', keys: 'o', handler: ok }),
          ]}
        />
      </KeyboardShortcutProvider>,
    )
    fireEvent.keyDown(document, { key: 'b' })
    fireEvent.keyDown(document, { key: 'o' })
    expect(ok).toHaveBeenCalledTimes(1)
    expect(error).toHaveBeenCalled()
    error.mockRestore()
  })

  it('lists registered shortcuts for the help overlay, deduplicated by id and sorted', () => {
    render(
      <KeyboardShortcutProvider mac={false}>
        <Registrar
          shortcuts={[
            shortcut({ id: 'go-incidents', keys: 'g i', category: 'Navigation', description: 'Incidents' }),
            shortcut({ id: 'help', keys: '?', description: 'Show shortcuts' }),
            shortcut({ id: 'go-overview', keys: 'g o', category: 'Navigation', description: 'Overview' }),
          ]}
        />
        <Registrar shortcuts={[shortcut({ id: 'help', keys: '?', scope: 'page', description: 'Page help' })]} />
        <HelpList />
      </KeyboardShortcutProvider>,
    )
    expect(screen.getAllByRole('listitem').map(li => li.textContent)).toEqual([
      '?: Page help',
      'g i: Incidents',
      'g o: Overview',
    ])
  })
})
