import { describe, expect, it } from 'vitest'
import { act, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { KeyboardShortcutProvider } from './shortcuts'
import { GlobalShortcuts } from './GlobalShortcuts'
import { findPageFilter } from './bindings'

function Loc() {
  return <p data-testid="loc">{useLocation().pathname}</p>
}

function renderShortcuts() {
  return render(
    <MemoryRouter initialEntries={['/overview']}>
      <KeyboardShortcutProvider mac={false}>
        <GlobalShortcuts />
        <main className="app-main">
          <div className="filter-bar">
            <input aria-label="filter" />
          </div>
        </main>
        <Loc />
      </KeyboardShortcutProvider>
    </MemoryRouter>,
  )
}

describe('GlobalShortcuts', () => {
  it('navigates on g then a letter', () => {
    renderShortcuts()
    fireEvent.keyDown(document.body, { key: 'g' })
    fireEvent.keyDown(document.body, { key: 'i' })
    expect(screen.getByTestId('loc').textContent).toBe('/incidents')
    fireEvent.keyDown(document.body, { key: 'g' })
    fireEvent.keyDown(document.body, { key: 'h' })
    expect(screen.getByTestId('loc').textContent).toBe('/changes')
  })

  it('focuses the page filter on / and does not navigate while typing', () => {
    renderShortcuts()
    fireEvent.keyDown(document.body, { key: '/' })
    const input = screen.getByLabelText('filter')
    expect(document.activeElement).toBe(input)
    fireEvent.keyDown(input, { key: 'g' })
    fireEvent.keyDown(input, { key: 'c' })
    expect(screen.getByTestId('loc').textContent).toBe('/overview')
  })

  it('lists the active shortcuts on ?', () => {
    renderShortcuts()
    act(() => {
      fireEvent.keyDown(document.body, { key: '?', shiftKey: true })
    })
    const dialog = screen.getByRole('dialog', { name: 'Keyboard shortcuts' })
    expect(dialog.textContent).toContain('g then i')
    expect(dialog.textContent).toContain('Go to Incidents')
    expect(dialog.textContent).toContain("Focus this page's filter")
  })

  it('prefers an explicitly marked filter', () => {
    document.body.innerHTML = '<div class="app-main"><div class="filter-bar"><input id="a"></div><input id="b" data-page-filter></div>'
    expect(findPageFilter()?.id).toBe('b')
    document.body.innerHTML = ''
  })
})
