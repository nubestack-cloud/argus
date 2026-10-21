import { afterEach, describe, expect, it } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { clearFresh } from '../realtime/freshRows'
import { useNewArrivals } from './useNewArrivals'

// CI-U8: rows that arrive while the reader is scrolled down are held behind a
// count rather than inserted above them; at the top they simply appear.

function anchorAt(top: number) {
  return { current: { getBoundingClientRect: () => ({ top }) as DOMRect, scrollIntoView: () => {} } as unknown as Element }
}

const rows = (...ids: string[]) => ids.map((id) => ({ id }))

afterEach(() => clearFresh())

describe('useNewArrivals', () => {
  it('holds new rows while scrolled away and lets them in on show', () => {
    const anchorRef = anchorAt(-400)
    const { result, rerender } = renderHook((p: { rows: { id: string }[]; scope: string }) => useNewArrivals({ ...p, settled: true, anchorRef }), {
      initialProps: { rows: rows('a', 'b'), scope: 's' },
    })
    expect(result.current.visible.map((r) => r.id)).toEqual(['a', 'b'])
    rerender({ rows: rows('n1', 'n2', 'a', 'b'), scope: 's' })
    expect(result.current.heldCount).toBe(2)
    expect(result.current.visible.map((r) => r.id)).toEqual(['a', 'b'])
    act(() => result.current.showHeld())
    expect(result.current.heldCount).toBe(0)
    expect(result.current.visible.map((r) => r.id)).toEqual(['n1', 'n2', 'a', 'b'])
  })

  it('shows new rows at once when the list top is in view', () => {
    const anchorRef = anchorAt(120)
    const { result, rerender } = renderHook((p: { rows: { id: string }[] }) => useNewArrivals({ ...p, scope: 's', settled: true, anchorRef }), {
      initialProps: { rows: rows('a') },
    })
    rerender({ rows: rows('n', 'a') })
    expect(result.current.heldCount).toBe(0)
    expect(result.current.visible).toHaveLength(2)
  })

  it('starts over when the query changes, so filtered-in rows are not "new"', () => {
    const anchorRef = anchorAt(-400)
    const { result, rerender } = renderHook((p: { rows: { id: string }[]; scope: string }) => useNewArrivals({ ...p, settled: true, anchorRef }), {
      initialProps: { rows: rows('a'), scope: 's1' },
    })
    rerender({ rows: rows('x', 'y'), scope: 's2' })
    expect(result.current.heldCount).toBe(0)
    expect(result.current.visible).toHaveLength(2)
  })
})
