import { act } from 'react'
import { describe, expect, it } from 'vitest'
import { renderHook } from '@testing-library/react'
import { usePagination } from './pagination'

// usePagination is shared by three lists, and every one of them refetches every
// five seconds — so a result set shrinking under a parked page number is routine,
// not an edge case. The clamp is the whole reason this hook exists rather than each
// page doing its own arithmetic, and it is exactly the kind of off-by-one that
// typecheck, lint and build all pass straight over.

const items = (n: number) => Array.from({ length: n }, (_, i) => i + 1)

describe('usePagination', () => {
  it('shows the first page and reports a 1-based range', () => {
    const { result } = renderHook(() => usePagination(items(25), 10))
    expect(result.current.visibleItems).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    expect(result.current.pagination.firstResult).toBe(1)
    expect(result.current.pagination.lastResult).toBe(10)
    expect(result.current.pagination.totalPages).toBe(3)
  })

  it('reports zeros for an empty list, and slices from 0 rather than -1', () => {
    const { result } = renderHook(() => usePagination(items(0), 10))
    expect(result.current.visibleItems).toEqual([])
    expect(result.current.pagination.firstResult).toBe(0)
    expect(result.current.pagination.lastResult).toBe(0)
    // Never 0: "Page 1 of 0" reads as broken.
    expect(result.current.pagination.totalPages).toBe(1)
  })

  it('gives the last page only its remainder', () => {
    const { result } = renderHook(() => usePagination(items(25), 10))
    act(() => result.current.pagination.onPageChange(3))
    expect(result.current.visibleItems).toEqual([21, 22, 23, 24, 25])
    expect(result.current.pagination.firstResult).toBe(21)
    expect(result.current.pagination.lastResult).toBe(25)
  })

  // THE ONE THAT MATTERS. Park on page 3, then the five-second refetch returns
  // fewer rows. Without the clamp the table renders empty and the footer says
  // "Showing 21-25 of 8".
  it('clamps a parked page when the list shrinks under it', () => {
    const { result, rerender } = renderHook(({ data }) => usePagination(data, 10), {
      initialProps: { data: items(25) },
    })
    act(() => result.current.pagination.onPageChange(3))
    expect(result.current.visibleItems).toEqual([21, 22, 23, 24, 25])

    rerender({ data: items(8) })

    expect(result.current.pagination.currentPage).toBe(1)
    expect(result.current.pagination.totalPages).toBe(1)
    expect(result.current.visibleItems).toEqual(items(8))
    expect(result.current.pagination.lastResult).toBe(8)
  })

  it('clamps to an empty list without producing a negative range', () => {
    const { result, rerender } = renderHook(({ data }) => usePagination(data, 10), {
      initialProps: { data: items(25) },
    })
    act(() => result.current.pagination.onPageChange(3))
    rerender({ data: items(0) })

    expect(result.current.pagination.firstResult).toBe(0)
    expect(result.current.pagination.lastResult).toBe(0)
    expect(result.current.visibleItems).toEqual([])
  })

  it('returns to page 1 when rows-per-page changes, because page 4 at 10 is not page 4 at 50', () => {
    const { result } = renderHook(() => usePagination(items(200), 10))
    act(() => result.current.pagination.onPageChange(4))
    expect(result.current.pagination.currentPage).toBe(4)

    act(() => result.current.pagination.onRowsPerPageChange(50))

    expect(result.current.pagination.currentPage).toBe(1)
    expect(result.current.pagination.rowsPerPage).toBe(50)
    expect(result.current.visibleItems).toHaveLength(50)
  })

  it('resetToFirstPage exists for the caller’s own filters, and works', () => {
    const { result } = renderHook(() => usePagination(items(100), 10))
    act(() => result.current.pagination.onPageChange(5))
    act(() => result.current.resetToFirstPage())
    expect(result.current.pagination.currentPage).toBe(1)
  })

  it('a list shorter than one page is a single page, not zero', () => {
    const { result } = renderHook(() => usePagination(items(3), 10))
    expect(result.current.pagination.totalPages).toBe(1)
    expect(result.current.pagination.lastResult).toBe(3)
    expect(result.current.visibleItems).toEqual([1, 2, 3])
  })
})
