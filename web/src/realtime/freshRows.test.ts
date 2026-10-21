import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, renderHook } from '@testing-library/react'
import { FRESH_MS, clearFresh, markFresh, useFreshIds } from './freshRows'

describe('fresh rows', () => {
  afterEach(() => {
    clearFresh()
    vi.useRealTimers()
  })

  it('marks a row fresh for two seconds', () => {
    vi.useFakeTimers()
    const { result } = renderHook(() => useFreshIds())
    act(() => markFresh(['a']))
    expect(result.current.has('a')).toBe(true)
    act(() => {
      vi.advanceTimersByTime(FRESH_MS + 50)
    })
    expect(result.current.has('a')).toBe(false)
  })
})
