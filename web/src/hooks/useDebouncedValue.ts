import { useEffect, useState } from 'react'

/** The latest `value` once it has stopped changing for `delayMs`, so a search
 *  box queries when the person pauses, not on every keystroke. */
export function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [settled, setSettled] = useState(value)
  useEffect(() => {
    if (Object.is(value, settled)) return
    const timer = window.setTimeout(() => setSettled(value), delayMs)
    return () => window.clearTimeout(timer)
  }, [value, settled, delayMs])
  return settled
}
