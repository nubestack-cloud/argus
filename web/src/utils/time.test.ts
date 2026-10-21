import { describe, expect, it } from 'vitest'
import { formatSeconds, formatSecondsRange, formatRelativeTime, formatDurationBetween, fromDatetimeLocalValue } from './time'

// These four are rendered on screens an operator makes decisions from — the
// detection-latency range on Cluster Detail, the breaker's window, every "3
// minutes ago". A wrong unit here is not a cosmetic bug: "5m" where the truth is
// "5s" changes what somebody believes about how fast the product notices things.

describe('formatSeconds', () => {
  it('renders sub-minute values in seconds, because detector timings live at that scale', () => {
    expect(formatSeconds(1)).toBe('1s')
    expect(formatSeconds(30)).toBe('30s')
    expect(formatSeconds(59)).toBe('59s')
  })

  it('renders whole minutes without a trailing 0s', () => {
    expect(formatSeconds(60)).toBe('1m')
    expect(formatSeconds(300)).toBe('5m')
    expect(formatSeconds(3600)).toBe('1h')
  })

  it('keeps the remainder when there is one', () => {
    expect(formatSeconds(90)).toBe('1m 30s')
    expect(formatSeconds(5400)).toBe('1h 30m')
  })

  // The one that matters most: every timing this renders arrives as an omitempty
  // field, so a missing value and a real zero are indistinguishable on the wire —
  // and only one of them is possible. Rendering "0s" would assert a detector that
  // sweeps continuously.
  it.each([0, undefined, -1, -3600])('renders %s as "Not reported", never as a duration', (input) => {
    expect(formatSeconds(input as number | undefined)).toBe('Not reported')
  })
})

describe('formatSecondsRange', () => {
  // Both endpoints in one unit. Formatting them independently gives
  // "1m-1m 30s" for the range a test cluster actually produces, which is correct
  // and materially harder to read than "60s-90s".
  it('uses seconds for a sub-two-minute range', () => {
    expect(formatSecondsRange(60, 90)).toBe('60s–90s')
  })

  it('uses minutes when both endpoints are whole minutes', () => {
    expect(formatSecondsRange(600, 900)).toBe('10m–15m')
  })

  it('falls back to per-endpoint formatting when the range is not on minute boundaries', () => {
    expect(formatSecondsRange(135, 180)).toBe('2m 15s–3m')
  })

  it('handles an hours-scale range', () => {
    expect(formatSecondsRange(3600, 4500)).toBe('1h–1h 15m')
  })
})

describe('formatRelativeTime', () => {
  it('renders null as an em dash rather than "Invalid Date"', () => {
    // A cluster that has never sent a heartbeat has a null lastHeartbeatAt, and
    // this is rendered in a table cell.
    expect(formatRelativeTime(null)).not.toContain('Invalid')
  })

  it('does not throw on an unparseable timestamp', () => {
    expect(() => formatRelativeTime('not a date')).not.toThrow()
  })
})

describe('formatDurationBetween — the incident timeline\'s client-computed gaps (BACKLOG.md B1)', () => {
  it('renders the gap between two real, increasing timestamps', () => {
    expect(formatDurationBetween('2026-08-25T09:00:00Z', '2026-08-25T09:03:00Z')).toBe('+3m')
  })

  it('returns null, never "+0s", for two identical timestamps', () => {
    // Two events written in the same transaction before migration 000067's
    // clock_timestamp() fix could share one instant — asserting a duration
    // here would be a fabricated fact, not a rendering nicety.
    expect(formatDurationBetween('2026-08-25T09:00:00Z', '2026-08-25T09:00:00Z')).toBeNull()
  })

  it('returns null when the second timestamp is earlier (out-of-order input)', () => {
    expect(formatDurationBetween('2026-08-25T09:03:00Z', '2026-08-25T09:00:00Z')).toBeNull()
  })

  it('returns null for an unparseable timestamp rather than throwing', () => {
    expect(formatDurationBetween('not a date', '2026-08-25T09:00:00Z')).toBeNull()
  })
})

describe('fromDatetimeLocalValue', () => {
  it('returns undefined for an empty box so the caller drops the filter entirely', () => {
    expect(fromDatetimeLocalValue('')).toBeUndefined()
  })

  it('returns undefined for an unparseable value rather than sending "Invalid Date"', () => {
    expect(fromDatetimeLocalValue('nonsense')).toBeUndefined()
  })

  it('round-trips a real local datetime to an ISO string', () => {
    const got = fromDatetimeLocalValue('2026-08-23T11:45')
    expect(got).toBeDefined()
    expect(Number.isNaN(Date.parse(got!))).toBe(false)
  })
})
