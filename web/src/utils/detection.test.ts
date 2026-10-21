import { describe, expect, it } from 'vitest'
import { detectionLatency } from './detection'
import { formatSecondsRange } from './time'

// The detection-latency range is the number an operator plans around, and it is
// NEITHER of the two values they configured — a fault is first observed at most one
// sweep after it starts, then reported at the first sweep past the persistence
// threshold, so the wait rounds UP to a sweep boundary rather than firing at the
// threshold exactly.
//
// Getting this wrong would not fail visibly. It would put a confident, wrong number
// on a page, and the two configured values sitting next to it would make it look
// corroborated. So the assertions below are anchored to values MEASURED on real
// clusters (CAPABILITIES.md §6) rather than to the formula restated.

describe('detectionLatency', () => {
  it('matches the 61s measured at 30s/60s on rke2', () => {
    const got = detectionLatency({ sweepIntervalSeconds: 30, sustainedThresholdSeconds: 60 })
    expect(got).not.toBeNull()
    expect(got!.floorSeconds).toBe(60)
    expect(got!.ceilingSeconds).toBe(90)
    // The measured 61s must fall inside the predicted range, exclusive of the
    // floor — a prediction that excludes the observation is wrong however tidy.
    expect(61).toBeGreaterThanOrEqual(got!.floorSeconds)
    expect(61).toBeLessThanOrEqual(got!.ceilingSeconds)
  })

  it('matches the ten-to-fifteen minutes measured at the shipped 300s/600s defaults', () => {
    const got = detectionLatency({ sweepIntervalSeconds: 300, sustainedThresholdSeconds: 600 })
    expect(formatSecondsRange(got!.floorSeconds, got!.ceilingSeconds)).toBe('10m–15m')
  })

  it('rounds UP to a sweep boundary when the threshold is not a multiple of the interval', () => {
    // 400s threshold at a 300s sweep cannot report at 400s — the next sweep is at
    // 600s. Reporting "6m 40s" would promise a precision the detector does not have.
    const got = detectionLatency({ sweepIntervalSeconds: 300, sustainedThresholdSeconds: 400 })
    expect(got!.floorSeconds).toBe(600)
    expect(got!.ceilingSeconds).toBe(900)
  })

  it('is one interval wide, always — the fault could have begun just after a sweep', () => {
    for (const [interval, threshold] of [[30, 60], [300, 600], [15, 15], [60, 300]]) {
      const got = detectionLatency({ sweepIntervalSeconds: interval, sustainedThresholdSeconds: threshold })
      expect(got!.ceilingSeconds - got!.floorSeconds).toBe(interval)
    }
  })

  it('handles a threshold shorter than the interval without reporting sub-interval latency', () => {
    // A 10s threshold on a 60s sweep still cannot be noticed faster than a sweep.
    const got = detectionLatency({ sweepIntervalSeconds: 60, sustainedThresholdSeconds: 10 })
    expect(got!.floorSeconds).toBe(60)
    expect(got!.ceilingSeconds).toBe(120)
  })

  // Zero is "not reported", never zero seconds — every field arrives omitempty, so
  // a missing value and a real zero are indistinguishable and only one is possible.
  // Returning a range here would render a latency for a cluster that reported none.
  it.each([
    ['nothing reported', {}],
    ['interval only', { sweepIntervalSeconds: 30 }],
    ['threshold only', { sustainedThresholdSeconds: 60 }],
    ['zero interval', { sweepIntervalSeconds: 0, sustainedThresholdSeconds: 60 }],
    ['zero threshold', { sweepIntervalSeconds: 30, sustainedThresholdSeconds: 0 }],
    ['negative interval', { sweepIntervalSeconds: -30, sustainedThresholdSeconds: 60 }],
  ])('returns null for %s', (_name, detection) => {
    expect(detectionLatency(detection)).toBeNull()
  })
})
