import { describe, expect, it } from 'vitest'
import { nearestSample } from './nearestSample'

// A 30-second series with one missed evaluation (t=60) and a trailing gap.
const series = [
  { timestamp: 0, value: 5 },
  { timestamp: 30, value: 0 },
  { timestamp: 90, value: 7 },
  { timestamp: 120, value: null },
]

describe('nearestSample', () => {
  it('snaps to a measured point within half a step, zero included', () => {
    expect(nearestSample(series, 40, 30)).toEqual({ timestamp: 30, value: 0 })
    expect(nearestSample(series, 100, 30)).toEqual({ timestamp: 90, value: 7 })
  })

  it('shows nothing over a missed evaluation or a gap, or past either end', () => {
    expect(nearestSample(series, 60, 30)).toBeNull()
    expect(nearestSample(series, 120, 30)).toBeNull()
    expect(nearestSample(series, -20, 30)).toBeNull()
  })

  it('without a step, takes the nearest measured point however far', () => {
    expect(nearestSample(series, 60)).toEqual({ timestamp: 30, value: 0 })
    expect(nearestSample(series, 500)).toEqual({ timestamp: 90, value: 7 })
    expect(nearestSample([], 0)).toBeNull()
    expect(nearestSample([{ timestamp: 0, value: null }], 0)).toBeNull()
  })
})
