import { describe, expect, it } from 'vitest'
import { arcLengths, isFloored, MIN_ARC_FRACTION } from './donut'

// The bug this exists to prevent: one critical incident among 180 drew 0.55% of
// the ring — a ~1.4px arc — so the single most important segment was the one you
// could not see. The floor fixes that, and the floor's own risk is that it
// silently distorts everything else. Both directions are asserted.

const CIRC = 2 * Math.PI * 40 // ~251.3, the real donut's circumference
const sum = (xs: number[]) => xs.reduce((a, b) => a + b, 0)

describe('arcLengths', () => {
  it('leaves proportions untouched when every segment is already big enough', () => {
    const got = arcLengths([50, 30, 20], 100, CIRC)
    expect(got[0]).toBeCloseTo(CIRC * 0.5, 6)
    expect(got[1]).toBeCloseTo(CIRC * 0.3, 6)
    expect(got[2]).toBeCloseTo(CIRC * 0.2, 6)
  })

  it('gives a 1-in-180 segment a visible arc instead of a 1.4px sliver', () => {
    const got = arcLengths([1, 179], 180, CIRC)
    const naive = (1 / 180) * CIRC
    expect(naive).toBeLessThan(2) // the bug: under two pixels
    expect(got[0]).toBeCloseTo(MIN_ARC_FRACTION * CIRC, 6)
    expect(got[0]).toBeGreaterThan(naive)
  })

  // The floor's own hazard: if it added length without taking it back, the ring
  // would overflow and the last segment would wrap past 12 o'clock.
  it('still sums to exactly the circumference after flooring', () => {
    for (const counts of [[1, 179], [1, 1, 1, 500], [3, 4, 5, 1000], [1, 2, 3, 4]]) {
      const got = arcLengths(counts, sum(counts), CIRC)
      expect(sum(got)).toBeCloseTo(CIRC, 4)
    }
  })

  it('takes the floor from the segments with room, in proportion to their spare', () => {
    // Two big segments, one tiny. The larger of the two donates more.
    const got = arcLengths([1, 60, 39], 100, CIRC)
    const naiveBig = 0.6 * CIRC
    const naiveMid = 0.39 * CIRC
    expect(got[1]).toBeLessThan(naiveBig)
    expect(got[2]).toBeLessThan(naiveMid)
    expect(naiveBig - got[1]).toBeGreaterThan(naiveMid - got[2])
  })

  it('never gives a zero-count segment an arc', () => {
    const got = arcLengths([0, 5, 0], 5, CIRC)
    expect(got[0]).toBe(0)
    expect(got[2]).toBe(0)
    expect(got[1]).toBeCloseTo(CIRC, 6)
  })

  it('leaves true proportions alone when nothing can afford the floor', () => {
    // 60 equal segments are each below the floor; rescuing them all would mean
    // distorting every one, so the honest answer is to distort none.
    const counts = Array.from({ length: 60 }, () => 1)
    const got = arcLengths(counts, 60, CIRC)
    expect(sum(got)).toBeCloseTo(CIRC, 4)
    for (const len of got) expect(len).toBeCloseTo(CIRC / 60, 6)
  })

  it('returns all zeros for an empty total rather than dividing by zero', () => {
    expect(arcLengths([0, 0], 0, CIRC)).toEqual([0, 0])
    expect(arcLengths([], 0, CIRC)).toEqual([])
  })

  it('handles a single segment as the whole ring', () => {
    const got = arcLengths([7], 7, CIRC)
    expect(got[0]).toBeCloseTo(CIRC, 6)
  })
})

describe('isFloored', () => {
  it('is true exactly when the arc is no longer to scale, which is when the UI must say so', () => {
    expect(isFloored(1, 180)).toBe(true)
    expect(isFloored(50, 100)).toBe(false)
  })

  it('is false for an absent segment and for an empty total', () => {
    expect(isFloored(0, 180)).toBe(false)
    expect(isFloored(5, 0)).toBe(false)
  })
})
