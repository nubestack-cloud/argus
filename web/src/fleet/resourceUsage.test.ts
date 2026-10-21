import { describe, expect, it } from 'vitest'
import { usageBand } from './resourceUsage'

describe('usageBand', () => {
  it.each([
    [0, 'normal'],
    [0.49, 'normal'],
    [0.5, 'medium'],
    [0.74, 'medium'],
    [0.75, 'high'],
    [0.89, 'high'],
    [0.9, 'critical'],
    [1.3, 'critical'],
  ])('reads %s as %s', (ratio, band) => {
    expect(usageBand(ratio)).toBe(band)
  })
})
