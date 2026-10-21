import { describe, expect, it } from 'vitest'
import { countFor, legacyViewParams, statesFor, type Breakdown } from './incidentFilters'

const breakdown: Breakdown = [
  { status: 'requiresAction', severity: 'critical', count: 2 },
  { status: 'requiresAction', severity: 'low', count: 5 },
  { status: 'inProgress', severity: 'critical', count: 1 },
  { status: 'closed', severity: 'critical', count: 40 },
]

describe('countFor', () => {
  it('sums the cells a status and severity select', () => {
    expect(countFor(breakdown, 'open', '')).toBe(8)
    expect(countFor(breakdown, 'open', 'critical')).toBe(3)
    expect(countFor(breakdown, 'requiresAction', 'low')).toBe(5)
    expect(countFor(breakdown, 'closed', 'low')).toBe(0)
    expect(countFor(breakdown, 'all', '')).toBe(48)
  })

  it('is undefined before the server answers, never a fabricated zero', () => {
    expect(countFor(undefined, 'open', '')).toBeUndefined()
  })
})

describe('statesFor', () => {
  it('keeps only the states inside the status', () => {
    expect(statesFor('closed', ['Detected', 'Resolved', 'Investigating', 'Expired'])).toEqual(['Resolved', 'Expired'])
    expect(statesFor('inProgress', ['Detected', 'Investigating', 'AwaitingMerge'])).toEqual(['Investigating', 'AwaitingMerge'])
    expect(statesFor('open', ['Detected', 'Investigating', 'Dismissed'])).toEqual(['Detected', 'Investigating'])
  })
})

describe('legacyViewParams', () => {
  it('maps the old mixed tabs onto status and severity', () => {
    expect(legacyViewParams('requiresAction')).toEqual({ status: 'requiresAction' })
    expect(legacyViewParams('critical')).toEqual({ status: 'all', severity: 'critical' })
    expect(legacyViewParams('nonsense')).toEqual({})
    expect(legacyViewParams(null)).toBeNull()
  })
})
