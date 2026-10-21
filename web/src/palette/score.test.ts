import { describe, expect, it } from 'vitest'
import { bestScore, rankEntries, scoreMatch, type ScoredEntry } from './score'

describe('scoreMatch', () => {
  it('ranks exact > prefix > word boundary > substring', () => {
    const exact = scoreMatch('Incidents', 'incidents')
    const prefix = scoreMatch('Incidents', 'inc')
    const boundary = scoreMatch('Open incidents', 'inc')
    const substring = scoreMatch('Coincidence', 'inc')
    expect(exact).toBe(170)
    expect(prefix).toBeGreaterThanOrEqual(100)
    expect(prefix).toBeLessThan(150)
    expect(boundary).toBeGreaterThanOrEqual(75)
    expect(boundary).toBeLessThan(100)
    expect(substring).toBeGreaterThanOrEqual(50)
    expect(substring).toBeLessThan(75)
  })

  it('adds a coverage bonus of query/text length × 20', () => {
    expect(scoreMatch('abcd', 'ab')).toBe(110)
    expect(scoreMatch('ab', 'ab')).toBe(170)
  })

  it('treats /, -, . and space as word boundaries', () => {
    for (const text of ['x/pay', 'x-pay', 'x.pay', 'x pay']) {
      expect(scoreMatch(text, 'pay')).toBe(75 + (3 / 5) * 20)
    }
    expect(scoreMatch('xpay', 'pay')).toBe(50 + (3 / 4) * 20)
  })

  it('is case-insensitive and returns 0 for no match or an empty query', () => {
    expect(scoreMatch('Payments', 'PAY')).toBeGreaterThan(0)
    expect(scoreMatch('Payments', 'zzz')).toBe(0)
    expect(scoreMatch('Payments', '')).toBe(0)
  })
})

describe('bestScore', () => {
  const page: ScoredEntry = { label: 'Incidents', category: 'Pages' }

  it('discounts sublabel and category matches to 0.6 and floors them', () => {
    const entry: ScoredEntry = { label: 'Overview', sublabel: 'cluster lab-dev', category: 'Clusters' }
    expect(bestScore(entry, 'clusters')).toBe(Math.floor(170 * 0.6))
    expect(bestScore(entry, 'lab')).toBe(Math.floor((75 + (3 / 15) * 20) * 0.6))
  })

  it('matches undisplayed search terms at full weight', () => {
    const entry: ScoredEntry = { label: 'Approvals', category: 'Pages', searchTerms: ['pending actions'] }
    expect(bestScore(entry, 'pending')).toBe(scoreMatch('pending actions', 'pending'))
  })

  it('adds the priority bonus only when the entry matched', () => {
    expect(bestScore({ ...page, priorityBonus: 10 }, 'inc')).toBe(scoreMatch('Incidents', 'inc') + 10)
    expect(bestScore({ ...page, priorityBonus: 10 }, 'zzz')).toBe(0)
  })
})

describe('rankEntries', () => {
  const entries: ScoredEntry[] = [
    { label: 'payments-api', category: 'Incidents' },
    { label: 'Signals', category: 'Pages' },
    { label: 'payments', category: 'Clusters' },
    { label: 'old-payments', category: 'Incidents' },
  ]

  it('orders matches best first and drops non-matches', () => {
    expect(rankEntries(entries, 'payments').map(e => e.label)).toEqual(['payments', 'payments-api', 'old-payments'])
  })

  it('keeps input order on a tie', () => {
    const tied: ScoredEntry[] = [
      { label: 'a-pay', category: 'X' },
      { label: 'b-pay', category: 'X' },
    ]
    expect(rankEntries(tied, 'pay').map(e => e.label)).toEqual(['a-pay', 'b-pay'])
  })

  it('returns nothing for a blank query', () => {
    expect(rankEntries(entries, '   ')).toEqual([])
  })
})
