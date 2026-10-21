import { describe, expect, it } from 'vitest'
import type { SpendToday } from '../api/types'
import { spendTileState } from './spend'

// PROJECT.md T8. The daily spend ceiling cannot fire on a subscription-billed
// provider, and this tile is one of the two places spend is displayed, so it
// is one of the two places that has to say so. Every case below is a claim a
// reader will act on, which is why they are pinned rather than eyeballed.
describe('spendTileState — the tile never claims a spend it cannot measure', () => {
  function spend(over: Partial<SpendToday> = {}): SpendToday {
    return {
      generatedAt: '2026-09-17T10:00:00Z',
      date: '2026-09-17',
      todaySpendUsd: 0,
      pricingConfigured: true,
      spendCountable: true,
      dailySpendCeilingUsd: null,
      ceilingBreached: false,
      ceilingEnforceable: false,
      ...over,
    }
  }
  const args = { canReadSpend: true, isLoading: false }

  it('renders the real figure, the ceiling and a bar only when the ceiling can actually fire', () => {
    const state = spendTileState({
      ...args,
      spend: spend({ todaySpendUsd: 2.5, dailySpendCeilingUsd: 10, ceilingEnforceable: true }),
    })
    expect(state.value).toBe('$2.50')
    expect(state.note).toBe('of $10.00 daily ceiling')
    expect(state.percent).toBe(25)
  })

  it('says "Not measured" and draws no bar on a subscription provider, however the ceiling is set', () => {
    const withCeiling = spendTileState({
      ...args,
      spend: spend({ spendCountable: false, dailySpendCeilingUsd: 10 }),
    })
    // Not '$0.00': todaySpendUsd sums metered rows only, so zero here means
    // unmeasured, not free.
    expect(withCeiling.value).toBe('Not measured')
    expect(withCeiling.note).toBe('$10.00 ceiling cannot be enforced')
    // A 0% bar would assert a measured 0% of the ceiling consumed.
    expect(withCeiling.percent).toBeNull()

    const noCeiling = spendTileState({ ...args, spend: spend({ spendCountable: false }) })
    expect(noCeiling.value).toBe('Not measured')
    expect(noCeiling.note).toBe('Provider bills by subscription, not per token')
  })

  it('does not tell an operator to configure pricing when pricing cannot help', () => {
    const state = spendTileState({
      ...args,
      spend: spend({ spendCountable: false, pricingConfigured: false }),
    })
    expect(state.note).not.toMatch(/model pricing/i)
  })

  it('names the missing price table only where a price table is what is missing', () => {
    const state = spendTileState({
      ...args,
      spend: spend({ pricingConfigured: false, dailySpendCeilingUsd: 10 }),
    })
    expect(state.value).toBe('Not measured')
    expect(state.note).toBe('$10.00 ceiling needs model pricing to apply')
    expect(state.percent).toBeNull()
  })

  it('states that a breached ceiling actually stopped something', () => {
    const state = spendTileState({
      ...args,
      spend: spend({
        todaySpendUsd: 10,
        dailySpendCeilingUsd: 10,
        ceilingEnforceable: true,
        ceilingBreached: true,
      }),
    })
    expect(state.note).toMatch(/automatic investigation paused/)
  })

  it('keeps the restricted, loading and failed-request states distinct from "not measured"', () => {
    expect(spendTileState({ canReadSpend: false, isLoading: false, spend: undefined }).value).toBe('Restricted')
    expect(spendTileState({ canReadSpend: true, isLoading: true, spend: undefined }).value).toBe('…')
    // A failed request is no evidence about the org's pricing table.
    const failed = spendTileState({ canReadSpend: true, isLoading: false, spend: undefined })
    expect(failed.value).toBe('—')
    expect(failed.note).toBe('Spend data unavailable')
  })
})
