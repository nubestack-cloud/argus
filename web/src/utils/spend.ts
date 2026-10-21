import type { SpendToday } from '../api/types'

// spendTileState is the fleet overview's Spend-today tile: its three rendered
// facts — the figure, its caveat line, and whether the ceiling progress bar has
// anything to draw.
//
// Extracted from OverviewPage so it can be tested and so that page exports
// only components — the same reason and the same shape as utils/donut.ts.
// OverviewPage wires seven queries and is not rendered by its own test file
// (OverviewPage.test.tsx: test the exported piece, not the page), and "the
// spend tile stopped claiming a working ceiling" is exactly the kind of
// assertion that a reordered condition breaks silently.
//
// PROJECT.md T8. Three things this used to get wrong, all of them the same
// mistake — treating a configured price table as proof that spend is
// measurable:
//
//  1. `$0.00` under a subscription-billed provider. todaySpendUsd sums only
//     cost_basis='metered' rows, so on that provider it is zero while real
//     investigations ran. anti-patterns.md: a missing cost renders '—', never
//     $0.00. 'Not measured' is the idiom this codebase already uses for it.
//  2. "of $10.00 daily ceiling", which reads as a ceiling in force. On that
//     provider the ceiling cannot be reached however low it is set, because
//     the sum it checks cannot grow from real activity.
//  3. A progress bar. At 0% it asserts "0% of the ceiling consumed" — a
//     measurement, drawn from a number that measures nothing. A mark that
//     encodes nothing goes (SKILL.md's decoration test).
//
// spendCountable is checked BEFORE pricingConfigured throughout: when the
// provider's spend is not countable, configuring a price table does not change
// any of the three, so 'Configure model pricing to track cost' would send an
// operator to do work that cannot help.
export function spendTileState({ canReadSpend, isLoading, spend }: {
  canReadSpend: boolean
  isLoading: boolean
  spend: SpendToday | undefined
}): { value: string; note: string; percent: number | null } {
  if (!canReadSpend) return { value: 'Restricted', note: 'Requires spend access', percent: null }
  if (isLoading) return { value: '…', note: 'Checking today’s spend…', percent: null }
  // No response to read: GET /spend/today failed. "Not configured" (what this
  // used to fall through to) is a claim about the org's pricing table that a
  // failed request is no evidence for at all — pricing may well be configured
  // — and it directly contradicted this tile's own sub-label, "Spend data
  // unavailable". '—' matches every other unknown value on this page: unknown,
  // stated as unknown.
  if (spend == null) return { value: '—', note: 'Spend data unavailable', percent: null }

  const ceiling = spend.dailySpendCeilingUsd

  if (!spend.spendCountable) {
    return {
      value: 'Not measured',
      note:
        ceiling != null
          ? `$${ceiling.toFixed(2)} ceiling cannot be enforced`
          : 'Provider bills by subscription, not per token',
      percent: null,
    }
  }
  if (!spend.pricingConfigured) {
    return {
      value: 'Not measured',
      note:
        ceiling != null
          ? `$${ceiling.toFixed(2)} ceiling needs model pricing to apply`
          : 'Configure model pricing to track cost',
      percent: null,
    }
  }
  return {
    value: `$${spend.todaySpendUsd.toFixed(2)}`,
    note:
      ceiling == null
        ? 'No daily ceiling set'
        : spend.ceilingBreached
          ? `at the $${ceiling.toFixed(2)} daily ceiling — automatic investigation paused`
          : `of $${ceiling.toFixed(2)} daily ceiling`,
    // Only drawn where the ceiling is a control that can fire, and only where
    // there is something to divide by.
    percent:
      spend.ceilingEnforceable && ceiling != null && ceiling > 0
        ? Math.min(100, (spend.todaySpendUsd / ceiling) * 100)
        : null,
  }
}
