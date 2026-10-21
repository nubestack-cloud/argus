import { describe, expect, it } from 'vitest'
import type { Cluster, FleetPostureSummary } from '../api/types'
import type { CheckStatus, FleetChecks } from './useFleetData'
import { ladderSummary, postureSummary } from './summaries'
import type { LadderRow } from './model'

const row = (name: string, target: string | null, verdict: string | null): LadderRow => ({
  clusterId: name,
  name,
  current: '1.29',
  target,
  verdict,
  scannedAt: null,
})

describe('ladderSummary', () => {
  it('counts each rung in the design order, a warning as review, and unscanned clusters apart', () => {
    const rows = [
      row('a', '1.30', 'blocked'),
      row('b', '1.30', 'blocked'),
      row('c', '1.30', 'warning'),
      row('d', '1.30', 'no_known_blockers'),
      row('e', null, null),
    ]
    expect(ladderSummary(rows)).toBe('2 blocked · 1 review · 1 ready · 1 not scanned')
  })

  it('says nothing for an empty fleet rather than a row of zeros', () => {
    expect(ladderSummary([])).toBeNull()
  })
})

describe('postureSummary', () => {
  const cl = (id: string) => ({ id, displayName: id }) as Cluster
  const unread = (): CheckStatus<FleetPostureSummary> => ({ kind: 'unread' })
  const checksWith = (posture: Record<string, CheckStatus<FleetPostureSummary>>): FleetChecks => ({
    certificates: () => ({ kind: 'unread' }),
    posture: (id) => posture[id] ?? unread(),
    helm: () => ({ kind: 'unread' }),
    gitops: () => ({ kind: 'unread' }),
  })
  const answered = (danger: number, warning: number): CheckStatus<FleetPostureSummary> => ({
    kind: 'ok',
    at: '2026-10-12T12:00:00Z',
    failedSince: null,
    failure: null,
    // The agent's own top-level totals include categories the heatmap does
    // not draw; the header sums the drawn ones so the two always agree.
    summary: { danger: 99, warning: 99, categories: { Security: { danger, warning, passing: 0 } } },
  })

  it('sums only the clusters that have been read, over the drawn categories', () => {
    expect(postureSummary([cl('a'), cl('b')], checksWith({ a: answered(3, 10) }))).toBe('3 danger · 10 warning')
  })

  it('is null, not "0 danger", while nothing has been read', () => {
    expect(postureSummary([cl('a')], checksWith({}))).toBeNull()
  })
})
