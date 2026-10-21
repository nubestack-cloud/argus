import { describe, expect, it } from 'vitest'
import { lifecycleSteps } from './incidentLifecycle'
import type { IncidentDetail } from '../api/types'

function incident(state: string, analysis: unknown = null): IncidentDetail {
  return { id: 'inc_1', state, analysis, findings: [], firstSeen: '2026-10-01T00:00:00Z' } as unknown as IncidentDetail
}

// Live QA, 2026-10-11: the Analysis step said "not run" for the whole of a run
// that was visibly under way.
describe('lifecycleSteps — the Analysis step while an analysis runs', () => {
  it('says running when the incident is Investigating', () => {
    expect(lifecycleSteps(incident('Investigating'))[1].meta).toBe('running')
  })

  it('says running when this tab has just started one', () => {
    expect(lifecycleSteps(incident('Detected'), true)[1].meta).toBe('running')
  })

  it('still says not run when nothing has run and nothing is running', () => {
    expect(lifecycleSteps(incident('Detected'))[1].meta).toBe('not run')
  })
})
