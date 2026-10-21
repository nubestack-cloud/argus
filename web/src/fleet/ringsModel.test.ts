import { describe, expect, it } from 'vitest'
import { readCapacity } from './clusterOverviewModel'
import { podsRing, resourceRows, workloadsRing } from './ringsModel'

describe('rings', () => {
  it('never draws a zero for an unreported kind', () => {
    expect(podsRing(undefined)).toMatchObject({ total: null, absence: 'unknown' })
    expect(podsRing({ unavailable: ['pods'] })).toMatchObject({ total: null, absence: 'unavailable' })
    expect(podsRing({ syncing: true })).toMatchObject({ total: null, absence: 'syncing' })
    expect(workloadsRing({ syncing: true })).toMatchObject({ total: null, absence: 'syncing' })
  })

  it('marks the workload ring partial when a kind could not be listed, and names it', () => {
    const r = workloadsRing({ deployments: { total: 4, ready: 3, notReady: 1, scaledToZero: 0 }, unavailable: ['statefulsets', 'daemonsets'] })
    expect(r.total).toBe(4)
    expect(r.partial).toBe(true)
    expect(r.notes).toContain('StatefulSets, DaemonSets not visible to the agent')
  })
})

describe('resource rows', () => {
  it('rejects a malformed capacity rather than reading it as zero', () => {
    expect(readCapacity({ capacity: { cpuRequestedMillicores: 1 } } as never)).toBeNull()
    const rows = resourceRows(null, null)
    expect(rows.map((r) => r.figure)).toEqual(['—', '—', '—', '—'])
    expect(rows[1].note).toMatch(/Not reported by this agent/)
  })
})

