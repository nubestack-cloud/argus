import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { QueryClient } from '@tanstack/react-query'
import type { Incident } from '../api/types'
import { createIncidentPatcher, isIncidentListKey, patchIncidentLists, patchListData } from './incidentPatch'
import { clearFresh } from './freshRows'
import { createEventInvalidator } from './refresh'

// CI-U8: an IncidentUpdated event patches the one incident into the cached
// lists instead of refetching them, and falls back to a refetch whenever a
// patch cannot place the row honestly.

const row = (id: string, over: Partial<Incident> = {}) => ({ id, state: 'Detected', severity: 'high', occurrenceCount: 1, ...over }) as unknown as Incident

describe('patching incident lists', () => {
  afterEach(() => clearFresh())

  it('recognises list keys, not detail keys', () => {
    expect(isIncidentListKey(['incidents'])).toBe(true)
    expect(isIncidentListKey(['incidents', { clusterId: 'c' }])).toBe(true)
    expect(isIncidentListKey(['incidents', 'inc_1'])).toBe(false)
    expect(isIncidentListKey(['incidents', 'inc_1', 'timeline'])).toBe(false)
  })

  it('replaces only the fields the list row already carries, keeping position', () => {
    const data = { incidents: [row('a'), row('b'), row('c')] }
    const next = patchListData(data, { ...row('b', { occurrenceCount: 9 }), findings: ['big'] } as unknown as Incident)!
    expect(next.incidents.map((r) => r.id)).toEqual(['a', 'b', 'c'])
    expect(next.incidents[1].occurrenceCount).toBe(9)
    expect('findings' in next.incidents[1]).toBe(false)
    expect(patchListData(data, row('zzz'))).toBeNull()
  })

  it('patches every cached list holding the incident and invalidates a state-filtered list it left', () => {
    const qc = new QueryClient()
    qc.setQueryData(['incidents', { sortKey: 'lastSeen' }], { incidents: [row('a'), row('b')] })
    qc.setQueryData(['incidents', { state: 'Detected' }], { incidents: [row('b')] })
    qc.setQueryData(['incidents', 'b'], { id: 'b', detail: true })
    const inv = vi.spyOn(qc, 'invalidateQueries')
    const r = patchIncidentLists(qc, row('b', { state: 'Resolved' }))
    expect(r).toEqual({ found: true, patched: 1 })
    expect((qc.getQueryData(['incidents', { sortKey: 'lastSeen' }]) as { incidents: Incident[] }).incidents[1].state).toBe('Resolved')
    expect(inv).toHaveBeenCalledWith({ queryKey: ['incidents', { state: 'Detected' }], exact: true })
    expect(qc.getQueryData(['incidents', 'b'])).toEqual({ id: 'b', detail: true })
  })

  it('reports not-found for a new incident and a failed fetch', async () => {
    const qc = new QueryClient()
    qc.setQueryData(['incidents'], { incidents: [row('a')] })
    expect(await createIncidentPatcher(qc, async () => row('new'))('new')).toBe(false)
    expect(await createIncidentPatcher(qc, async () => { throw new Error('x') })('a')).toBe(false)
    expect(await createIncidentPatcher(qc, async () => row('a', { occurrenceCount: 3 }))('a')).toBe(true)
  })
})

describe('the invalidator with a patcher', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  const event = (incidentId?: string) => ({ type: 'IncidentUpdated' as const, incidentId, occurredAt: '2026-10-10T00:00:00Z' })

  it('patches instead of invalidating the lists, once per incident per burst', async () => {
    const invalidateQueries = vi.fn()
    const patch = vi.fn().mockResolvedValue(true)
    const inv = createEventInvalidator({ invalidateQueries } as unknown as QueryClient, { patchIncident: patch })
    for (let i = 0; i < 5; i++) inv.handle(event('inc_1'))
    await vi.advanceTimersByTimeAsync(300)
    expect(patch).toHaveBeenCalledTimes(1)
    const keys = invalidateQueries.mock.calls.map((c) => JSON.stringify(c[0].queryKey))
    expect(keys).not.toContain(JSON.stringify(['incidents']))
    expect(keys).toContain(JSON.stringify(['approvals']))
    inv.dispose()
  })

  it('falls back to invalidating the lists when a patch cannot place the row', async () => {
    const invalidateQueries = vi.fn()
    const inv = createEventInvalidator({ invalidateQueries } as unknown as QueryClient, { patchIncident: vi.fn().mockResolvedValue(false) })
    inv.handle(event('inc_new'))
    await vi.advanceTimersByTimeAsync(300)
    expect(invalidateQueries.mock.calls.map((c) => JSON.stringify(c[0].queryKey))).toContain(JSON.stringify(['incidents']))
    inv.dispose()
  })

  it('invalidates as before for an event without an incident id', async () => {
    const invalidateQueries = vi.fn()
    const patch = vi.fn()
    const inv = createEventInvalidator({ invalidateQueries } as unknown as QueryClient, { patchIncident: patch })
    inv.handle(event(undefined))
    await vi.advanceTimersByTimeAsync(300)
    expect(patch).not.toHaveBeenCalled()
    expect(invalidateQueries.mock.calls.map((c) => JSON.stringify(c[0].queryKey))).toContain(JSON.stringify(['incidents']))
    inv.dispose()
  })
})
