import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { QueryClient } from '@tanstack/react-query'
import type { LiveEvent } from '../api/types'
import { createEventInvalidator, EVENT_REFRESHES, LIVE_FALLBACK_MS, SLOW_FALLBACK_MS, STATIC_POLL_MS, CLOCK_POLL_MS } from './refresh'

// PROJECT.md P16 moved every screen's refresh from a 5-10s poll onto the live
// event stream, with the poll kept as a 60-120s safety net. That makes this
// module the thing standing between "the hub changed something" and "the
// screen shows it" — so the coalescing and throttling below are pinned rather
// than eyeballed: a bug here is a permanently stale screen with a fast poll no
// longer covering for it.

function fakeClient() {
  const invalidateQueries = vi.fn()
  return { client: { invalidateQueries } as unknown as QueryClient, invalidateQueries }
}

function incidentEvent(): LiveEvent {
  return { type: 'IncidentUpdated', incidentId: 'inc_1', clusterId: 'cl_1', occurredAt: '2026-09-23T10:00:00Z' }
}

function keysInvalidated(mock: ReturnType<typeof vi.fn>): string[] {
  return mock.mock.calls.map((call) => JSON.stringify((call[0] as { queryKey: unknown[] }).queryKey))
}

describe('createEventInvalidator', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it('coalesces a burst of events into one invalidation per key', () => {
    const { client, invalidateQueries } = fakeClient()
    const invalidator = createEventInvalidator(client)

    // One broken workload legitimately emits several findings from several
    // detectors, and the sweepers publish per incident — events arrive in
    // clumps, and a clump must not become a clump of refetches.
    for (let i = 0; i < 20; i++) invalidator.handle(incidentEvent())
    expect(invalidateQueries).not.toHaveBeenCalled()

    vi.advanceTimersByTime(300)
    const keys = keysInvalidated(invalidateQueries)
    expect(keys).toEqual([...new Set(keys)])
    expect(keys).toContain(JSON.stringify(['incidents']))
    expect(keys).toContain(JSON.stringify(['approvals']))
    expect(keys.length).toBe(EVENT_REFRESHES.IncidentUpdated.length)
    invalidator.dispose()
  })

  it('refreshes promptly on the first event after a quiet period', () => {
    const { client, invalidateQueries } = fakeClient()
    const invalidator = createEventInvalidator(client)

    invalidator.handle(incidentEvent())
    vi.advanceTimersByTime(300)
    // Well under the old 5s tick: the point of the change is that an event
    // beats the poll it replaced, not merely that it costs less.
    expect(keysInvalidated(invalidateQueries)).toContain(JSON.stringify(['incidents']))
    invalidator.dispose()
  })

  it('holds an expensive aggregate to one refresh per throttle window, and still fires at the end of it', () => {
    const { client, invalidateQueries } = fakeClient()
    const invalidator = createEventInvalidator(client)
    const insights = JSON.stringify(['insights'])

    invalidator.handle(incidentEvent())
    vi.advanceTimersByTime(300)
    expect(keysInvalidated(invalidateQueries).filter((k) => k === insights)).toHaveLength(1)

    // A steady stream through the window must not schedule a refresh per
    // event — getInsights is five aggregate GROUP BYs over the whole tenant.
    for (let i = 0; i < 10; i++) {
      invalidator.handle(incidentEvent())
      vi.advanceTimersByTime(1000)
    }
    expect(keysInvalidated(invalidateQueries).filter((k) => k === insights)).toHaveLength(1)
    // ...but the change is not dropped either: one refresh lands once the
    // window closes.
    vi.advanceTimersByTime(30_000)
    expect(keysInvalidated(invalidateQueries).filter((k) => k === insights)).toHaveLength(2)

    // The un-throttled keys kept up throughout, which is the whole reason
    // the throttle is per key rather than global: the incident list stayed
    // current while the reporting aggregate was held back.
    const incidents = JSON.stringify(['incidents'])
    expect(keysInvalidated(invalidateQueries).filter((k) => k === incidents).length).toBeGreaterThan(2)
    invalidator.dispose()
  })

  it('routes a cluster event only to cluster queries', () => {
    const { client, invalidateQueries } = fakeClient()
    const invalidator = createEventInvalidator(client)
    invalidator.handle({ type: 'ClusterUpdated', clusterId: 'cl_1', occurredAt: '2026-09-23T10:00:00Z' })
    vi.advanceTimersByTime(300)
    expect(keysInvalidated(invalidateQueries)).toEqual([JSON.stringify(['clusters'])])
    invalidator.dispose()
  })

  it('routes a finding-recorded event only to the findings query (PROJECT.md F31)', () => {
    const { client, invalidateQueries } = fakeClient()
    const invalidator = createEventInvalidator(client)
    // The whole point of this event: a suppressed/retained finding touches no
    // incident, so it must reach ['findings'] without depending on
    // IncidentUpdated at all.
    invalidator.handle({ type: 'FindingRecorded', clusterId: 'cl_1', occurredAt: '2026-09-23T10:00:00Z' })
    vi.advanceTimersByTime(300)
    expect(keysInvalidated(invalidateQueries)).toEqual([JSON.stringify(['findings'])])
    invalidator.dispose()
  })

  it('ignores an event type it has no route for instead of throwing', () => {
    const { client, invalidateQueries } = fakeClient()
    const invalidator = createEventInvalidator(client)
    // A malformed or future message must not take down the socket's message
    // handler — useLiveEvents catches parse errors, not routing ones.
    expect(() => invalidator.handle({ type: 'SomethingNew' } as unknown as LiveEvent)).not.toThrow()
    vi.advanceTimersByTime(1000)
    expect(invalidateQueries).not.toHaveBeenCalled()
    invalidator.dispose()
  })

  it('cancels pending work on dispose, so a closed socket cannot refetch later', () => {
    const { client, invalidateQueries } = fakeClient()
    const invalidator = createEventInvalidator(client)
    invalidator.handle(incidentEvent())
    invalidator.dispose()
    vi.advanceTimersByTime(60_000)
    expect(invalidateQueries).not.toHaveBeenCalled()
  })
})

describe('the fallback intervals stay inside the safety-net band', () => {
  // PROJECT.md P16's acceptance is a band, not a number: short enough that a
  // missed event is corrected within a minute or two, long enough that an idle
  // tab is not a standing database load. A future edit that quietly puts a 5s
  // tick back is the regression this guards.
  it('keeps every event-backed interval between 60s and 120s', () => {
    for (const ms of [LIVE_FALLBACK_MS, SLOW_FALLBACK_MS, STATIC_POLL_MS, CLOCK_POLL_MS]) {
      expect(ms).toBeGreaterThanOrEqual(60_000)
      expect(ms).toBeLessThanOrEqual(120_000)
    }
  })
})
