import type { QueryClient } from '@tanstack/react-query'
import type { LiveEvent } from '../api/types'

// The refresh policy for every screen's server data, in one place: which live
// event (internal/events' bus, delivered over /ws/events) refreshes which
// TanStack query, and how slowly the fallback poll underneath it runs.
//
// PROJECT.md P16. Every page used to carry its own `refetchInterval` at
// 5s/10s/30s, on top of the WebSocket that exists to make exactly that
// unnecessary: an idle tab on /overview alone issued a request every ~1.5s,
// each one a scoped Postgres transaction (internal/api/middleware.go opens one
// in requireAuth for every authenticated read), so ten operators watching a
// quiet fleet cost the database ~120 transactions a minute to be told nothing
// had changed. The event stream already knows when something changed.
//
// So the order is inverted: the event is the primary refresh mechanism and the
// interval is a safety net for the case the stream cannot cover — a WS-hostile
// proxy, a hub restart that dropped an event mid-flight (internal/events' bus
// is in-process memory and says so), or a second hub replica, which is the
// exact reason useLiveEvents' own note insists polling stays. It stays; it just
// stops being what the app relies on.

// --- Fallback poll intervals -------------------------------------------------
//
// Four names, two values. The names are the point: they record WHY a given
// query polls at the rate it does, so the next person changing one knows
// whether an event backs it.

/** An event drives this query; the poll only covers a missed/undelivered one. */
export const LIVE_FALLBACK_MS = 60_000

/**
 * As LIVE_FALLBACK_MS, but for queries whose answer is an aggregate or a
 * standing figure rather than a live queue — nobody watches these change.
 */
export const SLOW_FALLBACK_MS = 120_000

/**
 * No event can exist: the value changes with the wall clock, server-side, with
 * nothing happening for anything to publish. Kept short deliberately.
 */
export const CLOCK_POLL_MS = 60_000

/**
 * No event exists, and the data only changes when a person edits it — whoever
 * edits it in this tab invalidates the query directly, so the poll is only for
 * a second operator working at the same time.
 */
export const STATIC_POLL_MS = 120_000

// --- Event → query routing ---------------------------------------------------

/**
 * How long a burst of events is allowed to accumulate before one invalidation
 * is issued for the keys it touched. One broken workload emits several findings
 * from several detectors (see migration 000036's correlation note), and the
 * hub's sweepers publish per incident, so an event arrives in clumps — without
 * this, a clump of twenty would mean twenty identical refetches.
 */
const COALESCE_MS = 250

/**
 * The floor between two refreshes of an expensive query. getInsights is five
 * aggregate GROUP BYs over every incident/finding/analysis this tenant has
 * ever had; running it on every incident event would trade P16's problem for a
 * worse one. 30s is the interval these queries already polled at, so being
 * event-driven can only reduce their request count, never increase it.
 */
const AGGREGATE_MIN_INTERVAL_MS = 30_000

type Refresh = {
  queryKey: readonly unknown[]
  /** Minimum gap between two invalidations of this key. Defaults to COALESCE_MS. */
  minIntervalMs?: number
}

/**
 * The map from an event type to the query keys it makes stale. Prefix keys:
 * TanStack matches `['incidents']` against `['incidents', id]` and
 * `['incidents', {...filters}]` too, which is why one entry covers the list,
 * the detail page and every filtered variant.
 *
 * A key belongs here only if the event genuinely implies it changed. Where the
 * link is indirect it is stated at the entry, because "it seemed related" is
 * how a screen ends up silently relying on an event nobody publishes.
 */
export const EVENT_REFRESHES: Record<LiveEvent['type'], readonly Refresh[]> = {
  // Published by every path that changes an incident: finding correlation
  // (internal/gateway/finding.go), analysis (internal/api/analyze.go,
  // internal/autoanalyze), approve/reject (internal/api/approvals.go),
  // execution and its reconciler, rollback, triage, tolerations, the merge and
  // validation sweepers, and the unattended executor. Grep `events.IncidentUpdated`.
  IncidentUpdated: [
    { queryKey: ['incidents'] },
    { queryKey: ['incidentsDigest'] },
    { queryKey: ['incident-counts'] },
    // An approval appears, is decided, or expires only as part of an incident
    // state change, so every approval-queue mutation publishes this event.
    { queryKey: ['approvals'] },
    // A row in Recent changes is written when an approval opens a pull request
    // (approvals.go) or the merge sweeper commits one (orchestrator/mergewatch.go);
    // both publish.
    { queryKey: ['changes'] },
    // Indirect but reliable: a breaker only ever trips on a remediation outcome
    // (orchestrator/breaker.go is evaluated from the execution paths), and every
    // one of those publishes. Throttled because it is a card, not a queue.
    { queryKey: ['circuit-breaker'], minIntervalMs: AGGREGATE_MIN_INTERVAL_MS },
    // Spend accrues when an analysis is persisted, which publishes.
    { queryKey: ['spend-today'], minIntervalMs: AGGREGATE_MIN_INTERVAL_MS },
    { queryKey: ['insights'], minIntervalMs: AGGREGATE_MIN_INTERVAL_MS },
    { queryKey: ['insights-remediation-quality'], minIntervalMs: AGGREGATE_MIN_INTERVAL_MS },
  ],
  // Published on accept, decommission, health-monitor demotion, and
  // heartbeat-driven recovery (internal/gateway/health.go, server.go,
  // internal/api/clusters.go).
  ClusterUpdated: [{ queryKey: ['clusters'] }],
  // PROJECT.md F31. Published for EVERY finding handleFinding durably
  // records — including the two thirds of them IncidentUpdated never
  // covers (retained_unpromoted, suppressed) — so SignalsPage is the one
  // screen this belongs to. See internal/events.FindingRecorded's own doc
  // comment for why it exists as a second, lighter event rather than
  // widening IncidentUpdated's own meaning.
  FindingRecorded: [{ queryKey: ['findings'] }],
}

export type EventInvalidator = {
  handle(event: LiveEvent): void
  dispose(): void
}

/**
 * Builds the coalescing, throttling invalidator useLiveEvents feeds every
 * received event into.
 *
 * Leading-edge with a trailing throttle: the first event after a quiet period
 * invalidates almost immediately (COALESCE_MS later, so the rest of its clump
 * rides along), and anything arriving inside a key's minimum interval is folded
 * into one invalidation at the end of it. A key never has more than one timer
 * outstanding, so an event storm cannot schedule unbounded work.
 *
 * `invalidateQueries` refetches only queries with an active observer and marks
 * the rest stale, so this never issues a request for a screen nobody is
 * looking at.
 */
/**
 * Beyond this many distinct incidents in one coalescing window, one list
 * refetch is cheaper than a fetch per incident, so the patcher steps aside.
 */
const MAX_PATCHES_PER_BURST = 10

export interface EventInvalidatorOptions {
  /**
   * CI-U8. When given, IncidentUpdated for a known incident id patches that
   * one incident into the cached lists (realtime/incidentPatch.ts) instead of
   * invalidating every ['incidents'] list. Resolves false when the lists
   * still need a refetch (a new incident, or the fetch failed), and the
   * invalidator then does exactly what it did without a patcher.
   */
  patchIncident?: (incidentId: string) => Promise<boolean>
}

export function createEventInvalidator(queryClient: QueryClient, options: EventInvalidatorOptions = {}): EventInvalidator {
  const timers = new Map<string, ReturnType<typeof setTimeout>>()
  const lastRunAt = new Map<string, number>()
  const { patchIncident } = options
  // Incident ids waiting for their patch, collected over one COALESCE_MS
  // window so a burst of events for one incident is one fetch.
  const pendingPatches = new Set<string>()
  let patchTimer: ReturnType<typeof setTimeout> | null = null

  function invalidateLists() {
    void queryClient.invalidateQueries({ queryKey: ['incidents'] })
  }

  function flushPatches() {
    patchTimer = null
    const ids = [...pendingPatches]
    pendingPatches.clear()
    if (!patchIncident || ids.length > MAX_PATCHES_PER_BURST) {
      invalidateLists()
      return
    }
    void Promise.all(ids.map((id) => patchIncident(id).catch(() => false))).then((results) => {
      if (results.some((ok) => !ok)) invalidateLists()
    })
  }

  function fire(id: string, queryKey: readonly unknown[]) {
    timers.delete(id)
    lastRunAt.set(id, Date.now())
    void queryClient.invalidateQueries({ queryKey })
  }

  return {
    handle(event: LiveEvent) {
      const patching = !!patchIncident && event.type === 'IncidentUpdated' && !!event.incidentId
      if (patching) {
        pendingPatches.add(event.incidentId!)
        if (!patchTimer) patchTimer = setTimeout(flushPatches, COALESCE_MS)
      }
      for (const refresh of EVENT_REFRESHES[event.type] ?? []) {
        // The lists are the patcher's job for this event (see flushPatches).
        if (patching && refresh.queryKey.length === 1 && refresh.queryKey[0] === 'incidents') continue
        const id = JSON.stringify(refresh.queryKey)
        // Already scheduled: this event is folded into that pending run rather
        // than resetting it. Resetting would let a steady event stream starve
        // the refresh it is supposed to trigger.
        if (timers.has(id)) continue
        const last = lastRunAt.get(id)
        const sinceLast = last === undefined ? Number.POSITIVE_INFINITY : Date.now() - last
        const delay = Math.max(COALESCE_MS, (refresh.minIntervalMs ?? COALESCE_MS) - sinceLast)
        timers.set(
          id,
          setTimeout(() => fire(id, refresh.queryKey), delay),
        )
      }
    },
    dispose() {
      for (const timer of timers.values()) clearTimeout(timer)
      timers.clear()
      if (patchTimer) clearTimeout(patchTimer)
      patchTimer = null
      pendingPatches.clear()
    },
  }
}
