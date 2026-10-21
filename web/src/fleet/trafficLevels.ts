// Traffic helpers shared by an incident's Traffic tab (TrafficDependencies)
// and the Network policy tab's comparison with observed traffic: one measure
// per view, figures now and in the earlier window, and one workload's callers
// and callees. Node and host traffic (kubelet probes, the host network) has
// no namespace and is recognised here.
import { errorPercent, formatBytesRate, formatRate, type TrafficEndpoint, type TrafficFlow } from './trafficModel'

/** A node or the host network: Beyla reports both with no namespace. */
export function isHostEndpoint(e: TrafficEndpoint): boolean {
  return !e.namespace
}

export function isHostFlow(f: TrafficFlow): boolean {
  return isHostEndpoint(f.src) || isHostEndpoint(f.dst)
}

/** What a view ranks and compares by: bytes where the source measured them
 *  (every Beyla and Hubble flow), else requests (Istio HTTP), else
 *  connections. One measure per view, so no row compares unlike units. */
export type Measure = 'bytes' | 'requests' | 'connections'

export function measureOf(flows: readonly TrafficFlow[]): Measure {
  if (flows.some((f) => f.bytesRate != null || f.before?.bytesRate != null)) return 'bytes'
  if (flows.some((f) => f.requestRate != null || f.before?.requestRate != null)) return 'requests'
  return 'connections'
}

type RateFields = Pick<TrafficFlow, 'bytesRate' | 'requestRate' | 'connectionRate'>

function pick(r: RateFields | null | undefined, m: Measure): number | null {
  if (!r) return null
  const v = m === 'bytes' ? r.bytesRate : m === 'requests' ? r.requestRate : r.connectionRate
  return v ?? null
}

/** The flow's figure now; null for a stopped flow or one not measured. */
export function amount(f: TrafficFlow, m: Measure): number | null {
  return f.stopped ? null : pick(f, m)
}

/** The flow's figure in the comparison window. */
export function beforeAmount(f: TrafficFlow, m: Measure): number | null {
  return pick(f.before, m)
}

export function formatAmount(v: number, m: Measure): string {
  return m === 'bytes' ? formatBytesRate(v) : m === 'requests' ? `${formatRate(v)} req/s` : `${formatRate(v)} conn/s`
}

/** "an hour ago", "a day ago", "3 hours ago". */
export function agoWords(seconds: number | undefined): string {
  if (!seconds) return 'earlier'
  const h = seconds / 3600
  if (h === 1) return 'an hour ago'
  if (h === 24) return 'a day ago'
  return h < 24 ? `${formatRate(h)} hours ago` : `${formatRate(h / 24)} days ago`
}

/** "↓70%", "↑3.2×", or null when the two cannot be compared. */
export function changeWords(now: number | null, before: number | null): string | null {
  if (now == null || before == null || before === 0) return null
  const r = now / before
  if (r >= 2) return `↑${formatRate(r)}×`
  const pct = Math.round((r - 1) * 100)
  if (pct === 0) return 'no change'
  return pct > 0 ? `↑${pct}%` : `↓${-pct}%`
}

export interface Neighbour {
  peer: TrafficEndpoint
  flow: TrafficFlow
  now: number | null
  before: number | null
  problem: boolean
}

/** Traffic into and out of one workload: who calls it (whose requests may be
 *  failing because of it) and what it calls (a dependency that may be the
 *  cause). Failing first, then busiest; stopped flows are kept, since a
 *  caller that went quiet is the point. */
export function flowsAround(flows: readonly TrafficFlow[], ns: string, name: string): { callers: Neighbour[]; callees: Neighbour[]; measure: Measure } {
  const m = measureOf(flows)
  const is = (e: TrafficEndpoint) => e.namespace === ns && e.name === name
  const row = (peer: TrafficEndpoint, f: TrafficFlow): Neighbour => ({ peer, flow: f, now: amount(f, m), before: beforeAmount(f, m), problem: (f.errorRate ?? 0) > 0 })
  const order = (a: Neighbour, b: Neighbour) => Number(b.problem) - Number(a.problem) || Math.max(b.now ?? 0, b.before ?? 0) - Math.max(a.now ?? 0, a.before ?? 0)
  // One row per peer and side, however many flows describe it (a directed
  // flow and an undirected one between the same pair, several ports).
  const merge = (rows: Neighbour[]): Neighbour[] => {
    const by = new Map<string, Neighbour>()
    const plus = (x: number | null, y: number | null) => (x == null ? y : y == null ? x : x + y)
    for (const r of rows) {
      const k = `${r.peer.namespace ?? ''}/${r.peer.name}`
      const prev = by.get(k)
      if (!prev) {
        by.set(k, r)
        continue
      }
      const stopped = !!prev.flow.stopped && !!r.flow.stopped
      const big = (prev.now ?? prev.before ?? 0) >= (r.now ?? r.before ?? 0) ? prev : r
      by.set(k, {
        peer: prev.peer,
        flow: { ...big.flow, stopped, directionUnknown: !!prev.flow.directionUnknown && !!r.flow.directionUnknown, before: plus(prev.before, r.before) == null ? null : big.flow.before },
        now: plus(prev.now, r.now),
        before: plus(prev.before, r.before),
        problem: prev.problem || r.problem,
      })
    }
    return [...by.values()]
  }
  const callers: Neighbour[] = []
  const callees: Neighbour[] = []
  for (const f of flows) {
    if (is(f.src) && is(f.dst)) continue
    if (is(f.dst)) callers.push(row(f.src, f))
    else if (is(f.src)) (f.directionUnknown ? callers : callees).push(row(f.dst, f))
  }
  return { callers: merge(callers).sort(order), callees: merge(callees).sort(order), measure: m }
}

/** The 5xx share as words, where measured. */
export function errorWords(f: TrafficFlow): string | null {
  const pct = errorPercent(f)
  return pct == null ? null : `${formatRate(pct)}% 5xx`
}
