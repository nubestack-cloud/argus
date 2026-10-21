// The cluster Overview's top row as the owner chose it (2026-10-11, after
// trying a "health ledger" in its place): three rings — Pods, Workloads,
// Nodes — each with its breakdown in words under it, and the Resource use
// card's used and requested rows against allocatable. Restored verbatim from
// the committed version so the figures and their honesty rules are unchanged:
// a count the agent did not report is "—" with the reason, never 0; a ring
// over a partial set says so; requested comes only from summary.capacity.

import type { Absence, CapacitySummary } from './clusterOverviewModel'
import { countAbsence, type ClusterSummary, type CountKey, type ResourceCounts } from './clusterSummary'
import type { UsageRollup } from './resourceUsage'

export type RingTone = 'ok' | 'warn' | 'bad' | 'info' | 'neutral'
export type RingGlyph = 'check' | 'half' | 'circle' | 'cross' | 'dot'

export interface RingSegment {
  key: string
  count: number
  /** The word under the ring: "running", "not ready". */
  word: string
  tone: RingTone
  /** Which aria-hidden mark precedes the count in the legend (Ring.tsx
   *  draws it); the word after the count is what carries the state. */
  glyph: RingGlyph
}

export interface RingModel {
  title: string
  /** Null when the agent did not report this kind; `absence` says why. */
  total: number | null
  absence?: Absence
  /** True when the total covers only some of the kinds it sums. */
  partial?: boolean
  segments: RingSegment[]
  /** Facts beside the breakdown that are not slices of it (cordoned nodes,
   *  scaled-to-zero Deployments, the kubelet versions). */
  notes: string[]
}

export function podsRing(counts: ResourceCounts | undefined): RingModel {
  const absence = countAbsence(counts, 'pods')
  const p = counts?.pods
  if (absence !== null || !p) return { title: 'Pods', total: null, absence: absence ?? 'unknown', segments: [], notes: [] }
  const other = Math.max(p.total - p.running - p.pending - p.failed - (p.succeeded ?? 0), 0)
  const segments: RingSegment[] = [
    { key: 'running', count: p.running, word: 'running', tone: 'ok', glyph: 'check' },
    { key: 'pending', count: p.pending, word: 'pending', tone: 'warn', glyph: 'half' },
    { key: 'succeeded', count: p.succeeded ?? 0, word: 'completed', tone: 'info', glyph: 'circle' },
    { key: 'failed', count: p.failed, word: 'failed', tone: 'bad', glyph: 'cross' },
  ]
  if (other > 0) segments.push({ key: 'other', count: other, word: 'other phase', tone: 'neutral', glyph: 'dot' })
  return { title: 'Pods', total: p.total, segments, notes: [] }
}

const WORKLOAD_KINDS: [CountKey, string][] = [
  ['deployments', 'Deployments'],
  ['statefulSets', 'StatefulSets'],
  ['daemonSets', 'DaemonSets'],
]

export function workloadsRing(counts: ResourceCounts | undefined): RingModel {
  let total = 0
  let notReady = 0
  const missing: string[] = []
  for (const [key, label] of WORKLOAD_KINDS) {
    const c = counts?.[key] as { total: number; notReady: number } | undefined
    if (c && countAbsence(counts, key) === null) {
      total += c.total
      notReady += c.notReady
    } else missing.push(label)
  }
  if (counts?.syncing) return { title: 'Workloads', total: null, absence: 'syncing', segments: [], notes: [] }
  if (missing.length === WORKLOAD_KINDS.length) {
    const anyUnavailable = WORKLOAD_KINDS.some(([k]) => countAbsence(counts, k) === 'unavailable')
    return { title: 'Workloads', total: null, absence: anyUnavailable ? 'unavailable' : 'unknown', segments: [], notes: [] }
  }
  const notes: string[] = []
  const scaled = counts?.deployments?.scaledToZero
  if (scaled) notes.push(`${scaled} Deployment${scaled === 1 ? '' : 's'} scaled to zero`)
  if (missing.length) notes.push(`${missing.join(', ')} not visible to the agent`)
  return {
    title: 'Workloads',
    total,
    partial: missing.length > 0,
    segments: [
      { key: 'ready', count: total - notReady, word: 'ready', tone: 'ok', glyph: 'check' },
      { key: 'notReady', count: notReady, word: 'not ready', tone: 'bad', glyph: 'cross' },
    ],
    notes,
  }
}

export function nodesRing(summary: ClusterSummary | null): RingModel {
  const counts = summary?.resourceCounts
  const absence = countAbsence(counts, 'nodes')
  const n = counts?.nodes
  if (absence !== null || !n) return { title: 'Nodes', total: null, absence: absence ?? 'unknown', segments: [], notes: [] }
  const notes: string[] = []
  notes.push(`${n.cordoned} cordoned`)
  const skew = summary?.nodeVersionSkew
  if (skew) notes.push(skew.skewed ? `kubelet ${skew.min} – ${skew.max}, mixed minor versions` : `kubelet ${skew.min} on every node`)
  return {
    title: 'Nodes',
    total: n.total,
    segments: [
      { key: 'ready', count: n.ready, word: 'ready', tone: 'ok', glyph: 'check' },
      { key: 'notReady', count: n.notReady, word: 'not ready', tone: 'bad', glyph: 'cross' },
    ],
    notes,
  }
}

// ---------------------------------------------------------------- resource use


export interface UsageRow {
  key: string
  label: string
  /** 0..n ratio, or null when there is nothing honest to draw. */
  ratio: number | null
  /** "2.8 of 20 cores" — or the reason the value is absent. */
  figure: string
  note?: string
}

function num(v: number): string {
  return new Intl.NumberFormat(undefined, { maximumFractionDigits: v >= 10 ? 0 : 1 }).format(v)
}

/** "2.8 of 20 cores" — the unit once, after the pair. */
function coresPair(a: number, b: number): string {
  return `${num(a)} of ${num(b)} ${b === 1 ? 'core' : 'cores'}`
}

function gibPair(a: number, b: number): string {
  return `${num(a / 1024 ** 3)} of ${num(b / 1024 ** 3)} GiB`
}

function coverageNote(u: UsageRollup): string | undefined {
  if (u.reporting === u.total) return undefined
  return `across ${u.reporting} of ${u.total} nodes`
}

/** The Resource use card's four rows: used (metrics-server, per node, summed)
 *  and requested (the agent's pod requests) for CPU and memory. */
export function resourceRows(usage: { cpu: UsageRollup; memory: UsageRollup } | null, capacity: CapacitySummary | null, syncing = false): UsageRow[] {
  type Pair = (a: number, b: number) => string
  const used = (key: string, label: string, u: UsageRollup | undefined, pair: Pair): UsageRow =>
    !u || u.ratio === null
      ? { key, label, ratio: null, figure: '—', note: !u || u.total === 0 ? 'No nodes reported' : 'Not reported by any node — metrics-server may not be installed' }
      : { key, label, ratio: u.ratio, figure: pair(u.used, u.capacity), note: coverageNote(u) }
  const requested = (key: string, label: string, req: number | undefined, alloc: number | undefined, pair: Pair): UsageRow =>
    !capacity || req === undefined || alloc === undefined
      ? { key, label, ratio: null, figure: '—', note: syncing ? 'Appears when the agent finishes its first read of the cluster' : 'Not reported by this agent — needs a newer agent build' }
      : alloc <= 0
        ? { key, label, ratio: null, figure: '—', note: 'No allocatable capacity reported' }
        : { key, label, ratio: req / alloc, figure: pair(req, alloc), note: `requests of ${capacity.podsCounted} scheduled pod${capacity.podsCounted === 1 ? '' : 's'}` }
  return [
    used('cpuUsed', 'CPU used', usage?.cpu, coresPair),
    requested('cpuRequested', 'CPU requested', capacity ? capacity.cpuRequestedMillicores / 1000 : undefined, capacity ? capacity.cpuAllocatableMillicores / 1000 : undefined, coresPair),
    used('memoryUsed', 'Memory used', usage?.memory, gibPair),
    requested('memoryRequested', 'Memory requested', capacity?.memoryRequestedBytes, capacity?.memoryAllocatableBytes, gibPair),
  ]
}

// ---------------------------------------------------------------- count strip

