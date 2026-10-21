// Pure reading model for the cluster page's Overview tab (owner reviews
// 2026-10-10 and 2026-10-11, PROJECT.md UX1): the health ledger (Nodes, CPU,
// Memory, Workloads, Pods), the object inventory, and the Needs attention /
// Changes / Checks previews. Every decision about WHAT a figure says lives
// here so it is tested without a DOM.
//
// The honesty rules it is built around, stated once:
//   - A count the agent did not report is null, never 0, and carries why
//     (not visible to the agent, or not reported by this build).
//   - A total over a partial set (some workload kinds unlistable) says so.
//   - Requested-vs-allocatable comes only from `summary.capacity`; an agent
//     that predates it reads "not reported by this agent", never 0%.
//   - Used comes from metrics-server per node; a roll-up over some nodes
//     says how many.

import type { Incident, IncidentSeverity, ResourceChange, ResourceChangeGap } from '../api/types'
import { isClosedIncidentState, kindFromObjectGvk, parseWorkloadKey, SEVERITY_RANK } from '../utils/incidents'
import { groupChangesByOwner } from '../insight/model'
import { countAbsence, type ClusterSummary, type CountKey, type ResourceCounts } from './clusterSummary'

export type Absence = 'unavailable' | 'unknown' | 'syncing'

export const ABSENCE_TEXT: Record<Absence, string> = {
  unavailable: 'Not visible to the agent',
  unknown: 'Not reported by this agent',
  syncing: 'Still being read by the agent',
}

// ---------------------------------------------------------------- capacity

export interface CapacitySummary {
  cpuRequestedMillicores: number
  cpuAllocatableMillicores: number
  memoryRequestedBytes: number
  memoryAllocatableBytes: number
  podsCounted: number
}

/** `summary.capacity`, validated; null on an agent that predates it. */
export function readCapacity(summary: ClusterSummary | null): CapacitySummary | null {
  const c = (summary as { capacity?: unknown } | null)?.capacity as Partial<CapacitySummary> | undefined
  if (!c || typeof c !== 'object') return null
  const fields: (keyof CapacitySummary)[] = ['cpuRequestedMillicores', 'cpuAllocatableMillicores', 'memoryRequestedBytes', 'memoryAllocatableBytes', 'podsCounted']
  if (!fields.every((f) => typeof c[f] === 'number' && Number.isFinite(c[f]))) return null
  return c as CapacitySummary
}

/** One measured quantity on a capacity line (used, or requested). */
// ---------------------------------------------------------------- inventory

export interface InventoryDetail {
  text: string
  /** The part names something wrong (a non-zero not-ready / failed /
   *  pending / unbound): drawn in the danger text colour; the words already
   *  say it. */
  problem: boolean
}

export interface InventoryItem {
  key: CountKey
  label: string
  value: number | null
  absence?: Absence
  detail?: InventoryDetail[]
}

export interface InventoryGroup {
  title: string
  items: InventoryItem[]
}

function total(counts: ResourceCounts, key: CountKey): number {
  const v = counts[key]
  return typeof v === 'number' ? v : (v as { total: number }).total
}

const bad = (n: number, word: string): InventoryDetail => ({ text: `${n} ${word}`, problem: n > 0 })
const fact = (n: number, word: string): InventoryDetail => ({ text: `${n} ${word}`, problem: false })

type Spec = { key: CountKey; label: string; detail?: (c: ResourceCounts) => InventoryDetail[] | null }

const GROUPS: { title: string; items: Spec[] }[] = [
  {
    title: 'Workloads',
    items: [
      { key: 'deployments', label: 'Deployments', detail: (c) => (c.deployments ? [bad(c.deployments.notReady, 'not ready'), fact(c.deployments.scaledToZero, 'scaled to zero')] : null) },
      { key: 'statefulSets', label: 'StatefulSets', detail: (c) => (c.statefulSets?.notReady ? [bad(c.statefulSets.notReady, 'not ready')] : null) },
      { key: 'daemonSets', label: 'DaemonSets', detail: (c) => (c.daemonSets?.notReady ? [bad(c.daemonSets.notReady, 'not ready')] : null) },
    ],
  },
  {
    title: 'Batch',
    items: [
      { key: 'jobs', label: 'Jobs', detail: (c) => (c.jobs ? [bad(c.jobs.failed, 'failed'), fact(c.jobs.active, 'active')] : null) },
      { key: 'cronJobs', label: 'CronJobs', detail: (c) => (c.cronJobs ? [fact(c.cronJobs.suspended, 'suspended')] : null) },
    ],
  },
  {
    title: 'Networking',
    items: [
      { key: 'services', label: 'Services' },
      { key: 'ingresses', label: 'Ingresses' },
    ],
  },
  {
    title: 'Config and storage',
    items: [
      { key: 'namespaces', label: 'Namespaces' },
      { key: 'configMaps', label: 'ConfigMaps' },
      { key: 'pvcs', label: 'PersistentVolumeClaims', detail: (c) => (c.pvcs ? [bad(c.pvcs.pending, 'pending'), bad(c.pvcs.unbound, 'unbound')] : null) },
    ],
  },
]

/** Every object count the summary carries, grouped by what the objects are
 *  for. An absent count says why instead of reading 0. */
export function inventoryGroups(counts: ResourceCounts | undefined): InventoryGroup[] {
  return GROUPS.map((g) => ({
    title: g.title,
    items: g.items.map(({ key, label, detail }) => {
      const absence = countAbsence(counts, key)
      if (absence !== null || !counts) return { key, label, value: null, absence: absence ?? 'unknown' }
      return { key, label, value: total(counts, key), detail: detail?.(counts) ?? undefined }
    }),
  }))
}

// ---------------------------------------------------------------- needs attention

/** Open incidents worst first, then most recently active; the first `n`. */
export function topOpenIncidents(incidents: readonly Incident[], n = 3): Incident[] {
  return incidents
    .filter((i) => !isClosedIncidentState(i.state))
    .sort((a, b) => (SEVERITY_RANK[a.severity] ?? 4) - (SEVERITY_RANK[b.severity] ?? 4) || Date.parse(b.lastSeen) - Date.parse(a.lastSeen))
    .slice(0, n)
}

/**
 * Closed incidents, most recently closed first — what fills the card when
 * fewer than `n` are open, so a quiet cluster shows what ARGUS last dealt
 * with instead of an empty box. Read from the same fetched page as the open
 * ones, so it is "recent", never "all".
 */
export function recentlyClosed(incidents: readonly Incident[], n: number): Incident[] {
  if (n <= 0) return []
  const when = (i: Incident) => Date.parse(i.resolvedAt ?? i.lastSeen)
  return incidents
    .filter((i) => isClosedIncidentState(i.state))
    .sort((a, b) => when(b) - when(a))
    .slice(0, n)
}

// ---------------------------------------------------------------- changes

export interface ChangedObject {
  key: string
  kind: string
  name: string
  namespace?: string
  count: number
  created: number
  deleted: number
  updated: number
  /** ISO time of the newest and oldest change in the window. */
  newest: string
  oldest: string
}

export interface ChangeActivity {
  /** Changes per bin, oldest bin first. */
  bins: number[]
  binMs: number
  peak: number
  total: number
  /** The owning objects, newest activity first, at most `max`. */
  objects: ChangedObject[]
  /** Owning objects left out of `objects`. */
  hidden: number
}

/**
 * Changes in [start, end]: a per-bin count for the activity strip, and the
 * owning objects (CI-U4 grouping), newest first, with what was done to them.
 */
export function changeActivity(changes: readonly ResourceChange[], start: number, end: number, binCount = 12, max = 5): ChangeActivity {
  const span = Math.max(end - start, 1)
  const binMs = span / binCount
  const bins = Array.from({ length: binCount }, () => 0)
  const inWindow = changes.filter((c) => {
    const t = Date.parse(c.observedAt)
    return t >= start && t <= end
  })
  for (const c of inWindow) {
    const i = Math.min(Math.floor((Date.parse(c.observedAt) - start) / binMs), binCount - 1)
    bins[i] += 1
  }
  const groups = groupChangesByOwner(inWindow)
  const objects = groups.slice(0, max).map((g) => ({
    key: g.key,
    kind: g.owner?.kind ?? '',
    name: g.owner?.name ?? g.label,
    namespace: g.owner?.namespace,
    count: g.changes.length,
    created: g.changes.filter((c) => c.op === 'add').length,
    deleted: g.changes.filter((c) => c.op === 'delete').length,
    updated: g.changes.filter((c) => c.op !== 'add' && c.op !== 'delete').length,
    newest: g.changes[0].observedAt,
    oldest: g.changes[g.changes.length - 1].observedAt,
  }))
  return { bins, binMs, peak: Math.max(0, ...bins), total: inWindow.length, objects, hidden: Math.max(groups.length - max, 0) }
}

/** "6 changed · 2 created" — zero kinds left out. */
export function opsText(o: Pick<ChangedObject, 'created' | 'deleted' | 'updated'>): string {
  const parts: string[] = []
  if (o.updated) parts.push(`${o.updated} changed`)
  if (o.created) parts.push(`${o.created} created`)
  if (o.deleted) parts.push(`${o.deleted} deleted`)
  return parts.join(' · ')
}

/** Incidents first seen inside [start, end], as positions along it. */
export function incidentsOpenedIn(incidents: readonly Incident[], start: number, end: number): { incident: Incident; at: number }[] {
  const span = Math.max(end - start, 1)
  return incidents
    .map((incident) => ({ incident, t: Date.parse(incident.firstSeen) }))
    .filter(({ t }) => t >= start && t <= end)
    .sort((a, b) => a.t - b.t)
    .map(({ incident, t }) => ({ incident, at: (t - start) / span }))
}

/**
 * The worst open incident naming this object — as the owning workload the
 * hub resolved, or as the object itself. A match is stated; no match is not
 * claimed to mean "no incident", since the incident list may be capped.
 */
export function openIncidentOn(obj: { kind: string; name: string; namespace?: string }, incidents: readonly Incident[]): Incident | null {
  let worst: Incident | null = null
  for (const i of incidents) {
    if (isClosedIncidentState(i.state)) continue
    const owner = parseWorkloadKey(i.workloadKey)
    const objKind = kindFromObjectGvk(i.objectGvk)
    const hit =
      (owner.name === obj.name && (!owner.kind || owner.kind === obj.kind) && (!owner.namespace || !obj.namespace || owner.namespace === obj.namespace)) ||
      (i.objectName === obj.name && (!objKind || objKind === obj.kind) && (!i.objectNamespace || !obj.namespace || i.objectNamespace === obj.namespace))
    if (hit && (!worst || (SEVERITY_RANK[i.severity] ?? 4) < (SEVERITY_RANK[worst.severity] ?? 4))) worst = i
  }
  return worst
}

/** Gaps in the change history that overlap the window, as sentences. */
export function windowGaps(gaps: readonly ResourceChangeGap[] | undefined, start: number, end: number): string[] {
  return (gaps ?? [])
    .filter((g) => Date.parse(g.to) >= start && Date.parse(g.from) <= end)
    .map((g) => g.reason)
}

export const SEV_CLASS: Record<IncidentSeverity | string, string> = {
  critical: 'sev-critical',
  high: 'sev-high',
  medium: 'sev-medium',
  low: 'sev-low',
}

// ---------------------------------------------------------------- checks

export interface CountWithCertainty {
  value: number
  atLeast: boolean
}

export function postureDangerCount(r: { findings?: { severity: string }[] | null; truncated?: boolean } | null | undefined): CountWithCertainty | null {
  if (!r) return null
  return { value: (r.findings ?? []).filter((f) => f.severity === 'danger').length, atLeast: !!r.truncated }
}

export function certificatesExpiring(
  r: { certificates?: { daysLeft?: number | null }[] | null; truncated?: boolean } | null | undefined,
  days = 30,
): (CountWithCertainty & { unknown: number }) | null {
  if (!r) return null
  const certs = r.certificates ?? []
  return {
    value: certs.filter((c) => typeof c.daysLeft === 'number' && c.daysLeft < days).length,
    unknown: certs.filter((c) => typeof c.daysLeft !== 'number').length,
    atLeast: !!r.truncated,
  }
}

export interface AttentionGroup {
  key: string
  /** Worst first: the group's first incident leads it. */
  items: Incident[]
}

/** Open incidents grouped by look-alike — same kind, namespace, opening
 *  reason and severity — worst severity then most recently active first, at
 *  most `n` groups (owner-approved cluster-pages design, 2026-10-11): thirteen
 *  pods of one fault are one row with a count, not six identical rows that
 *  push the rest out of view. */
export function openAttentionGroups(incidents: readonly Incident[], n: number): AttentionGroup[] {
  const open = topOpenIncidents(incidents, Number.MAX_SAFE_INTEGER)
  const by = new Map<string, AttentionGroup>()
  for (const i of open) {
    const kind = (i.objectGvk ?? '').split('/').pop() ?? ''
    const key = [kind, i.objectNamespace ?? '', i.openingReason ?? '', i.severity].join('|')
    const g = by.get(key) ?? { key, items: [] }
    g.items.push(i)
    by.set(key, g)
  }
  return [...by.values()].slice(0, n)
}
