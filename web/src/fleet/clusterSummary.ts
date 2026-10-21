import type { Certainty } from '../components/Quantity'

// The cluster health summary the agent carries in its facts
// (docs/CLUSTER_INSIGHT_SPECS.md CI-S11). ClusterFacts in api/generated.ts
// predates these two fields, so they are read here, defensively, from the raw
// facts object: an agent that does not report them yet is "unknown", never a
// zero. Wire shape: internal/agent/clustersummary (Summary, ResourceCounts)
// plus gitopsControllers/computedAt (internal/agent/tools_insight_more.go),
// and tunnel.ClusterObjectCache.

export interface ReplicaCount {
  total: number
  ready: number
  notReady: number
  scaledToZero: number
}

export interface NodeCount {
  total: number
  ready: number
  notReady: number
  cordoned: number
}

export interface ResourceCounts {
  pods?: { total: number; running: number; pending: number; failed: number; succeeded: number }
  deployments?: ReplicaCount
  statefulSets?: ReplicaCount
  daemonSets?: ReplicaCount
  services?: number
  ingresses?: number
  nodes?: NodeCount
  namespaces?: number
  jobs?: { total: number; active: number; succeeded: number; failed: number }
  cronJobs?: { total: number; active: number; suspended: number }
  configMaps?: number
  pvcs?: { total: number; bound: number; pending: number; unbound: number }
  /** Kind keys (clustersummary.Kind*) the agent could not list. */
  unavailable?: string[]
  /** Set by the UI (never by the agent) when the object cache's first sync
   *  has not finished: every count is "still being read", not missing. */
  syncing?: boolean
}

export interface ClusterSummary {
  resourceCounts?: ResourceCounts
  nodeVersionSkew?: { min: string; max: string; skewed: boolean; nodesByMinor?: Record<string, number>; unparsed?: number }
  networkPolicyCoverage?: {
    policies: number
    coveredWorkloads: number
    totalWorkloads: number
    invalidPolicies?: number
    notEvaluated?: { group: string; kind: string; count: number }[]
  }
  gitopsControllers?: string[]
  computedAt?: string
  /** "syncing" while the agent's object cache has not finished its first
   *  list (the summary then carries no figures); "synced" after. Absent on
   *  agents that predate it. */
  cacheState?: 'syncing' | 'synced'
  /** When the object cache started — present with cacheState "syncing". */
  cacheStartedAt?: string
}

export interface CacheKindState {
  group?: string
  kind: string
  state: string
  reason?: string
}

export interface ObjectCacheFacts {
  syncedAt?: string
  kinds: CacheKindState[]
}

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** Reads `summary` and `objectCache` out of a cluster's raw facts. */
export function readInsightFacts(facts: unknown): { summary: ClusterSummary | null; objectCache: ObjectCacheFacts | null } {
  if (!isObject(facts)) return { summary: null, objectCache: null }
  const summary = isObject(facts.summary) ? (facts.summary as ClusterSummary) : null
  const oc = facts.objectCache
  const objectCache =
    isObject(oc) && Array.isArray(oc.kinds) ? ({ syncedAt: oc.syncedAt as string | undefined, kinds: oc.kinds } as ObjectCacheFacts) : null
  return { summary, objectCache }
}

/** A Go zero time ("0001-01-01T…") or a missing value: not a real instant. */
export function realInstant(v: string | undefined): boolean {
  if (!v) return false
  const t = Date.parse(v)
  return Number.isFinite(t) && t > 0
}

/**
 * Whether the agent's object cache is still on its first sync, and since
 * when. A just-restarted agent sends its first facts before the cache has
 * listed anything; its counts are then "still being read", never "not visible
 * to the agent" or "needs a newer build". Newer agents say so outright
 * (`summary.cacheState`); for older ones the same snapshot's object-cache
 * report is read instead — no first-sync time yet and a kind still syncing.
 * Null when the figures are real (or there is nothing to say).
 */
export function cacheSyncing(summary: ClusterSummary | null, cache: ObjectCacheFacts | null): { startedAt: string | null } | null {
  if (summary?.cacheState === 'syncing') return { startedAt: realInstant(summary.cacheStartedAt) ? summary.cacheStartedAt! : null }
  if (summary?.cacheState === 'synced') return null
  if (cache && !realInstant(cache.syncedAt) && cache.kinds.some((k) => k.state === 'syncing')) return { startedAt: null }
  return null
}

/**
 * The summary the Overview draws from: unchanged when the figures are real;
 * while the cache is still syncing, one that carries no figures and marks
 * every count as "syncing", so nothing reads as missing or zero.
 */
export function overviewSummary(summary: ClusterSummary | null, syncing: { startedAt: string | null } | null): ClusterSummary | null {
  if (!syncing) return summary
  return { computedAt: summary?.computedAt, cacheState: 'syncing', resourceCounts: { syncing: true } }
}

/** The clustersummary kind key each count is filed under in `unavailable`. */
export const COUNT_KIND_KEY = {
  pods: 'pods',
  deployments: 'deployments',
  statefulSets: 'statefulsets',
  daemonSets: 'daemonsets',
  services: 'services',
  ingresses: 'ingresses',
  nodes: 'nodes',
  namespaces: 'namespaces',
  jobs: 'jobs',
  cronJobs: 'cronjobs',
  configMaps: 'configmaps',
  pvcs: 'persistentvolumeclaims',
} as const satisfies Record<Exclude<keyof ResourceCounts, 'unavailable' | 'syncing'>, string>

export type CountKey = keyof typeof COUNT_KIND_KEY

/**
 * Why a count is absent: the agent named the kind as not visible to it
 * ("unavailable"), or the summary simply does not carry it ("unknown" — an
 * older agent, or no summary yet). Present counts return null.
 */
export function countAbsence(counts: ResourceCounts | undefined, key: CountKey): 'unavailable' | 'unknown' | 'syncing' | null {
  if (counts?.syncing) return 'syncing'
  if (counts && counts[key] !== undefined && counts[key] !== null) return null
  if (counts?.unavailable?.includes(COUNT_KIND_KEY[key])) return 'unavailable'
  return 'unknown'
}

export const CACHE_STATE_LABEL: Record<string, string> = {
  synced: 'Synced',
  syncing: 'Still syncing',
  forbidden: 'Forbidden to the agent',
  absent: 'Not installed on this cluster',
  disabled: 'Disabled in the agent',
  error: 'Error',
}

// Problems first: a kind the agent cannot read changes what every answer
// built on it means; a CRD that is not installed is information, not a gap.
const CACHE_STATE_ORDER: Record<string, number> = { forbidden: 0, error: 1, syncing: 2, disabled: 3, absent: 4 }

/** Kinds the object cache has not synced, problems first. */
export function unsyncedKinds(cache: ObjectCacheFacts | null): CacheKindState[] {
  if (!cache) return []
  return cache.kinds
    .filter((k) => k.state !== 'synced')
    .sort(
      (a, b) =>
        (CACHE_STATE_ORDER[a.state] ?? 5) - (CACHE_STATE_ORDER[b.state] ?? 5) ||
        `${a.group ?? ''}/${a.kind}`.localeCompare(`${b.group ?? ''}/${b.kind}`),
    )
}

export function kindLabel(k: { group?: string; kind: string }): string {
  return k.group ? `${k.kind}.${k.group}` : k.kind
}

const GITOPS_LABEL: Record<string, string> = { argocd: 'Argo CD', flux: 'Flux', fleet: 'Rancher Fleet' }

export function gitopsControllerLabel(id: string): string {
  return GITOPS_LABEL[id] ?? id
}

/** "1.31.4+rke2r1" / "v1.31" → { major: 1, minor: 31 }, or null. */
export function parseMinor(version: string | null | undefined): { major: number; minor: number } | null {
  const m = /^v?(\d+)\.(\d+)/.exec((version ?? '').trim())
  if (!m) return null
  return { major: Number(m[1]), minor: Number(m[2]) }
}

/** The next minor release after `version`, as "1.N"; null when unparseable. */
export function nextMinor(version: string | null | undefined): string | null {
  const v = parseMinor(version)
  return v ? `${v.major}.${v.minor + 1}` : null
}

/** A scan target the hub accepts: "1.N". */
export function isValidTarget(target: string): boolean {
  return /^1\.\d{1,3}$/.test(target.trim())
}

/** Not-ready workloads summed over the kinds the agent could list. A lower
 *  bound when only some were listed; unknown when none were. */
export function notReadyWorkloads(counts: ResourceCounts | undefined): { value: number | null; certainty: Certainty; total: number; missing: string[] } {
  const kinds: [CountKey, string][] = [
    ['deployments', 'Deployments'],
    ['statefulSets', 'StatefulSets'],
    ['daemonSets', 'DaemonSets'],
  ]
  let value = 0
  let total = 0
  const missing: string[] = []
  for (const [key, label] of kinds) {
    const c = counts?.[key] as { notReady: number; total: number } | undefined
    if (c && countAbsence(counts, key) === null) {
      value += c.notReady
      total += c.total
    } else missing.push(label)
  }
  if (missing.length === kinds.length) return { value: null, certainty: 'unknown', total: 0, missing }
  return { value, certainty: missing.length > 0 ? 'atLeast' : 'exact', total, missing }
}

/** tunnel.SweepCoverage — what the agent's last sweep pass actually read. */
export interface SweepCoverage {
  at: string
  kindsRead: number
  kindsForbidden: number
  kindsNotServed: number
  kindsNotAffordable: number
  kindsFailed: number
  kindsNotListed: number
}

/** tunnel.ClusterCoverage (PROJECT.md E11): how much of the cluster this
 *  agent may watch (grant-shaped) and what its last sweep read. */
export interface ClusterCoverage {
  checked: boolean
  kindsServed: number
  kindsReadable: number
  deniedSample?: string[]
  deniedSampleTruncated?: boolean
  error?: string
  lastSweep?: SweepCoverage
}

function finiteNumber(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v)
}

/** `facts.coverage`, validated; null on an agent that does not report it.
 *  An unchecked coverage comes back as-is — the caller renders it as
 *  unknown, never as 0 of 0. */
export function readClusterCoverage(facts: unknown): ClusterCoverage | null {
  if (!isObject(facts) || !isObject(facts.coverage)) return null
  const c = facts.coverage
  if (typeof c.checked !== 'boolean') return null
  const sweep = isObject(c.lastSweep) && typeof c.lastSweep.at === 'string' ? c.lastSweep : null
  return {
    checked: c.checked,
    kindsServed: finiteNumber(c.kindsServed) ? c.kindsServed : 0,
    kindsReadable: finiteNumber(c.kindsReadable) ? c.kindsReadable : 0,
    deniedSample: Array.isArray(c.deniedSample) ? c.deniedSample.filter((x): x is string => typeof x === 'string') : undefined,
    deniedSampleTruncated: c.deniedSampleTruncated === true,
    error: typeof c.error === 'string' ? c.error : undefined,
    lastSweep: sweep
      ? {
          at: sweep.at as string,
          kindsRead: finiteNumber(sweep.kindsRead) ? sweep.kindsRead : 0,
          kindsForbidden: finiteNumber(sweep.kindsForbidden) ? sweep.kindsForbidden : 0,
          kindsNotServed: finiteNumber(sweep.kindsNotServed) ? sweep.kindsNotServed : 0,
          kindsNotAffordable: finiteNumber(sweep.kindsNotAffordable) ? sweep.kindsNotAffordable : 0,
          kindsFailed: finiteNumber(sweep.kindsFailed) ? sweep.kindsFailed : 0,
          kindsNotListed: finiteNumber(sweep.kindsNotListed) ? sweep.kindsNotListed : 0,
        }
      : undefined,
  }
}
