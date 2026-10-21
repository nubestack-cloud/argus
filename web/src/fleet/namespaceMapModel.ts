import type { Incident, NamespaceIndexRow, NamespaceTopology } from '../api/types'
import { isClosedIncidentState, parseWorkloadKey } from '../utils/incidents'

// The namespace map (PROJECT.md AD6), from get_namespace_topology:
// internal/agent/tools_inventory.go + internal/agent/topology/namespace.go.
// Without a namespace the tool answers the picker index; with one, that
// namespace's relationship graph, capped with honest omitted counts.

export type { NamespaceIndexRow, NamespaceTopology }

/** Default and largest cap the agent accepts (topology.NamespaceDefaultMaxNodes / NamespaceMaxNodes). */
export const MAP_DEFAULT_CAP = 150
export const MAP_MAX_CAP = 300

interface TopologyNode {
  id: string
  kind: string
  apiGroup?: string
  namespace?: string
  name: string
  status?: string
  statusReason?: string
  summary?: Record<string, unknown>
}

interface TopologyEdge {
  id?: string
  source: string
  target: string
  type: string
}

// ---------------------------------------------------------------- the map's shape

// The map is a set of workload cards, each laid out in the same four lanes
// left to right — how traffic reaches the workload, then what runs it — with
// what guards and configures the workload hanging off underneath. Same lanes
// in every card, so the eye runs down one column across all of them. It is
// drawn with HTML, not on a zoomable canvas: a namespace of sixty objects on a
// canvas had to shrink below the design system's smallest type to fit, and
// here every label stays at a size that can be read at rest.

export type Lane = 'entry' | 'service' | 'workload' | 'pods'
export const LANES: readonly Lane[] = ['entry', 'service', 'workload', 'pods']
export const LANE_LABEL: Record<Lane, string> = { entry: 'Entry', service: 'Service', workload: 'Workload', pods: 'Pods' }

const LANE_OF: Record<string, Lane> = {
  Ingress: 'entry',
  Gateway: 'entry',
  HTTPRoute: 'entry',
  GRPCRoute: 'entry',
  TCPRoute: 'entry',
  TLSRoute: 'entry',
  Service: 'service',
  Deployment: 'workload',
  StatefulSet: 'workload',
  DaemonSet: 'workload',
  CronJob: 'workload',
  Job: 'workload',
  ReplicaSet: 'workload',
  PodGroup: 'pods',
  Pod: 'pods',
}

/** The kinds a viewer can show or hide, as one toggle each. Workloads are
 *  always drawn — they are the cards. */
export type KindFilter = 'entry' | 'service' | 'pods' | 'policies' | 'autoscalers' | 'config'
export const KIND_FILTERS: readonly { id: KindFilter; label: string; kinds: readonly string[] }[] = [
  { id: 'entry', label: 'Ingresses & routes', kinds: ['Ingress', 'Gateway', 'HTTPRoute', 'GRPCRoute', 'TCPRoute', 'TLSRoute'] },
  { id: 'service', label: 'Services', kinds: ['Service'] },
  { id: 'pods', label: 'Pods', kinds: ['PodGroup', 'Pod'] },
  { id: 'policies', label: 'Policies & budgets', kinds: ['NetworkPolicy', 'PodDisruptionBudget'] },
  { id: 'autoscalers', label: 'Autoscalers', kinds: ['HorizontalPodAutoscaler'] },
  { id: 'config', label: 'Config & storage', kinds: ['ConfigMap', 'ServiceAccount', 'PersistentVolumeClaim', 'PersistentVolume'] },
]
/** Config and storage start hidden: in a large namespace every workload has a
 *  service account and a ConfigMap or two, and they outnumber everything else. */
export const DEFAULT_FILTERS: ReadonlySet<KindFilter> = new Set(['entry', 'service', 'pods', 'policies', 'autoscalers'])

const FILTER_OF: Record<string, KindFilter> = Object.fromEntries(KIND_FILTERS.flatMap((f) => f.kinds.map((k) => [k, f.id])))

/** Kinds that hang off a workload rather than sit in a lane. */
export const ATTACHED_LABEL: Record<string, string> = {
  NetworkPolicy: 'guards',
  PodDisruptionBudget: 'guards',
  HorizontalPodAutoscaler: 'scales',
  ConfigMap: 'configures',
  ServiceAccount: 'configures',
  PersistentVolumeClaim: 'stores',
  PersistentVolume: 'stores',
}

const WORKLOAD_KINDS = new Set(['Deployment', 'StatefulSet', 'DaemonSet', 'CronJob', 'Job'])

/** The card for objects wired to no single workload (a Service in front of an
 *  operator-managed database, a budget for pods no workload here owns). */
export const UNTIED_GROUP = 'Not tied to one workload'

/** An object wired to at least this many workloads is listed above the map
 *  rather than repeated in every card: a namespace-wide NetworkPolicy's
 *  fifteen links say one thing, "applies to all of them". */
export const SHARED_MIN_WORKLOADS = 3

export type Health = 'healthy' | 'degraded' | 'unhealthy' | 'neutral' | 'unknown'
const HEALTH_RANK: Record<Health, number> = { unhealthy: 0, degraded: 1, unknown: 2, healthy: 3, neutral: 4 }

function toHealth(s: string | undefined): Health {
  return s === 'healthy' || s === 'degraded' || s === 'unhealthy' || s === 'neutral' ? s : 'unknown'
}

export interface MapNode {
  id: string
  kind: string
  apiGroup?: string
  namespace?: string
  name: string
  health: Health
  reason?: string
  /** One short fact from the agent's summary: "ClusterIP :8080", "2/2 ready". */
  detail?: string
  /** Pods can be opened; a pod group is a count, not an object. */
  openable: boolean
}

export interface MapCard {
  key: string
  title: string
  /** The workload kind, or null for the untied card. */
  kind: string | null
  health: Health
  /** Not healthy (degraded, unhealthy) anywhere in the card. */
  problem: boolean
  /** The card's own workload is not healthy — the count the picker's
   *  "workloads not healthy" makes (false on the untied card). */
  workloadProblem: boolean
  lanes: Record<Lane, MapNode[]>
  attached: MapNode[]
  /** Every object in the card before kind filters. */
  total: number
  pods: number
}

export interface SharedObject {
  node: MapNode
  workloads: number
}

export interface NamespaceMapModel {
  cards: MapCard[]
  shared: SharedObject[]
  /** Objects per kind filter, before filtering, for the toggle labels. */
  filterCounts: Record<KindFilter, number>
}

function num(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined
}

/** One short line of what the agent knows about the object. */
export function nodeDetail(kind: string, summary: Record<string, unknown> | undefined): string | undefined {
  if (!summary) return undefined
  switch (kind) {
    case 'Ingress': {
      const hosts = Array.isArray(summary.hosts) ? (summary.hosts as string[]) : []
      return hosts.length ? `${hosts[0]}${hosts.length > 1 ? ` +${hosts.length - 1}` : ''}` : undefined
    }
    case 'Service': {
      const ports = Array.isArray(summary.ports) ? (summary.ports as { port?: number }[]) : []
      const p = ports.map((x) => x.port).filter((x) => x !== undefined)
      return [summary.type as string | undefined, p.length ? `:${p.slice(0, 3).join(', :')}` : ''].filter(Boolean).join(' ')
    }
    case 'Deployment':
    case 'StatefulSet':
    case 'ReplicaSet': {
      const want = num(summary.replicas)
      const ready = num(summary.readyReplicas) ?? 0
      return want === undefined ? undefined : `${ready}/${want} ready`
    }
    case 'DaemonSet': {
      const want = num(summary.desiredNumberScheduled) ?? num(summary.desired)
      const ready = num(summary.numberReady) ?? num(summary.ready) ?? 0
      return want === undefined ? undefined : `${ready}/${want} ready`
    }
    case 'PodGroup': {
      const n = num(summary.podCount)
      const bad = (num(summary.unhealthy) ?? 0) + (num(summary.degraded) ?? 0)
      return n === undefined ? undefined : bad ? `${bad} of ${n} not healthy` : `all ${n} healthy`
    }
    case 'Pod':
      return [summary.phase as string | undefined, summary.ready ? `${summary.ready} ready` : ''].filter(Boolean).join(' · ') || undefined
    case 'PodDisruptionBudget': {
      const n = num(summary.disruptionsAllowed)
      return n === undefined ? undefined : `${n} disruption${n === 1 ? '' : 's'} allowed`
    }
    case 'NetworkPolicy':
      return Array.isArray(summary.policyTypes) ? (summary.policyTypes as string[]).join(' + ') : undefined
    case 'ConfigMap': {
      const n = num(summary.keys)
      return n === undefined ? undefined : `${n} key${n === 1 ? '' : 's'}`
    }
    default:
      return undefined
  }
}

/**
 * Builds the workload cards for one namespace. A workload names a card; an
 * object joins the card of the one workload its neighbours lead to (an
 * Ingress reaches its workload through the Service, a pod group through its
 * owner); objects wired to several workloads (≥ SHARED_MIN_WORKLOADS) are
 * listed as shared; anything left joins the untied card. Problem cards sort
 * first, then by name. `filters` hides kinds inside cards; counts are taken
 * before filtering.
 */
export function buildNamespaceMap(r: NamespaceTopology, filters: ReadonlySet<KindFilter> = DEFAULT_FILTERS): NamespaceMapModel {
  const raw = (r.nodes ?? []) as unknown as TopologyNode[]
  const edges = (r.edges ?? []) as unknown as TopologyEdge[]
  const byId = new Map(raw.map((n) => [n.id, n]))
  const valid = edges.filter((e) => byId.has(e.source) && byId.has(e.target))

  const filterCounts = Object.fromEntries(KIND_FILTERS.map((f) => [f.id, 0])) as Record<KindFilter, number>
  for (const n of raw) {
    const f = FILTER_OF[n.kind]
    if (f) filterCounts[f]++
  }

  // Which card each object belongs to. A workload owns its card, unless
  // another workload owns it (a CronJob's Jobs join the CronJob); then
  // whatever a workload owns (its pod groups) joins that workload's card.
  const card = new Map<string, string>()
  for (const n of raw) if (WORKLOAD_KINDS.has(n.kind)) card.set(n.id, n.id)
  const owns = valid.filter((e) => e.type === 'owns')
  for (const e of owns) {
    if (WORKLOAD_KINDS.has(byId.get(e.source)!.kind) && WORKLOAD_KINDS.has(byId.get(e.target)!.kind)) card.set(e.target, e.source)
  }
  for (const e of owns) {
    if (card.has(e.source) && !card.has(e.target)) card.set(e.target, card.get(e.source)!)
  }
  for (const e of owns) {
    if (card.has(e.source) && !card.has(e.target)) card.set(e.target, card.get(e.source)!)
  }
  const neighbours = new Map<string, string[]>()
  for (const e of valid) {
    neighbours.set(e.source, [...(neighbours.get(e.source) ?? []), e.target])
    neighbours.set(e.target, [...(neighbours.get(e.target) ?? []), e.source])
  }
  // Shared: objects whose direct neighbours span several workload cards.
  const sharedIds = new Set<string>()
  const shared: SharedObject[] = []
  for (const n of raw) {
    if (card.has(n.id)) continue
    const f = FILTER_OF[n.kind]
    if (f && !filters.has(f)) continue
    const touched = new Set((neighbours.get(n.id) ?? []).map((o) => card.get(o)).filter((c): c is string => !!c))
    if (touched.size >= SHARED_MIN_WORKLOADS) {
      sharedIds.add(n.id)
      shared.push({ node: toMapNode(n), workloads: touched.size })
    }
  }
  for (let changed = true, round = 0; changed && round < 10; round++) {
    changed = false
    for (const n of raw) {
      if (card.has(n.id) || sharedIds.has(n.id)) continue
      const seen = new Set((neighbours.get(n.id) ?? []).filter((o) => !sharedIds.has(o)).map((o) => card.get(o)).filter((c): c is string => !!c))
      if (seen.size === 1) {
        card.set(n.id, [...seen][0])
        changed = true
      }
    }
  }

  const cards = new Map<string, MapCard>()
  const cardFor = (key: string): MapCard => {
    let c = cards.get(key)
    if (!c) {
      const root = key === UNTIED_GROUP ? undefined : byId.get(key)
      c = {
        key,
        title: root ? root.name : UNTIED_GROUP,
        kind: root ? root.kind : null,
        health: 'healthy',
        problem: false,
        workloadProblem: false,
        lanes: { entry: [], service: [], workload: [], pods: [] },
        attached: [],
        total: 0,
        pods: 0,
      }
      cards.set(key, c)
    }
    return c
  }
  for (const n of raw) {
    if (sharedIds.has(n.id)) continue
    const c = cardFor(card.get(n.id) ?? UNTIED_GROUP)
    const m = toMapNode(n)
    c.total++
    if (n.kind === 'PodGroup') c.pods += num(n.summary?.podCount) ?? 0
    if (n.kind === 'Pod') c.pods++
    if (HEALTH_RANK[m.health] < HEALTH_RANK[c.health]) c.health = m.health
    if (m.health === 'unhealthy' || m.health === 'degraded') {
      c.problem = true
      if (n.id === c.key) c.workloadProblem = true
    }
    const f = FILTER_OF[n.kind]
    if (f && !filters.has(f)) continue
    const lane = LANE_OF[n.kind]
    if (lane) c.lanes[lane].push(m)
    else c.attached.push(m)
  }
  const out = [...cards.values()]
  // Problems first; then the most connected workloads, which are the most
  // map-like (an Ingress, a Service, a workload, its pods); the untied card
  // last.
  const order = (c: MapCard) => (c.kind === null ? 2 : c.problem ? 0 : 1)
  out.sort((a, b) => order(a) - order(b) || b.total - a.total || a.title.localeCompare(b.title))
  shared.sort((a, b) => b.workloads - a.workloads || a.node.name.localeCompare(b.node.name))
  return { cards: out, shared, filterCounts }
}

function toMapNode(n: TopologyNode): MapNode {
  return {
    id: n.id,
    kind: n.kind,
    apiGroup: n.apiGroup,
    namespace: n.namespace,
    name: n.name,
    health: toHealth(n.status),
    reason: n.statusReason,
    detail: nodeDetail(n.kind, n.summary),
    openable: n.kind !== 'PodGroup',
  }
}

/** Whether a card matches a search: its title or any object's name. */
export function cardMatches(c: MapCard, q: string): boolean {
  const needle = q.trim().toLowerCase()
  if (!needle) return true
  if (c.title.toLowerCase().includes(needle)) return true
  return [...LANES.flatMap((l) => c.lanes[l]), ...c.attached].some((n) => n.name.toLowerCase().includes(needle))
}

/** How many cards open by default. Every card that needs attention opens;
 *  healthy ones fill the rest of this budget in map order, and the others
 *  collapse to one line until opened. */
export const OPEN_BY_DEFAULT = 6

/** The keys of the cards open before anyone toggles one. */
export function defaultOpen(cards: readonly MapCard[]): Set<string> {
  const open = new Set(cards.filter((c) => c.problem).map((c) => c.key))
  for (const c of cards) {
    if (open.size >= OPEN_BY_DEFAULT) break
    open.add(c.key)
  }
  return open
}

/** Why the drawn map may be smaller than the namespace, in one sentence,
 *  or null when it is the whole namespace. */
export function mapPartialNote(r: NamespaceTopology): string | null {
  const parts: string[] = []
  if (r.omittedNodes) {
    const byKind = Object.entries(r.omittedByKind ?? {})
      .sort((a, b) => b[1] - a[1])
      .map(([k, n]) => `${n} ${k}`)
      .join(', ')
    parts.push(`${r.omittedNodes} of ${r.totalNodes ?? '?'} objects are not drawn (${byKind}) — the map keeps entry points and workloads first`)
  }
  if (r.omittedEdges) parts.push(`${r.omittedEdges} connection${r.omittedEdges === 1 ? '' : 's'} to undrawn objects ${r.omittedEdges === 1 ? 'is' : 'are'} left out`)
  if (r.unavailable && r.unavailable.length > 0) parts.push(`these kinds could not be listed: ${r.unavailable.join(', ')}`)
  return parts.length > 0 ? `Partial map — ${parts.join('; ')}.` : null
}

/** Open incidents per namespace, from the incidents the page already has. */
export function openIncidentsByNamespace(incidents: readonly Incident[]): Map<string, number> {
  const out = new Map<string, number>()
  for (const i of incidents) {
    if (isClosedIncidentState(i.state)) continue
    const ns = i.objectNamespace || parseWorkloadKey(i.workloadKey).namespace
    if (!ns) continue
    out.set(ns, (out.get(ns) ?? 0) + 1)
  }
  return out
}

/** The namespace the map opens on: the one with the most open incidents
 *  (ties to the larger namespace), else the largest. Null with no index. */
export function defaultNamespace(incidents: readonly Incident[], index: readonly NamespaceIndexRow[]): { name: string; why: string } | null {
  if (index.length === 0) return null
  const size = new Map(index.map((n) => [n.name, n.pods + n.workloads + n.services]))
  const open = openIncidentsByNamespace(incidents)
  let best: string | null = null
  for (const [ns, n] of open) {
    if (!size.has(ns)) continue
    const cur = best ? (open.get(best) ?? 0) : -1
    if (n > cur || (n === cur && (size.get(ns) ?? 0) > (size.get(best!) ?? 0))) best = ns
  }
  if (best) {
    const n = open.get(best) ?? 0
    return { name: best, why: `most open incidents (${n})` }
  }
  return { name: index[0].name, why: 'the largest namespace; no open incident names one' }
}

/**
 * "nebula — 37 pods (1 not healthy), 16 workloads (1 not healthy), 8 Services"
 * for the picker. Pods and workloads not healthy are named apart, so the
 * workload figure is the same count the map's status line makes once the
 * namespace is open. An agent that predates the split reports one sum, said
 * as exactly that.
 */
export function namespaceOptionLabel(n: NamespaceIndexRow, openIncidents: number): string {
  const split = typeof n.podsNotHealthy === 'number' && typeof n.workloadsNotHealthy === 'number'
  const bad = (k: number | undefined) => (split && k ? ` (${k} not healthy)` : '')
  const parts = [`${n.pods} pod${n.pods === 1 ? '' : 's'}${bad(n.podsNotHealthy)}`, `${n.workloads} workload${n.workloads === 1 ? '' : 's'}${bad(n.workloadsNotHealthy)}`]
  if (n.services > 0) parts.push(`${n.services} Service${n.services === 1 ? '' : 's'}`)
  if (!split && n.notHealthy > 0) parts.push(`${n.notHealthy} pods or workloads not healthy`)
  if (openIncidents > 0) parts.push(`${openIncidents} open incident${openIncidents === 1 ? '' : 's'}`)
  return `${n.name} — ${parts.join(', ')}`
}

export interface MapStatusCounts {
  /** Workload cards (the untied card is not a workload). */
  workloads: number
  /** Workload cards whose own workload is not healthy. */
  workloadsNotHealthy: number
  /** Cards with a healthy workload but a pod or attached object not healthy,
   *  plus the untied card when something in it is not healthy. */
  otherProblems: number
  /** Whether there is an untied card. */
  untied: boolean
}

/** The map's status-line counts, so its parts add up to the cards drawn. */
export function mapStatusCounts(cards: readonly MapCard[]): MapStatusCounts {
  const workloadCards = cards.filter((c) => c.kind !== null)
  return {
    workloads: workloadCards.length,
    workloadsNotHealthy: workloadCards.filter((c) => c.workloadProblem).length,
    otherProblems: cards.filter((c) => c.problem && !c.workloadProblem).length,
    untied: cards.some((c) => c.kind === null),
  }
}

/**
 * The status line under the map's toolbar. Every figure adds up: workloads
 * not healthy + healthy = workloads; cards open + collapsed = workloads +
 * the untied card.
 */
export function mapStatusText(cards: readonly MapCard[], namespace: string, open: number, collapsed: number): string {
  const s = mapStatusCounts(cards)
  const w = (k: number) => `${k} workload${k === 1 ? '' : 's'}`
  const parts: string[] = []
  let lead = `${w(s.workloads)} in ${namespace}`
  if (s.workloadsNotHealthy === 0 && s.otherProblems === 0) lead += ', all healthy right now'
  else {
    const bits: string[] = []
    if (s.workloadsNotHealthy > 0) bits.push(`${s.workloadsNotHealthy} not healthy now`)
    if (s.otherProblems > 0) bits.push(`${s.otherProblems} ${s.otherProblems === 1 ? 'card has' : 'cards have'} a pod or object not healthy`)
    lead += `: ${bits.join('; ')} — shown first`
  }
  parts.push(lead)
  if (collapsed > 0) {
    const cardsWord = s.untied ? `${s.workloads + 1} cards (one per workload, and one for objects tied to no single workload)` : `${s.workloads} cards`
    parts.push(`${cardsWord}: ${open} open, ${collapsed} collapsed to a line — select one to open it`)
  }
  return parts.join('. ')
}

export function safeFilePart(s: string): string {
  return s.replace(/[^A-Za-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'map'
}

/** The open incidents on a card's own objects: an object in the card by
 *  kind and name, or a Pod/ReplicaSet named from the card's workload
 *  ("<workload>-<hash>…"), in the card's namespace. Worst first. */
export function cardIncidents(card: MapCard, namespace: string, incidents: readonly Incident[]): Incident[] {
  const nodes = [...Object.values(card.lanes).flat(), ...card.attached]
  const workload = card.lanes.workload[0]
  const rank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }
  return incidents
    .filter((i) => {
      if (isClosedIncidentState(i.state) || i.objectNamespace !== namespace || !i.objectName) return false
      const kind = (i.objectGvk ?? '').split('/').pop() ?? ''
      if (nodes.some((n) => n.kind === kind && n.name === i.objectName)) return true
      return !!workload && (kind === 'Pod' || kind === 'ReplicaSet') && i.objectName.startsWith(`${workload.name}-`)
    })
    .sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9) || (a.lastSeen < b.lastSeen ? 1 : -1))
}

/** A short badge for an attached object: what it is, in two or three letters. */
export const ATTACHED_SHORT: Record<string, string> = {
  NetworkPolicy: 'NP',
  PodDisruptionBudget: 'PDB',
  HorizontalPodAutoscaler: 'HPA',
  ConfigMap: 'CM',
  ServiceAccount: 'SA',
  PersistentVolumeClaim: 'PVC',
  PersistentVolume: 'PV',
}
