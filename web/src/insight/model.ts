// Pure reading models for the object inspector and the incident page's
// insight sections. Rendering lives in the .tsx files beside this one; every
// decision about WHAT to show (which tabs apply, which facts a summary
// carries, how a change reads as one line) is here so it can be tested
// without a DOM.

import type { ResourceChange } from '../api/types'
import type { ReferenceLine } from '../charts/types'
import { parseCPUCores, parseMemoryBytes } from '../fleet/resourceUsage'
import type { GraphEdge, GraphNode } from '../graph/types'
import { toNodeStatus } from '../graph/GraphCanvas'
import { hasGitOpsMarkers, isGitOpsKind, PATH_KINDS, PERMISSION_KINDS, WORKLOAD_KINDS } from './kinds'
import type { CoverageEntry, KubeObject, NeighborhoodResult } from './types'

// ---------------------------------------------------------------- tabs

export type InspectorTab =
  | 'summary'
  | 'yaml'
  | 'events'
  | 'logs'
  | 'metrics'
  | 'changes'
  | 'related'
  | 'path'
  | 'permissions'
  | 'policy'
  | 'gitops'
  | 'helm'
  | 'autoscaler'
  | 'rollout'
  | 'scheduling'
  | 'drain'

export const TAB_LABEL: Record<InspectorTab, string> = {
  summary: 'Summary',
  yaml: 'YAML',
  events: 'Events',
  logs: 'Logs',
  metrics: 'Metrics',
  changes: 'Changes',
  related: 'Related',
  path: 'Connectivity',
  permissions: 'Permissions',
  policy: 'Policy',
  gitops: 'GitOps',
  helm: 'Helm',
  autoscaler: 'Autoscaler',
  rollout: 'Rollout',
  scheduling: 'Scheduling',
  drain: 'Drain impact',
}

export const HELM_RELEASE_ANNOTATION = 'meta.helm.sh/release-name'
export const HELM_NAMESPACE_ANNOTATION = 'meta.helm.sh/release-namespace'

// The order a reader wants them in (owner, 2026-10-11): what it is, then the
// one tab that answers THIS kind's own question, then what is happening to it
// (events, logs), how it connects (related, connectivity), what changed, who
// owns and governs it, and the raw YAML last. Every applicable tab is on the
// row — a row that does not fit scrolls (components/Tabs.tsx), so the tabs
// that scroll out of sight are the least needed rather than hidden.
const TAB_ORDER: readonly InspectorTab[] = [
  'summary',
  'events',
  'logs',
  'metrics',
  'related',
  'path',
  'changes',
  'rollout',
  'autoscaler',
  'scheduling',
  'drain',
  'helm',
  'gitops',
  'permissions',
  'policy',
  'yaml',
]

/** The tab that answers this kind's own question, placed right after Summary. */
function leadTab(kind: string, apiGroup: string | undefined, obj: KubeObject | null | undefined): InspectorTab | null {
  if (kind === 'Pod' && podUnscheduled(obj)) return 'scheduling'
  if (kind === 'Deployment') return 'rollout'
  if (kind === 'Node') return 'drain'
  if (kind === 'HorizontalPodAutoscaler') return 'autoscaler'
  if (PATH_KINDS.has(kind)) return 'path'
  if (kind === 'ServiceAccount') return 'permissions'
  if (isGitOpsKind(kind, apiGroup)) return 'gitops'
  return null
}

/**
 * The tabs that mean something for this object, in display order. `obj` is
 * the described object when known: tabs that depend on its content (GitOps
 * markers, a Helm annotation, a Pending phase) appear only once it has been
 * read. A tab is left out only when it is irrelevant to the kind — never
 * because the viewer lacks a capability (that is the caller's disabled state).
 */
export function tabsFor(kind: string, apiGroup: string | undefined, obj: KubeObject | null | undefined): InspectorTab[] {
  const set = new Set<InspectorTab>(['summary', 'yaml', 'events', 'changes', 'related', 'policy'])
  if (kind === 'Pod' || WORKLOAD_KINDS.has(kind)) {
    set.add('logs')
    // CPU, memory, restarts and throttling from the cluster's Prometheus
    // (PROJECT.md AD7); the tab says so when none is configured.
    set.add('metrics')
  }
  // Connectivity: from a Service, Ingress or route the trace starts at the
  // object itself; from a Pod or workload it starts at the Services and
  // Ingresses that route to it (ConnectivityTab).
  if (PATH_KINDS.has(kind) || kind === 'Pod' || WORKLOAD_KINDS.has(kind)) set.add('path')
  if (PERMISSION_KINDS.has(kind)) set.add('permissions')
  const labels = obj?.metadata?.labels ?? {}
  const annotations = obj?.metadata?.annotations ?? {}
  if (isGitOpsKind(kind, apiGroup) || hasGitOpsMarkers(labels, annotations)) set.add('gitops')
  if (annotations[HELM_RELEASE_ANNOTATION]) set.add('helm')
  if (kind === 'HorizontalPodAutoscaler') set.add('autoscaler')
  if (kind === 'Deployment') set.add('rollout')
  if (kind === 'Pod' && podUnscheduled(obj)) set.add('scheduling')
  if (kind === 'Node') set.add('drain')
  const lead = leadTab(kind, apiGroup, obj)
  const ordered = TAB_ORDER.filter((t) => set.has(t) && t !== 'summary' && t !== lead)
  return ['summary', ...(lead && set.has(lead) ? [lead] : []), ...ordered]
}

export function isInspectorTab(v: string | null): v is InspectorTab {
  return v !== null && v in TAB_LABEL
}

// ---------------------------------------------------------------- summary facts

function rec(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
}

function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : []
}

function num(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined
}

function s(v: unknown): string | undefined {
  return typeof v === 'string' && v !== '' ? v : undefined
}

export function podPhase(obj: KubeObject | null | undefined): string | undefined {
  return s(rec(obj?.status).phase)
}

/**
 * A Pending pod the scheduler has not placed yet — the only pod "why won't
 * this schedule?" applies to. Pending also covers a pod already bound to a
 * node and stuck starting (ContainerCreating on a volume attach, an image
 * pull), which is a node-side problem; spec.nodeName or PodScheduled=True
 * says it was scheduled.
 */
export function podUnscheduled(obj: KubeObject | null | undefined): boolean {
  if (podPhase(obj) !== 'Pending') return false
  if (s(rec(obj?.spec).nodeName)) return false
  const scheduled = arr(rec(obj?.status).conditions).some((c) => rec(c).type === 'PodScheduled' && rec(c).status === 'True')
  return !scheduled
}

/** The pod template spec for a workload, or the spec itself for a Pod. */
function podSpec(obj: KubeObject | null | undefined): Record<string, unknown> {
  const spec = rec(obj?.spec)
  if (obj?.kind === 'Pod' || 'containers' in spec) return spec
  if (obj?.kind === 'CronJob') return rec(rec(rec(rec(spec.jobTemplate).spec).template).spec)
  return rec(rec(spec.template).spec)
}

export interface ResourceAmounts {
  cpu?: string
  memory?: string
}

export interface ContainerFact {
  name: string
  image: string
  init: boolean
  ready?: boolean
  restartCount?: number
  state?: string
  /** The spec's own quantity strings ("100m", "256Mi"); a missing key means
   *  the spec sets none, which Kubernetes treats as "no request/limit". */
  requests: ResourceAmounts
  limits: ResourceAmounts
}

function amounts(v: unknown): ResourceAmounts {
  const r = rec(v)
  const q = (x: unknown) => (typeof x === 'string' && x !== '' ? x : typeof x === 'number' ? String(x) : undefined)
  return { cpu: q(r.cpu), memory: q(r.memory) }
}

/**
 * One pod's CPU (cores) or memory (bytes) request and limit, as reference lines
 * for the Metrics tab's per-pod series (PROJECT.md AD7). Pod-level resources
 * (`spec.resources`) win when set. Otherwise the containers' values are summed,
 * and a line is drawn only when EVERY container sets that value: a sum missing
 * one container would understate the pod and read as a real ceiling. Init
 * containers are left out; they do not run beside the others.
 */
export function perPodResourceLines(obj: KubeObject | null | undefined, resource: 'cpu' | 'memory'): ReferenceLine[] {
  const spec = podSpec(obj)
  const parse = resource === 'cpu' ? parseCPUCores : parseMemoryBytes
  const lines: ReferenceLine[] = []
  for (const kind of ['request', 'limit'] as const) {
    const field = kind === 'request' ? 'requests' : 'limits'
    const podLevel = rec(rec(spec.resources)[field])[resource]
    let total: number | null = null
    if (typeof podLevel === 'string') {
      total = parse(podLevel)
    } else {
      const containers = arr(spec.containers)
      if (containers.length === 0) continue
      total = 0
      for (const c of containers) {
        const v = rec(rec(rec(c).resources)[field])[resource]
        const n = typeof v === 'string' ? parse(v) : null
        if (n === null) {
          total = null
          break
        }
        total += n
      }
    }
    if (total !== null && total > 0) lines.push({ value: total, label: `${kind} per pod`, kind })
  }
  return lines
}

export function containersOf(obj: KubeObject | null | undefined): ContainerFact[] {
  const spec = podSpec(obj)
  const statuses = new Map<string, Record<string, unknown>>()
  for (const st of [...arr(rec(obj?.status).containerStatuses), ...arr(rec(obj?.status).initContainerStatuses)]) {
    const r = rec(st)
    if (typeof r.name === 'string') statuses.set(r.name, r)
  }
  const out: ContainerFact[] = []
  for (const [list, init] of [[spec.initContainers, true], [spec.containers, false]] as const) {
    for (const c of arr(list)) {
      const r = rec(c)
      const name = s(r.name)
      if (!name) continue
      const st = statuses.get(name)
      let state: string | undefined
      if (st) {
        const stateRec = rec(st.state)
        const key = Object.keys(stateRec)[0]
        if (key) {
          const reason = s(rec(stateRec[key]).reason)
          state = reason ? `${key} (${reason})` : key
        }
      }
      out.push({
        name,
        image: s(r.image) ?? '',
        init,
        ready: typeof st?.ready === 'boolean' ? st.ready : undefined,
        restartCount: num(st?.restartCount),
        state,
        requests: amounts(rec(r.resources).requests),
        limits: amounts(rec(r.resources).limits),
      })
    }
  }
  return out
}

export function serviceAccountOf(obj: KubeObject | null | undefined): string | undefined {
  if (!obj) return undefined
  if (obj.kind === 'ServiceAccount') return obj.metadata?.name
  const spec = podSpec(obj)
  if (!('containers' in spec)) return undefined
  // An unset serviceAccountName runs as the namespace's "default" account —
  // that is the Kubernetes default, not a guess.
  return s(spec.serviceAccountName) ?? 'default'
}

export interface ConditionFact {
  type: string
  status: string
  reason?: string
  message?: string
}

export function conditionsOf(obj: KubeObject | null | undefined): ConditionFact[] {
  return arr(rec(obj?.status).conditions).flatMap((c) => {
    const r = rec(c)
    const type = s(r.type)
    if (!type) return []
    return [{ type, status: s(r.status) ?? 'Unknown', reason: s(r.reason), message: s(r.message) }]
  })
}

export interface ReplicaFacts {
  desired?: number
  ready?: number
  updated?: number
  available?: number
}

/** Replica counts for kinds that have them; null for kinds that do not. A
 *  missing status count is undefined (rendered "—"), never 0. */
export function replicasOf(obj: KubeObject | null | undefined): ReplicaFacts | null {
  const kind = obj?.kind
  const spec = rec(obj?.spec)
  const status = rec(obj?.status)
  if (kind === 'DaemonSet') {
    return { desired: num(status.desiredNumberScheduled), ready: num(status.numberReady), updated: num(status.updatedNumberScheduled), available: num(status.numberAvailable) }
  }
  if (kind === 'Deployment' || kind === 'StatefulSet' || kind === 'ReplicaSet') {
    // spec.replicas defaults to 1 server-side, so an absent value on a
    // stored object means 1.
    return {
      desired: num(spec.replicas) ?? 1,
      ready: num(status.readyReplicas),
      updated: num(status.updatedReplicas),
      available: num(status.availableReplicas),
    }
  }
  return null
}

/**
 * A count the API server OMITS when it is zero (readyReplicas,
 * availableReplicas…): absent on a status that was otherwise observed
 * means 0, which is the API's own convention, not a fabricated zero. Absent
 * on an object with no status at all stays unknown.
 */
export function statusCount(obj: KubeObject | null | undefined, value: number | undefined): number | undefined {
  if (value !== undefined) return value
  const status = rec(obj?.status)
  return Object.keys(status).length > 0 && num(status.observedGeneration) !== undefined ? 0 : undefined
}

// ---------------------------------------------------------------- redaction

export const REDACTED = '[REDACTED]'

/** Splits a line into plain and redacted segments, in order. */
export function splitRedacted(line: string): { text: string; redacted: boolean }[] {
  if (!line.includes(REDACTED)) return [{ text: line, redacted: false }]
  const out: { text: string; redacted: boolean }[] = []
  const parts = line.split(REDACTED)
  parts.forEach((p, i) => {
    if (p) out.push({ text: p, redacted: false })
    if (i < parts.length - 1) out.push({ text: REDACTED, redacted: true })
  })
  return out
}

export function countRedacted(text: string): number {
  return text.split(REDACTED).length - 1
}

// ---------------------------------------------------------------- logs

/** Case-insensitive substring filter; an empty query keeps every line. */
export function filterLogLines(lines: readonly string[], query: string): string[] {
  const q = query.trim().toLowerCase()
  if (!q) return [...lines]
  return lines.filter((l) => l.toLowerCase().includes(q))
}

// ---------------------------------------------------------------- coverage

/** "Incomplete: X not synced (reason); …" or null when inputs were complete. */
export function coverageNote(coverage: readonly CoverageEntry[] | null | undefined): string | null {
  if (!coverage || coverage.length === 0) return null
  const parts = coverage.map((c) => {
    const name = c.group ? `${c.kind}.${c.group}` : c.kind
    return `${name} ${c.state}${c.reason ? ` (${c.reason})` : ''}`
  })
  return `Incomplete: this answer needed kinds the agent has not synced — ${parts.join('; ')}.`
}

// ---------------------------------------------------------------- graph

export function neighborhoodGraph(r: NeighborhoodResult): { nodes: GraphNode[]; edges: GraphEdge[]; rootId?: string } {
  const nodes: GraphNode[] = (r.nodes ?? []).map((n) => ({
    id: n.id,
    kind: n.kind,
    apiGroup: n.apiGroup,
    namespace: n.namespace,
    name: n.name,
    status: toNodeStatus(n.status),
    statusReason: n.statusReason,
  }))
  const ids = new Set(nodes.map((n) => n.id))
  const edges: GraphEdge[] = (r.edges ?? [])
    .filter((e) => ids.has(e.source) && ids.has(e.target))
    .map((e) => ({ id: e.id || `${e.source}->${e.target}:${e.type}`, source: e.source, target: e.target, type: e.type }))
  const root = r.root
  const rootNode = root
    ? nodes.find((n) => n.kind === root.kind && n.name === root.name && (n.namespace ?? '') === (root.namespace ?? ''))
    : undefined
  return { nodes, edges, rootId: rootNode?.id ?? nodes[0]?.id }
}

/** Why the drawn graph may be smaller than the real neighbourhood, or null. */
export function graphPartialNote(r: NeighborhoodResult): string | null {
  const parts: string[] = []
  if (r.truncated) parts.push('the neighbourhood hit its size cap, so more objects exist than are drawn')
  if (r.omitted) parts.push(`${r.omitted} object${r.omitted === 1 ? ' was' : 's were'} left out because the agent may not read ${r.omitted === 1 ? 'it' : 'them'}`)
  if (r.unavailable && r.unavailable.length > 0) parts.push(`these kinds could not be listed: ${r.unavailable.join(', ')}`)
  return parts.length > 0 ? `Partial graph — ${parts.join('; ')}.` : null
}

// ---------------------------------------------------------------- changes

function valueText(v: unknown): string {
  if (v === undefined || v === null || v === '') return '∅'
  if (typeof v === 'string') return v
  return JSON.stringify(v)
}

/** "Deployment/payments" */
export function changeObjectLabel(c: Pick<ResourceChange, 'kind' | 'name'>): string {
  return `${c.kind}/${c.name}`
}

/** What changed, in words: the agent's summary, else each field as
 *  "path: old → new", else the operation. */
export function changeWhat(c: ResourceChange): string {
  if (c.op === 'add') return c.summary ? `created — ${c.summary}` : 'created'
  if (c.op === 'delete') return 'deleted'
  if (c.summary) return c.summary.replace(/→/g, ' → ').replace(/\s+→\s+/g, ' → ')
  const fields = (c.fields ?? []).filter((f) => f.path)
  if (fields.length === 0) return 'changed'
  return fields.map((f) => `${f.path}: ${valueText(f.oldValue)} → ${valueText(f.newValue)}`).join(', ')
}

export interface ChangeGroup {
  key: string
  /** "Deployment/payments" — the owner when one is recorded, else the object. */
  label: string
  owner?: { kind: string; name: string; namespace?: string }
  changes: ResourceChange[]
  newest: string
}

/**
 * Newest-first groups keyed by owner (CI-U4): a Deployment's own changes and
 * its ReplicaSets'/Pods' changes read as one group with a true count. Within
 * a group, changes stay newest first; groups are ordered by their newest
 * change.
 */
export function groupChangesByOwner(changes: readonly ResourceChange[]): ChangeGroup[] {
  const sorted = [...changes].sort((a, b) => Date.parse(b.observedAt) - Date.parse(a.observedAt))
  const groups = new Map<string, ChangeGroup>()
  for (const c of sorted) {
    const ownerKind = c.ownerKind || c.kind
    const ownerName = c.ownerName || c.name
    const key = `${c.namespace ?? ''}/${ownerKind}/${ownerName}`
    let g = groups.get(key)
    if (!g) {
      g = {
        key,
        label: `${ownerKind}/${ownerName}`,
        owner: { kind: ownerKind, name: ownerName, namespace: c.namespace },
        changes: [],
        newest: c.observedAt,
      }
      groups.set(key, g)
    }
    g.changes.push(c)
  }
  return [...groups.values()]
}
