// Reading model for the object panel's Summary tab (owner review 2026-10-10,
// PROJECT.md UX1): the status header, the replica bar, the condition
// checklist and the workload's pods. Pure, so every rule that decides what the
// header SAYS is tested without a DOM.
//
// Honesty rules this file is built around:
//   - A health word is computed only from what the object itself reports
//     (conditions, replica counts, container states). A kind with no health
//     signal at all (a ConfigMap, a Service) gets no header, not "Healthy".
//   - A count the status omits stays unknown unless statusCount's API
//     convention applies (model.ts) — a replica bar is never drawn from a
//     guessed zero.

import type { GraphNode } from '../graph/types'
import { toNodeStatus } from '../graph/GraphCanvas'
import { conditionsOf, containersOf, neighborhoodGraph, podPhase, replicasOf, statusCount, type ConditionFact } from './model'
import { defaultGroupFor } from './kinds'
import type { ObjectRef } from './panelUrl'
import type { KubeObject, NeighborhoodResult } from './types'

/** The get_neighborhood arguments the Summary and the Related tab share, so
 *  one cached read serves both. */
export function neighborhoodArgs(target: ObjectRef) {
  return {
    kind: target.kind,
    apiGroup: target.apiGroup ?? defaultGroupFor(target.kind) ?? '',
    namespace: target.namespace ?? '',
    name: target.name,
    hops: 1,
  }
}

export type HealthWord =
  | 'Healthy'
  | 'Degraded'
  | 'Failing'
  | 'Progressing'
  | 'Pending'
  | 'Completed'
  | 'Scaled to zero'
  | 'Unknown'

export type Tone = 'green' | 'orange' | 'red' | 'blue' | 'amber' | 'gray'

export const HEALTH_TONE: Record<HealthWord, Tone> = {
  Healthy: 'green',
  Degraded: 'orange',
  Failing: 'red',
  Progressing: 'blue',
  Pending: 'amber',
  Completed: 'gray',
  'Scaled to zero': 'gray',
  Unknown: 'gray',
}

export interface ObjectHealth {
  word: HealthWord
  /** One line saying why, in the object's own vocabulary. */
  reason: string
}

// Condition types where True is the bad state. Everything else reads the
// usual way (True is good, False is bad).
const NEGATIVE_CONDITIONS = new Set([
  'MemoryPressure',
  'DiskPressure',
  'PIDPressure',
  'NetworkUnavailable',
  'ReplicaFailure',
  'Failed',
  'Stalled',
  'DisruptionTarget',
])

export type ConditionVerdict = 'failing' | 'unknown' | 'ok'

export function conditionVerdict(c: Pick<ConditionFact, 'type' | 'status'>): ConditionVerdict {
  if (c.status !== 'True' && c.status !== 'False') return 'unknown'
  const isTrue = c.status === 'True'
  return NEGATIVE_CONDITIONS.has(c.type) === isTrue ? 'failing' : 'ok'
}

const VERDICT_ORDER: Record<ConditionVerdict, number> = { failing: 0, unknown: 1, ok: 2 }

/** Failing conditions first, then unknown, then passing; stable within each. */
export function sortedConditions(conditions: readonly ConditionFact[]): (ConditionFact & { verdict: ConditionVerdict })[] {
  return conditions
    .map((c, i) => ({ ...c, verdict: conditionVerdict(c), i }))
    .sort((a, b) => VERDICT_ORDER[a.verdict] - VERDICT_ORDER[b.verdict] || a.i - b.i)
    .map(({ i: _i, ...c }) => c)
}

function conditionSentence(c: ConditionFact): string {
  return `${c.type} is ${c.status}${c.reason ? `: ${c.reason}` : ''}`
}

function rec(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : {}
}

function arr(v: unknown): unknown[] {
  return Array.isArray(v) ? v : []
}

const FAILING_WAIT_REASONS = new Set([
  'CrashLoopBackOff',
  'ImagePullBackOff',
  'ErrImagePull',
  'CreateContainerConfigError',
  'CreateContainerError',
  'InvalidImageName',
  'RunContainerError',
])

function podHealth(obj: KubeObject): ObjectHealth {
  const phase = podPhase(obj)
  const containers = containersOf(obj).filter((c) => !c.init)
  if (phase === 'Succeeded') return { word: 'Completed', reason: 'Every container exited successfully' }
  if (phase === 'Failed') {
    const why = rec(obj.status).reason
    return { word: 'Failing', reason: `Pod phase is Failed${typeof why === 'string' && why ? `: ${why}` : ''}` }
  }
  for (const c of containersOf(obj)) {
    const m = /^waiting \((.+)\)$/.exec(c.state ?? '')
    if (m && FAILING_WAIT_REASONS.has(m[1])) return { word: 'Failing', reason: `Container ${c.name} is waiting: ${m[1]}` }
    const t = /^terminated \((.+)\)$/.exec(c.state ?? '')
    if (t && t[1] !== 'Completed' && !c.init) return { word: 'Failing', reason: `Container ${c.name} terminated: ${t[1]}` }
  }
  if (phase === 'Pending') {
    const scheduled = conditionsOf(obj).find((c) => c.type === 'PodScheduled')
    if (scheduled && scheduled.status === 'False') return { word: 'Pending', reason: conditionSentence(scheduled) }
    const waiting = containersOf(obj).find((c) => c.state?.startsWith('waiting'))
    return { word: 'Pending', reason: waiting ? `Container ${waiting.name} is ${waiting.state}` : 'Pod phase is Pending' }
  }
  if (phase === 'Running') {
    const known = containers.filter((c) => c.ready !== undefined)
    if (known.length === 0) return { word: 'Unknown', reason: 'Running, but no container readiness was reported' }
    const ready = known.filter((c) => c.ready).length
    if (ready === containers.length) return { word: 'Healthy', reason: `Running · ${ready} of ${containers.length} containers ready` }
    return { word: 'Degraded', reason: `Running · ${ready} of ${containers.length} containers ready` }
  }
  return { word: 'Unknown', reason: phase ? `Pod phase is ${phase}` : 'Pod phase not reported' }
}

function workloadHealth(obj: KubeObject): ObjectHealth {
  const failing = sortedConditions(conditionsOf(obj)).find((c) => c.verdict === 'failing')
  if (failing) {
    return { word: failing.type === 'ReplicaFailure' ? 'Failing' : 'Degraded', reason: conditionSentence(failing) }
  }
  const r = replicasOf(obj)
  if (!r) return { word: 'Unknown', reason: 'Replica counts not reported' }
  const desired = r.desired
  const ready = statusCount(obj, r.ready)
  const updated = statusCount(obj, r.updated)
  if (desired === 0) return { word: 'Scaled to zero', reason: 'Desired replicas is 0' }
  if (desired === undefined || ready === undefined) return { word: 'Unknown', reason: 'Replica status not reported yet' }
  const unit = desired === 1 ? 'replica' : 'replicas'
  if (ready >= desired) {
    if (updated !== undefined && updated < desired) return { word: 'Progressing', reason: `Rollout in progress — ${updated} of ${desired} ${unit} updated` }
    return { word: 'Healthy', reason: `${ready} of ${desired} ${unit} ready` }
  }
  // Fewer ready than desired is Degraded even mid-rollout: the replicas that
  // are missing are missing whatever the reason, and calling it "Progressing"
  // would soften the one fact that matters.
  const rollout = updated !== undefined && updated < desired && updated > 0 ? `, ${updated} updated` : ''
  return { word: 'Degraded', reason: `${ready} of ${desired} ${unit} ready${rollout}` }
}

function jobHealth(obj: KubeObject): ObjectHealth {
  const conditions = conditionsOf(obj)
  const done = conditions.find((c) => (c.type === 'Complete' || c.type === 'SuccessCriteriaMet') && c.status === 'True')
  if (done) return { word: 'Completed', reason: conditionSentence(done) }
  const failed = conditions.find((c) => c.type === 'Failed' && c.status === 'True')
  if (failed) return { word: 'Failing', reason: conditionSentence(failed) }
  const active = rec(obj.status).active
  if (typeof active === 'number' && active > 0) return { word: 'Progressing', reason: `${active} pod${active === 1 ? '' : 's'} active` }
  return { word: 'Unknown', reason: 'No completion or failure reported yet' }
}

/**
 * The status header's health word and reason, or null for a kind that
 * carries no health signal (no conditions, no replicas, not a Pod/Job).
 */
export function objectHealth(obj: KubeObject | null | undefined): ObjectHealth | null {
  if (!obj) return null
  const kind = obj.kind ?? ''
  if (kind === 'Pod') return podHealth(obj)
  if (kind === 'Deployment' || kind === 'StatefulSet' || kind === 'DaemonSet' || kind === 'ReplicaSet') return workloadHealth(obj)
  if (kind === 'Job') return jobHealth(obj)
  const conditions = sortedConditions(conditionsOf(obj))
  if (conditions.length === 0) return null
  const failing = conditions.find((c) => c.verdict === 'failing')
  if (kind === 'Node') {
    const ready = conditions.find((c) => c.type === 'Ready')
    if (ready && ready.verdict !== 'ok') return { word: 'Failing', reason: conditionSentence(ready) }
    if (failing) return { word: 'Degraded', reason: conditionSentence(failing) }
    if (ready) return { word: 'Healthy', reason: conditionSentence(ready) }
  }
  if (failing) return { word: 'Degraded', reason: conditionSentence(failing) }
  const positive = conditions.find((c) => c.type === 'Ready' || c.type === 'Available')
  if (positive && positive.verdict === 'ok') return { word: 'Healthy', reason: conditionSentence(positive) }
  if (conditions.every((c) => c.verdict === 'unknown')) return { word: 'Unknown', reason: conditionSentence(conditions[0]) }
  return null
}

// ---------------------------------------------------------------- replicas

export interface ReplicaBar {
  desired: number
  /** Replicas that exist right now — above `desired` mid-rollout, when the
   *  new ReplicaSet's surge pod is still starting. */
  existing: number
  ready: number
  notReady: number
  /** "Desired 2 · updated 2 · available 1 · RollingUpdate (maxUnavailable 25%)" */
  detail: string
}

/** The replica bar's segments, or null when there is nothing honest to draw
 *  (not a replicated kind, nothing desired, or the ready count unknown). */
export function replicaBar(obj: KubeObject | null | undefined): ReplicaBar | null {
  const r = replicasOf(obj)
  if (!r || r.desired === undefined || r.desired === 0) return null
  const ready = statusCount(obj, r.ready)
  if (ready === undefined) return null
  const updated = statusCount(obj, r.updated)
  const available = statusCount(obj, r.available)
  const parts = [`Desired ${r.desired}`]
  if (updated !== undefined) parts.push(`updated ${updated}`)
  if (available !== undefined) parts.push(`available ${available}`)
  const strategy = strategyText(obj)
  if (strategy) parts.push(strategy)
  // The bar is drawn over the replicas that EXIST, not just the desired
  // count: a stuck rollout is precisely "1 desired, 2 exist, 1 not ready",
  // and a bar over desired alone would read as healthy.
  const statusReplicas = rec(obj?.status).replicas
  const existing = Math.max(r.desired, typeof statusReplicas === 'number' ? statusReplicas : 0)
  if (existing !== r.desired) parts.splice(1, 0, `existing ${existing}`)
  return { desired: r.desired, existing, ready: Math.min(ready, existing), notReady: Math.max(existing - ready, 0), detail: parts.join(' · ') }
}

function strategyText(obj: KubeObject | null | undefined): string | null {
  const spec = rec(obj?.spec)
  const st = rec(spec.strategy ?? spec.updateStrategy)
  const type = typeof st.type === 'string' ? st.type : null
  if (!type) return null
  const ru = rec(st.rollingUpdate)
  const bits: string[] = []
  if (ru.maxUnavailable !== undefined) bits.push(`maxUnavailable ${String(ru.maxUnavailable)}`)
  if (ru.maxSurge !== undefined) bits.push(`maxSurge ${String(ru.maxSurge)}`)
  return bits.length ? `${type} (${bits.join(', ')})` : type
}

// ---------------------------------------------------------------- neighbourhood

export interface PodRow {
  name: string
  status: GraphNode['status']
  reason?: string
  phase?: string
  node?: string
  restarts?: number
  /** True for a member listed inside a collapsed PodGroup: the agent sends
   *  only its name and health, so phase/node/restarts are absent. */
  grouped: boolean
}

export interface WorkloadPods {
  rows: PodRow[]
  /** The true pod count, including group members the agent did not list. */
  total: number
}

/**
 * The pods the root owns directly (the agent hides a Deployment's
 * ReplicaSets and draws Deployment → Pod), from one get_neighborhood read.
 * A collapsed PodGroup contributes the members it lists and its true count,
 * so `total` can exceed `rows.length` — the caller says so rather than
 * presenting the listed members as the whole set.
 */
export function workloadPods(r: NeighborhoodResult | null | undefined): WorkloadPods {
  if (!r) return { rows: [], total: 0 }
  const { rootId } = neighborhoodGraph(r)
  const owned = new Set((r.edges ?? []).filter((e) => e.type === 'owns' && e.source === rootId).map((e) => e.target))
  const rows: PodRow[] = []
  let total = 0
  for (const n of r.nodes ?? []) {
    if (!owned.has(n.id)) continue
    const sum = n.summary ?? {}
    if (n.kind === 'Pod') {
      total += 1
      rows.push({
        name: n.name,
        status: toNodeStatus(n.status),
        reason: n.statusReason,
        phase: typeof sum.phase === 'string' ? sum.phase : undefined,
        node: typeof sum.nodeName === 'string' ? sum.nodeName : undefined,
        restarts: typeof sum.restarts === 'number' ? sum.restarts : undefined,
        grouped: false,
      })
    } else if (n.kind === 'PodGroup') {
      const members = Array.isArray(sum.pods) ? (sum.pods as Record<string, unknown>[]) : []
      const count = typeof sum.podCount === 'number' ? sum.podCount : members.length
      total += count
      for (const m of members) {
        if (typeof m.name !== 'string') continue
        rows.push({
          name: m.name,
          status: toNodeStatus(typeof m.status === 'string' ? m.status : undefined),
          reason: typeof m.statusReason === 'string' ? m.statusReason : undefined,
          grouped: true,
        })
      }
    }
  }
  // Worst first, the same order the agent caps group members by.
  const rank: Record<GraphNode['status'], number> = { unhealthy: 0, degraded: 1, unknown: 2, neutral: 3, healthy: 4 }
  rows.sort((a, b) => rank[a.status] - rank[b.status] || a.name.localeCompare(b.name))
  return { rows, total }
}

export interface ConnectedNode {
  id: string
  kind: string
  apiGroup?: string
  namespace?: string
  name: string
  status: GraphNode['status']
}

/** Objects one edge from the root — the Summary's "Connected" preview of the
 *  Related tab, read from the same relationships. The only objects left out
 *  are the pods the root OWNS, because the Pods card lists exactly those; a
 *  pod connected any other way (a ServiceAccount that configures it, a
 *  Service that selects it) is connected and is shown. */
export function connectedObjects(r: NeighborhoodResult | null | undefined): ConnectedNode[] {
  if (!r) return []
  const { nodes, rootId } = neighborhoodGraph(r)
  const adjacent = new Set<string>()
  const ownedPods = new Set<string>()
  for (const e of r.edges ?? []) {
    if (e.source === rootId) adjacent.add(e.target)
    if (e.target === rootId) adjacent.add(e.source)
    if (e.source === rootId && e.type === 'owns') ownedPods.add(e.target)
  }
  return nodes
    .filter((n) => n.id !== rootId && adjacent.has(n.id) && !((n.kind === 'Pod' || n.kind === 'PodGroup') && ownedPods.has(n.id)))
    .map((n) => ({ id: n.id, kind: n.kind, apiGroup: n.apiGroup, namespace: n.namespace, name: n.name, status: n.status }))
}

// ---------------------------------------------------------------- Ingress and Service

export interface IngressRoute {
  host: string
  path: string
  pathType?: string
  /** "svc:port" or a resource backend's "Kind/name". */
  service?: string
  port?: string
  resource?: string
  /** The TLS secret covering this host, when a tls entry lists it. */
  tlsSecret?: string
  tls: boolean
}

export interface IngressFacts {
  className?: string
  routes: IngressRoute[]
  defaultBackend?: { service?: string; port?: string; resource?: string }
  /** Hosts a tls entry lists, with the secret name (never its content). */
  tls: { hosts: string[]; secretName?: string }[]
  addresses: string[]
}

function backendOf(b: unknown): { service?: string; port?: string; resource?: string } | undefined {
  const r = rec(b)
  const svc = rec(r.service)
  if (typeof svc.name === 'string') {
    const port = rec(svc.port)
    const p = typeof port.number === 'number' ? String(port.number) : typeof port.name === 'string' ? port.name : undefined
    return { service: svc.name, port: p }
  }
  const res = rec(r.resource)
  if (typeof res.name === 'string') return { resource: `${typeof res.kind === 'string' ? res.kind : 'Resource'}/${res.name}` }
  return undefined
}

function lbAddresses(status: Record<string, unknown>): string[] {
  return arr(rec(status.loadBalancer).ingress).flatMap((i) => {
    const r = rec(i)
    const a = typeof r.ip === 'string' ? r.ip : typeof r.hostname === 'string' ? r.hostname : undefined
    return a ? [a] : []
  })
}

/** An Ingress's routing table, read from its own spec — host, path, backend
 *  and whether TLS covers the host. A wildcard tls entry (no hosts) covers
 *  every rule, as the controller treats it. */
export function ingressFacts(obj: KubeObject | null | undefined): IngressFacts | null {
  if (obj?.kind !== 'Ingress') return null
  const spec = rec(obj.spec)
  const tls = arr(spec.tls).map((t) => {
    const r = rec(t)
    return { hosts: arr(r.hosts).filter((h): h is string => typeof h === 'string'), secretName: typeof r.secretName === 'string' ? r.secretName : undefined }
  })
  const tlsFor = (host: string) => tls.find((t) => (t.hosts.length === 0 ? true : t.hosts.includes(host)))
  const routes: IngressRoute[] = []
  for (const rule of arr(spec.rules)) {
    const r = rec(rule)
    const host = typeof r.host === 'string' && r.host !== '' ? r.host : '*'
    const t = tlsFor(host)
    const paths = arr(rec(r.http).paths)
    if (paths.length === 0) {
      routes.push({ host, path: '/', tls: !!t, tlsSecret: t?.secretName })
      continue
    }
    for (const p of paths) {
      const pr = rec(p)
      const b = backendOf(pr.backend)
      routes.push({
        host,
        path: typeof pr.path === 'string' && pr.path !== '' ? pr.path : '/',
        pathType: typeof pr.pathType === 'string' ? pr.pathType : undefined,
        ...b,
        tls: !!t,
        tlsSecret: t?.secretName,
      })
    }
  }
  return {
    className: typeof spec.ingressClassName === 'string' ? spec.ingressClassName : obj.metadata?.annotations?.['kubernetes.io/ingress.class'],
    routes,
    defaultBackend: backendOf(spec.defaultBackend),
    tls,
    addresses: lbAddresses(rec(obj.status)),
  }
}

export interface ServicePort {
  name?: string
  port?: number
  targetPort?: string
  protocol: string
  nodePort?: number
}

export interface ServiceFacts {
  type: string
  clusterIP?: string
  externalName?: string
  ports: ServicePort[]
  /** null when the Service has no selector — its endpoints are managed by
   *  something other than the selector (or by hand). */
  selector: [string, string][] | null
  addresses: string[]
}

export function serviceFacts(obj: KubeObject | null | undefined): ServiceFacts | null {
  if (obj?.kind !== 'Service') return null
  const spec = rec(obj.spec)
  const sel = rec(spec.selector)
  const selector = Object.keys(sel).length > 0 ? Object.entries(sel).map(([k, v]) => [k, String(v)] as [string, string]) : null
  return {
    type: typeof spec.type === 'string' ? spec.type : 'ClusterIP',
    clusterIP: typeof spec.clusterIP === 'string' ? spec.clusterIP : undefined,
    externalName: typeof spec.externalName === 'string' ? spec.externalName : undefined,
    ports: arr(spec.ports).map((p) => {
      const r = rec(p)
      return {
        name: typeof r.name === 'string' ? r.name : undefined,
        port: typeof r.port === 'number' ? r.port : undefined,
        targetPort: typeof r.targetPort === 'number' || typeof r.targetPort === 'string' ? String(r.targetPort) : undefined,
        protocol: typeof r.protocol === 'string' ? r.protocol : 'TCP',
        nodePort: typeof r.nodePort === 'number' ? r.nodePort : undefined,
      }
    }),
    selector,
    addresses: lbAddresses(rec(obj.status)),
  }
}

/** Ready and not-ready addresses on a Service's Endpoints object — the
 *  endpoint controller's own count, not one ARGUS computes. */
export function endpointCounts(obj: KubeObject | null | undefined): { ready: number; notReady: number } | null {
  if (obj?.kind !== 'Endpoints') return null
  let ready = 0
  let notReady = 0
  for (const sub of arr((obj as Record<string, unknown>).subsets)) {
    const r = rec(sub)
    ready += arr(r.addresses).length
    notReady += arr(r.notReadyAddresses).length
  }
  return { ready, notReady }
}

export const NODE_STATUS_WORD: Record<GraphNode['status'], string> = {
  healthy: 'Healthy',
  degraded: 'Degraded',
  unhealthy: 'Unhealthy',
  neutral: 'No health signal',
  unknown: 'Health unknown',
}
