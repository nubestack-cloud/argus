// Service traffic (docs/CLUSTER_INSIGHT_SPECS.md CI-S13), as get_traffic
// returns it: internal/agent/traffic/types.go Result. Rates are per second;
// errorRate is 5xx responses per second, so the percentage is derived from
// it and requestRate — and is unknown whenever either is.
import type { GraphEdge, GraphNode } from '../graph/types'
import { connectPrometheusHint, type DetectedPrometheus } from './metricsSource'

export interface TrafficEndpoint {
  namespace?: string
  name: string
  kind: string
}

export interface TrafficFlow {
  src: TrafficEndpoint
  dst: TrafficEndpoint
  port: number
  protocol: string
  requestRate?: number | null
  errorRate?: number | null
  connectionRate?: number | null
  bytesRate?: number | null
  directionUnknown?: boolean
  /** The same edge over the same span, comparisonSeconds earlier; absent
   *  when no comparison ran or it carried no traffic then. */
  before?: { requestRate?: number | null; errorRate?: number | null; connectionRate?: number | null; bytesRate?: number | null } | null
  /** Carried traffic in the earlier window and none now. */
  stopped?: boolean
}

export interface TrafficResult {
  observedAt?: string
  available: boolean
  reason?: string
  /** not_configured | unreachable | no_source (agents before this field
   *  send only `reason`). */
  reasonCode?: string
  detectedPrometheus?: DetectedPrometheus | null
  source?: string
  windowSeconds?: number
  flows?: TrafficFlow[] | null
  totalFlows?: number
  truncated?: boolean
  missing?: string[] | null
  notes?: string[] | null
  comparisonSeconds?: number
  comparisonAvailable?: boolean
  comparisonReason?: string
}

export const TRAFFIC_SOURCE_LABEL: Record<string, string> = {
  istio: 'Istio metrics',
  beyla: 'Beyla (Grafana Alloy) metrics',
  obi: 'OpenTelemetry eBPF instrumentation metrics',
  hubble: 'Cilium Hubble flow metrics',
}

export function endpointId(e: TrafficEndpoint): string {
  return `${e.kind}:${e.namespace ?? ''}/${e.name}`
}

export function endpointLabel(e: TrafficEndpoint): string {
  return e.namespace ? `${e.namespace}/${e.name}` : e.name
}

export function flowId(f: TrafficFlow): string {
  return `${endpointId(f.src)}|${endpointId(f.dst)}|${f.port}`
}

/** 5xx share in percent, or null when it was not measured. */
export function errorPercent(f: TrafficFlow): number | null {
  if (f.errorRate == null || f.requestRate == null) return null
  if (f.requestRate === 0) return f.errorRate === 0 ? 0 : null
  return (f.errorRate / f.requestRate) * 100
}

function fmt(n: number, digits = 1): string {
  return n.toLocaleString(undefined, { maximumFractionDigits: digits })
}

/** A per-second rate or a percentage, to one decimal. */
export function formatRate(n: number): string {
  return fmt(n)
}

export function formatBytesRate(bps: number): string {
  const units = ['B/s', 'KiB/s', 'MiB/s', 'GiB/s']
  let v = bps
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${fmt(v)} ${units[i]}`
}

/** The edge's label, in text: "12.3 req/s · 2.1% 5xx". L4-only edges say
 *  what was measured instead; an unmeasured error rate says so. */
export function edgeLabel(f: TrafficFlow): string {
  const parts: string[] = []
  if (f.requestRate != null) {
    parts.push(`${fmt(f.requestRate)} req/s`)
    const pct = errorPercent(f)
    parts.push(pct == null ? '5xx not measured' : `${fmt(pct)}% 5xx`)
  } else if (f.connectionRate != null) {
    parts.push(`${fmt(f.connectionRate)} conn/s`)
  } else if (f.bytesRate != null) {
    parts.push(formatBytesRate(f.bytesRate))
  } else {
    parts.push('rate not measured')
  }
  return parts.join(' · ')
}

/** An edge drawn as a problem: some 5xx were measured on it. */
export function isProblemFlow(f: TrafficFlow): boolean {
  return (f.errorRate ?? 0) > 0
}

export interface TrafficGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  edgeLabels: Record<string, string>
  problemEdges: Set<string>
  edgeWidths: Record<string, number>
}

/** Nodes are flow endpoints; their status is neutral — traffic says nothing
 *  about whether the object itself is healthy, so the graph does not claim it. */
export function buildTrafficGraph(flows: readonly TrafficFlow[]): TrafficGraph {
  const nodes = new Map<string, GraphNode>()
  const edges: GraphEdge[] = []
  const edgeLabels: Record<string, string> = {}
  const problemEdges = new Set<string>()
  const edgeWidths: Record<string, number> = {}
  const top = Math.max(0, ...flows.map((f) => f.requestRate ?? 0))
  const seenEdge = new Set<string>()
  for (const f of flows) {
    for (const e of [f.src, f.dst]) {
      const id = endpointId(e)
      if (!nodes.has(id)) nodes.set(id, { id, kind: e.kind, namespace: e.namespace, name: e.name, status: 'neutral' })
    }
    const id = flowId(f)
    if (seenEdge.has(id)) continue
    seenEdge.add(id)
    edges.push({ id, source: endpointId(f.src), target: endpointId(f.dst), type: f.protocol || 'traffic' })
    edgeLabels[id] = edgeLabel(f)
    if (isProblemFlow(f)) problemEdges.add(id)
    // 1.5–7px by request rate (square root, so a quiet edge stays visible
    // beside a busy one); an unmeasured rate keeps the default stroke.
    if (top > 0 && f.requestRate != null) edgeWidths[id] = 1.5 + 5.5 * Math.sqrt(f.requestRate / top)
  }
  return { nodes: [...nodes.values()], edges, edgeLabels, problemEdges, edgeWidths }
}

/** The graph draws at most this many flows (busiest first); the table below
 *  it always lists every flow the agent returned. */
export const GRAPH_FLOW_CAP = 150

export type TrafficSortKey = 'src' | 'dst' | 'requests' | 'errors' | 'bytes'

/** Sorts the complete returned set (not a page of it). Unmeasured values sort
 *  last in either direction, so "unknown" never reads as the smallest. */
export function sortFlows(flows: readonly TrafficFlow[], key: TrafficSortKey, dir: 'asc' | 'desc'): TrafficFlow[] {
  const val = (f: TrafficFlow): number | string | null => {
    switch (key) {
      case 'src':
        return endpointLabel(f.src)
      case 'dst':
        return endpointLabel(f.dst)
      case 'requests':
        return f.requestRate ?? null
      case 'errors':
        return errorPercent(f)
      case 'bytes':
        return f.bytesRate ?? null
    }
  }
  const sign = dir === 'asc' ? 1 : -1
  return [...flows].sort((a, b) => {
    const va = val(a)
    const vb = val(b)
    if (va === null && vb === null) return 0
    if (va === null) return 1
    if (vb === null) return -1
    if (typeof va === 'string' && typeof vb === 'string') return sign * va.localeCompare(vb)
    return sign * ((va as number) - (vb as number))
  })
}

/** Busiest flows first, for the graph cap. */
export function busiestFlows(flows: readonly TrafficFlow[], cap = GRAPH_FLOW_CAP): TrafficFlow[] {
  if (flows.length <= cap) return [...flows]
  return sortFlows(flows, 'requests', 'desc').slice(0, cap)
}

/** Why traffic is unavailable, as one accurate sentence per case. */
export function trafficUnavailableReason(r: TrafficResult | null | undefined): string {
  // An agent from before reasonCode said this only in config-key form.
  const code = r?.reasonCode ?? (/no Prometheus is configured/i.test(r?.reason ?? '') ? 'not_configured' : undefined)
  switch (code) {
    case 'not_configured':
      return `No Prometheus is connected to this cluster’s agent, so there are no traffic metrics to read. ${connectPrometheusHint(r?.detectedPrometheus, 'traffic')}`
    case 'unreachable':
      return 'The agent’s Prometheus did not answer, so traffic could not be read. Check that Prometheus is running and reachable from the agent.'
    case 'no_source':
      return r?.reason || 'Prometheus holds no service-mesh or eBPF traffic metrics (Istio, Beyla or OpenTelemetry eBPF instrumentation).'
    default:
      return r?.reason || 'The agent did not say why.'
  }
}
