import type {
  NetworkPolicyAllow,
  NetworkPolicyFinding,
  NetworkPolicyIndexRow,
  NetworkPolicyMap,
  NetworkPolicyPeer,
  NetworkPolicyWorkload,
} from '../api/types'
import type { BarPart } from '../components/SplitBar'

// The cluster page's Network policy tab, from get_network_policy_map
// (internal/agent/netpolmap). Pure helpers: labels, the isolation split, and
// which workloads a recommendation names.

export type { NetworkPolicyMap, NetworkPolicyWorkload, NetworkPolicyAllow, NetworkPolicyFinding, NetworkPolicyIndexRow }

/** Where a workload stands: the three groups the isolation bar draws. */
export type Isolation = 'restricted' | 'outboundOpen' | 'inboundOpen' | 'hostNetwork'

/** A direction is open when no policy restricts it, or when one does but a
 *  rule still admits anyone on every port (an allow-all policy): "selected"
 *  is not the same as "restricted". */
function openSide(isolated: boolean, allows: readonly NetworkPolicyAllow[]): boolean {
  return !isolated || allows.some((a) => a.peer.type === 'anywhere' && a.ports.includes('all ports'))
}

export function isolationOf(w: NetworkPolicyWorkload): Isolation {
  if (w.hostNetwork) return 'hostNetwork'
  if (openSide(w.ingressIsolated, w.ingress)) return 'inboundOpen'
  if (openSide(w.egressIsolated, w.egress)) return 'outboundOpen'
  return 'restricted'
}

export const ISOLATION_WORD: Record<Isolation, string> = {
  restricted: 'Inbound and outbound restricted',
  outboundOpen: 'Inbound restricted, outbound open',
  inboundOpen: 'Accepts from anyone',
  hostNetwork: 'Host network: policies do not apply',
}

export function isolationParts(workloads: readonly NetworkPolicyWorkload[]): BarPart[] {
  const n = { restricted: 0, outboundOpen: 0, inboundOpen: 0, hostNetwork: 0 }
  for (const w of workloads) n[isolationOf(w)]++
  return [
    { value: n.restricted, tone: 'ok', label: 'restricted both ways' },
    { value: n.outboundOpen, tone: 'medium', label: 'outbound open' },
    { value: n.inboundOpen, tone: 'high', label: 'accept from anyone' },
    { value: n.hostNetwork, tone: 'neutral', label: 'on the host network' },
  ]
}

export function workloadLabel(w: { kind: string; name: string }): string {
  return `${w.kind} ${w.name}`
}

/** A peer in words. `dir` decides "anyone" (inbound) vs "anywhere" (outbound). */
export function peerLabel(p: NetworkPolicyPeer, dir: 'in' | 'out', namespace: string): string {
  switch (p.type) {
    case 'anywhere':
      return dir === 'in' ? 'Anyone, including outside the cluster' : 'Anywhere'
    case 'namespace':
      return p.namespace === namespace ? 'Every pod in this namespace' : `Every pod in ${p.namespace}`
    case 'workload':
      return p.namespace === namespace ? `${p.kind} ${p.name}` : `${p.kind} ${p.name} in ${p.namespace}`
    case 'cidr': {
      const nodes = p.nodes?.length ? ` (node ${p.nodes.join(', ')})` : ''
      const except = p.except?.length ? ` except ${p.except.join(', ')}` : ''
      return `${p.cidr}${except}${nodes}`
    }
    default:
      return `Matches nothing: ${p.selector || 'empty selector'}`
  }
}

/** The tone a peer chip carries. Words always say the same thing. */
export function peerTone(a: NetworkPolicyAllow): 'open' | 'blocked' | 'dead' | 'plain' {
  if (a.effective === 'blocked') return 'blocked'
  if (a.peer.type === 'none') return 'dead'
  if (a.peer.type === 'anywhere' || (a.peer.type === 'cidr' && (a.peer.cidr === '0.0.0.0/0' || a.peer.cidr === '::/0'))) return 'open'
  return 'plain'
}

/** How many recommendations name this workload. Objects are written
 *  "Kind name" optionally followed by detail, so a prefix match on
 *  "Kind name" plus a separator is exact. */
export function findingsFor(w: NetworkPolicyWorkload, findings: readonly NetworkPolicyFinding[]): NetworkPolicyFinding[] {
  const label = workloadLabel(w)
  return findings.filter((f) => f.objects.some((o) => o === label || o.startsWith(`${label} `) || o.startsWith(`${label}:`)))
}

/** Workloads with a recommendation first, then the ones that accept from
 *  anyone, then by name. */
export function sortWorkloads(workloads: readonly NetworkPolicyWorkload[], findings: readonly NetworkPolicyFinding[]): NetworkPolicyWorkload[] {
  const weight = (w: NetworkPolicyWorkload) => {
    const fs = findingsFor(w, findings)
    if (fs.some((f) => f.severity === 'warning')) return 0
    if (fs.length > 0) return 1
    if (isolationOf(w) === 'inboundOpen') return 2
    return 3
  }
  return [...workloads].sort((a, b) => weight(a) - weight(b) || workloadLabel(a).localeCompare(workloadLabel(b)))
}

export type WorkloadFilter = 'all' | 'recommendations' | 'open'

export function filterWorkloads(
  workloads: readonly NetworkPolicyWorkload[],
  findings: readonly NetworkPolicyFinding[],
  filter: WorkloadFilter,
): NetworkPolicyWorkload[] {
  if (filter === 'recommendations') return workloads.filter((w) => findingsFor(w, findings).length > 0)
  if (filter === 'open') return workloads.filter((w) => isolationOf(w) === 'inboundOpen')
  return [...workloads]
}

/** Findings worst first: warnings, then reviews, keeping the agent's order. */
export function sortFindings(findings: readonly NetworkPolicyFinding[]): NetworkPolicyFinding[] {
  return [...findings].sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'warning' ? -1 : 1))
}

/** The namespace the tab opens on: the agent's index is already ordered
 *  most warnings first, then most policies. */
export function defaultPolicyNamespace(rows: readonly NetworkPolicyIndexRow[]): NetworkPolicyIndexRow | undefined {
  return rows[0]
}

export function totalWarnings(rows: readonly NetworkPolicyIndexRow[] | undefined): number | undefined {
  if (!rows) return undefined
  return rows.reduce((n, r) => n + r.warnings, 0)
}
