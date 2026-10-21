// The Network policy tab against observed traffic (owner, 2026-10-15): the
// policy map says what may talk; the traffic source says what did. Two lists
// come out of comparing them:
//   seen, not allowed — traffic into or out of a workload whose policies
//     isolate that side, which no rule admits. Either the CNI is not enforcing
//     NetworkPolicy, or ARGUS's reading of the policies is wrong; both matter.
//   allowed, not seen — a rule naming a workload or namespace with no
//     matching traffic in the window. A hint for tightening, never proof a
//     rule is unused: the window is minutes long.
// A flow whose direction the source could not establish (DNS, mostly) is
// skipped, since which side's rules apply depends on who began it. A peer
// ARGUS cannot match exactly (a selector it did not resolve to names) makes
// the answer "cannot tell", which is counted, not guessed.
import type { NetworkPolicyAllow, NetworkPolicyMap, NetworkPolicyWorkload } from '../api/types'
import type { TrafficEndpoint, TrafficFlow } from './trafficModel'

type Match = 'yes' | 'no' | 'unknown'

/** Whether one rule's peer admits an endpoint. */
export function peerMatches(a: NetworkPolicyAllow, e: TrafficEndpoint, namespace: string): Match {
  const p = a.peer
  switch (p.type) {
    case 'anywhere':
      return 'yes'
    case 'none':
      return 'no'
    case 'namespace':
      if (!e.namespace) return 'no'
      return !p.namespace || p.namespace === e.namespace ? 'yes' : 'no'
    case 'workload':
      if (!e.namespace) return 'no'
      if ((p.namespace ?? namespace) !== e.namespace) return 'no'
      if (!p.name) return 'unknown'
      return p.name === e.name ? 'yes' : 'no'
    case 'cidr':
      // Node addresses are the one CIDR peer ARGUS can name; a host-network
      // endpoint in the traffic is reported by node name.
      if (e.namespace) return 'unknown'
      return (p.nodes ?? []).includes(e.name) ? 'yes' : 'unknown'
    default:
      return 'unknown'
  }
}

function admitted(allows: readonly NetworkPolicyAllow[], peer: TrafficEndpoint, namespace: string): Match {
  let unknown = false
  for (const a of allows) {
    if (a.effective === 'blocked') continue
    const m = peerMatches(a, peer, namespace)
    if (m === 'yes') return 'yes'
    if (m === 'unknown') unknown = true
  }
  return unknown ? 'unknown' : 'no'
}

export interface SeenNotAllowed {
  workload: NetworkPolicyWorkload
  side: 'ingress' | 'egress'
  peer: TrafficEndpoint
  flow: TrafficFlow
}

export interface AllowedNotSeen {
  workload: NetworkPolicyWorkload
  side: 'ingress' | 'egress'
  allow: NetworkPolicyAllow
}

export interface PolicyTrafficComparison {
  seenNotAllowed: SeenNotAllowed[]
  allowedNotSeen: AllowedNotSeen[]
  /** Flows checked against an isolated side, and those that could not be
   *  decided (direction unknown, or a peer ARGUS cannot match by name). */
  checked: number
  undecided: number
}

export function compareWithTraffic(map: NetworkPolicyMap, flows: readonly TrafficFlow[], namespace: string): PolicyTrafficComparison {
  const workloads = map.workloads ?? []
  const byName = new Map(workloads.map((w) => [w.name, w]))
  const used = new Set<NetworkPolicyAllow>()
  const out: PolicyTrafficComparison = { seenNotAllowed: [], allowedNotSeen: [], checked: 0, undecided: 0 }
  const check = (w: NetworkPolicyWorkload | undefined, side: 'ingress' | 'egress', peer: TrafficEndpoint, f: TrafficFlow) => {
    if (!w || w.hostNetwork) return
    const isolated = side === 'ingress' ? w.ingressIsolated : w.egressIsolated
    if (!isolated) return
    out.checked++
    const allows = side === 'ingress' ? w.ingress : w.egress
    for (const a of allows) if (a.effective !== 'blocked' && peerMatches(a, peer, namespace) === 'yes') used.add(a)
    const m = admitted(allows, peer, namespace)
    // Traffic between a pod and the node it runs on is always allowed,
    // whatever the policies say (kubelet probes, above all), and a flow does
    // not say which node the pod is on: a node no rule names is not judged.
    if (m === 'no' && !peer.namespace) out.undecided++
    else if (m === 'no') out.seenNotAllowed.push({ workload: w, side, peer, flow: f })
    else if (m === 'unknown') out.undecided++
  }
  for (const f of flows) {
    // A flow seen only in the comparison window is not traffic now.
    if (f.stopped) continue
    if (f.src.namespace === namespace && f.dst.namespace === namespace && f.src.name === f.dst.name) continue
    if (f.directionUnknown) {
      // Not judged, but it still shows a rule in use (DNS above all), so a
      // rule it could match is not listed as unseen.
      for (const [self, peer] of [[f.src, f.dst], [f.dst, f.src]] as const) {
        const w = self.namespace === namespace ? byName.get(self.name) : undefined
        if (!w) continue
        for (const a of [...w.ingress, ...w.egress]) if (peerMatches(a, peer, namespace) === 'yes') used.add(a)
      }
      if (f.src.namespace === namespace || f.dst.namespace === namespace) out.undecided++
      continue
    }
    if (f.dst.namespace === namespace) check(byName.get(f.dst.name), 'ingress', f.src, f)
    if (f.src.namespace === namespace) check(byName.get(f.src.name), 'egress', f.dst, f)
  }
  for (const w of workloads) {
    for (const [side, allows, isolated] of [['ingress', w.ingress, w.ingressIsolated], ['egress', w.egress, w.egressIsolated]] as const) {
      if (!isolated) continue
      for (const a of allows) {
        if (a.effective === 'blocked' || used.has(a)) continue
        if (a.peer.type === 'workload' || a.peer.type === 'namespace') out.allowedNotSeen.push({ workload: w, side, allow: a })
      }
    }
  }
  return out
}

export interface UnseenGroup {
  workload: NetworkPolicyWorkload
  side: 'ingress' | 'egress'
  allows: NetworkPolicyAllow[]
}

/** Unseen rules grouped by workload and direction, most first: one row per
 *  workload rather than one per rule. */
export function groupUnseen(items: readonly AllowedNotSeen[]): UnseenGroup[] {
  const by = new Map<string, UnseenGroup>()
  for (const x of items) {
    const k = `${x.workload.kind}/${x.workload.name}|${x.side}`
    const g = by.get(k) ?? { workload: x.workload, side: x.side, allows: [] }
    g.allows.push(x.allow)
    by.set(k, g)
  }
  return [...by.values()].sort((a, b) => b.allows.length - a.allows.length || a.workload.name.localeCompare(b.workload.name))
}
