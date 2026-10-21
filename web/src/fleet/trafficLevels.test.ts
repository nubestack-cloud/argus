import { describe, expect, it } from 'vitest'
import { changeWords, flowsAround } from './trafficLevels'
import { compareWithTraffic, groupUnseen } from './policyVsTraffic'
import type { TrafficFlow } from './trafficModel'
import type { NetworkPolicyMap } from '../api/types'

const w = (namespace: string, name: string) => ({ namespace, name, kind: 'Workload' })
const node = (name: string) => ({ name, kind: 'External' })
const f = (src: TrafficFlow['src'], dst: TrafficFlow['dst'], bytesRate: number, extra: Partial<TrafficFlow> = {}): TrafficFlow => ({ src, dst, port: 0, protocol: 'tcp', bytesRate, ...extra })
const was = (bytesRate: number) => ({ before: { bytesRate } })

// Cut down from rke2 on 2026-10-15, with an hour-ago window: an app talking
// to its database pooler, DNS, an HTTP pair with 5xx, node traffic.
const flows: TrafficFlow[] = [
  f(w('nebula', 'nebula-api'), w('nebula', 'nebula-db-pooler-rw'), 136, was(140)),
  f(w('nebula', 'nebula-delivery'), w('nebula', 'nebula-db-pooler-rw'), 2729, was(9100)),
  f(w('kube-system', 'coredns'), w('nebula', 'nebula-api'), 4, { directionUnknown: true, ...was(4) }),
  f(w('argus-lab', 'loadgen'), w('argus-lab', 'oversized'), 1869, { protocol: 'http', requestRate: 4, errorRate: 0.2, ...was(1800) }),
  f(node('worker-1'), node('worker-2'), 227210, { directionUnknown: true, ...was(220000) }),
  f(node('worker-2'), w('nebula', 'nebula-api'), 84, was(84)),
  { ...f(w('nebula', 'nebula-control'), w('nebula', 'nebula-db-pooler-rw'), 0, was(1650)), bytesRate: undefined, stopped: true },
  f(w('nebula', 'nebula-quota'), w('nebula', 'nebula-db-pooler-rw'), 2900),
]

describe('changeWords', () => {
  it('says the change in words', () => {
    expect(changeWords(2729, 9100)).toBe('↓70%')
    expect(changeWords(3000, 1000)).toBe('↑3×')
    expect(changeWords(100, null)).toBeNull()
  })
})

describe('flowsAround', () => {
  it('splits callers from callees, keeps a caller that stopped, and counts an undirected peer as a caller', () => {
    const { callers } = flowsAround(flows, 'nebula', 'nebula-db-pooler-rw')
    expect(callers.map((c) => c.peer.name)).toEqual(['nebula-delivery', 'nebula-quota', 'nebula-control', 'nebula-api'])
    expect(callers.find((c) => c.peer.name === 'nebula-control')!.now).toBeNull()
    // A directed and an undirected flow from the same peer are one row.
    const twice = [...flows, f(w('nebula', 'nebula-delivery'), w('nebula', 'nebula-db-pooler-rw'), 100, { directionUnknown: true, ...was(100) })]
    const merged = flowsAround(twice, 'nebula', 'nebula-db-pooler-rw').callers.filter((c) => c.peer.name === 'nebula-delivery')
    expect(merged).toHaveLength(1)
    expect(merged[0].now).toBe(2829)
    expect(merged[0].flow.directionUnknown).toBe(false)
    const api = flowsAround(flows, 'nebula', 'nebula-api')
    expect(api.callers.map((c) => c.peer.name)).toEqual(['worker-2', 'coredns'])
    expect(api.callees.map((c) => c.peer.name)).toEqual(['nebula-db-pooler-rw'])
  })
})

describe('compareWithTraffic', () => {
  const map = {
    namespace: 'nebula',
    workloads: [
      {
        kind: 'Deployment', name: 'nebula-db-pooler-rw', pods: 1, ingressIsolated: true, egressIsolated: false, policies: ['db'],
        ingress: [{ peer: { type: 'workload', namespace: 'nebula', name: 'nebula-api' }, ports: ['TCP 5432'] }, { peer: { type: 'namespace', namespace: 'nebula-ops' }, ports: ['TCP 5432'] }],
        egress: [],
      },
      {
        kind: 'Deployment', name: 'nebula-api', pods: 1, ingressIsolated: false, egressIsolated: true, policies: ['api'],
        ingress: [],
        egress: [{ peer: { type: 'workload', namespace: 'nebula', name: 'nebula-db-pooler-rw' }, ports: ['TCP 5432'] }, { peer: { type: 'namespace', namespace: 'kube-system' }, ports: ['UDP 53'] }],
      },
    ],
  } as unknown as NetworkPolicyMap

  it('finds traffic no rule admits, and rules nothing used — but not DNS, whose direction is unknown', () => {
    // A kubelet probe from the node: always allowed to a pod on that node,
    // and the flow does not say which node the pod is on (live on rke2).
    const probe = f(node('worker-2'), w('nebula', 'nebula-db-pooler-rw'), 27)
    const cmp = compareWithTraffic(map, [...flows, probe], 'nebula')
    // nebula-control stopped an hour ago, so it is not judged as traffic now.
    expect(cmp.seenNotAllowed.map((x) => `${x.peer.name}>${x.workload.name}`)).toEqual(['nebula-delivery>nebula-db-pooler-rw', 'nebula-quota>nebula-db-pooler-rw'])
    // The nebula-ops rule saw nothing; the kube-system DNS rule did (undirected).
    expect(cmp.allowedNotSeen.map((x) => x.allow.peer.namespace)).toEqual(['nebula-ops'])
    expect(cmp.undecided).toBe(2)
    expect(groupUnseen(cmp.allowedNotSeen).map((g) => [g.workload.name, g.allows.length])).toEqual([['nebula-db-pooler-rw', 1]])
  })
})
