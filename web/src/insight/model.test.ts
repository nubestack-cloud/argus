import { describe, expect, it } from 'vitest'
import type { ResourceChange } from '../api/types'
import {
  changeWhat,
  containersOf,
  coverageNote,
  filterLogLines,
  graphPartialNote,
  groupChangesByOwner,
  neighborhoodGraph,
  perPodResourceLines,
  replicasOf,
  serviceAccountOf,
  splitRedacted,
  statusCount,
  tabsFor,
} from './model'
import type { KubeObject } from './types'

describe('tabsFor', () => {
  it('offers logs, permissions, rollout and connectivity on a Deployment', () => {
    const t = tabsFor('Deployment', 'apps', null)
    expect(t).toEqual(expect.arrayContaining(['summary', 'yaml', 'events', 'logs', 'changes', 'related', 'permissions', 'policy', 'rollout', 'path']))
    expect(t).not.toContain('scheduling')
  })

  it('offers path on a Service and scheduling only on a Pending Pod', () => {
    expect(tabsFor('Service', undefined, null)).toContain('path')
    expect(tabsFor('Pod', undefined, { kind: 'Pod', status: { phase: 'Running' } })).not.toContain('scheduling')
    expect(tabsFor('Pod', undefined, { kind: 'Pod', status: { phase: 'Pending' } })).toContain('scheduling')
  })

  // The live defect: a Pending pod already bound to a node and stuck
  // ContainerCreating on FailedAttachVolume got a Scheduling tab that blamed
  // scheduler predicates.
  it('offers no Scheduling tab for a Pending pod that is already scheduled', () => {
    const stuck: KubeObject = {
      kind: 'Pod',
      spec: { nodeName: 'lab-worker-2', containers: [{ name: 'app' }] },
      status: {
        phase: 'Pending',
        conditions: [
          { type: 'PodScheduled', status: 'True' },
          { type: 'Initialized', status: 'True' },
          { type: 'ContainersReady', status: 'False', reason: 'ContainersNotReady' },
        ],
        containerStatuses: [{ name: 'app', ready: false, restartCount: 0, state: { waiting: { reason: 'ContainerCreating' } } }],
      },
    }
    const t = tabsFor('Pod', undefined, stuck)
    expect(t).not.toContain('scheduling')
    expect(t[1]).not.toBe('scheduling')
    // Bound by condition alone (nodeName not yet in the cached spec) counts too.
    expect(tabsFor('Pod', undefined, { kind: 'Pod', status: { phase: 'Pending', conditions: [{ type: 'PodScheduled', status: 'True' }] } })).not.toContain('scheduling')
    // Unschedulable is still offered, and leads.
    const unsched: KubeObject = { kind: 'Pod', status: { phase: 'Pending', conditions: [{ type: 'PodScheduled', status: 'False', reason: 'Unschedulable' }] } }
    expect(tabsFor('Pod', undefined, unsched)[1]).toBe('scheduling')
  })

  it('adds GitOps and Helm from the object content', () => {
    const obj: KubeObject = {
      metadata: { labels: { 'kustomize.toolkit.fluxcd.io/name': 'apps' }, annotations: { 'meta.helm.sh/release-name': 'web' } },
    }
    const t = tabsFor('ConfigMap', undefined, obj)
    expect(t).toContain('gitops')
    expect(t).toContain('helm')
    expect(tabsFor('Application', 'argoproj.io', null)).toContain('gitops')
    expect(tabsFor('HorizontalPodAutoscaler', 'autoscaling', null)).toContain('autoscaler')
  })
})

describe('summary facts', () => {
  const pod: KubeObject = {
    kind: 'Pod',
    spec: { containers: [{ name: 'app', image: 'r/app:1' }], initContainers: [{ name: 'init', image: 'r/init:1' }] },
    status: {
      phase: 'Running',
      containerStatuses: [{ name: 'app', ready: false, restartCount: 4, state: { waiting: { reason: 'CrashLoopBackOff' } } }],
    },
  }

  it('reads containers with their state', () => {
    const c = containersOf(pod)
    expect(c).toHaveLength(2)
    expect(c[1]).toMatchObject({ name: 'app', image: 'r/app:1', ready: false, restartCount: 4, state: 'waiting (CrashLoopBackOff)' })
    expect(c[0]).toMatchObject({ name: 'init', init: true, ready: undefined })
  })

  it('reads a workload template and defaults the service account', () => {
    const dep: KubeObject = { kind: 'Deployment', spec: { replicas: 3, template: { spec: { containers: [{ name: 'a', image: 'i' }] } } } }
    expect(containersOf(dep)[0].image).toBe('i')
    expect(serviceAccountOf(dep)).toBe('default')
    expect(serviceAccountOf({ kind: 'Pod', spec: { containers: [], serviceAccountName: 'api' } })).toBe('api')
    expect(serviceAccountOf({ kind: 'ConfigMap', data: {} })).toBeUndefined()
  })

  it('never invents a replica count', () => {
    const r = replicasOf({ kind: 'Deployment', spec: { replicas: 3 }, status: {} })
    expect(r).toEqual({ desired: 3, ready: undefined, updated: undefined, available: undefined })
    expect(replicasOf({ kind: 'Pod' })).toBeNull()
    // The API omits a zero count from an observed status; that is a real 0.
    expect(statusCount({ status: { observedGeneration: 2 } }, undefined)).toBe(0)
    expect(statusCount({ status: {} }, undefined)).toBeUndefined()
  })
})

describe('splitRedacted', () => {
  it('marks every redacted span', () => {
    expect(splitRedacted('  password: [REDACTED]')).toEqual([
      { text: '  password: ', redacted: false },
      { text: '[REDACTED]', redacted: true },
    ])
    expect(splitRedacted('plain')).toEqual([{ text: 'plain', redacted: false }])
  })
})

describe('filterLogLines', () => {
  it('filters case-insensitively and keeps everything for an empty query', () => {
    expect(filterLogLines(['Error: x', 'ok', 'error y'], 'ERROR')).toEqual(['Error: x', 'error y'])
    expect(filterLogLines(['a', 'b'], '  ')).toEqual(['a', 'b'])
  })
})

describe('coverageNote', () => {
  it('names each missing kind with its reason', () => {
    expect(coverageNote([{ group: 'wgpolicyk8s.io', kind: 'PolicyReport', state: 'absent', reason: 'CRD not installed' }])).toMatch(
      /Incomplete: .*PolicyReport\.wgpolicyk8s\.io absent \(CRD not installed\)/,
    )
    expect(coverageNote([])).toBeNull()
  })
})

describe('neighborhoodGraph', () => {
  it('finds the root and drops edges to unknown nodes', () => {
    const g = neighborhoodGraph({
      root: { kind: 'Deployment', namespace: 'p', name: 'api' },
      nodes: [
        { id: 'a', kind: 'Pod', namespace: 'p', name: 'api-1', status: 'unhealthy' },
        { id: 'b', kind: 'Deployment', namespace: 'p', name: 'api', status: 'healthy' },
      ],
      edges: [
        { id: 'e1', source: 'b', target: 'a', type: 'owns' },
        { id: 'e2', source: 'b', target: 'zzz', type: 'uses' },
      ],
    })
    expect(g.rootId).toBe('b')
    expect(g.edges).toHaveLength(1)
    expect(g.nodes[0].status).toBe('unhealthy')
  })

  it('states why a graph is partial', () => {
    expect(graphPartialNote({ truncated: true, omitted: 2, unavailable: ['NetworkPolicy'] })).toMatch(/size cap.*2 objects were left out.*NetworkPolicy/)
    expect(graphPartialNote({})).toBeNull()
  })
})

function change(over: Partial<ResourceChange>): ResourceChange {
  return { id: 'c', clusterId: 'k', observedAt: '2026-10-10T14:02:00Z', kind: 'Deployment', name: 'payments', namespace: 'p', op: 'update', fields: [], ...over }
}

describe('changeWhat', () => {
  it('prefers the agent summary, spacing its arrows', () => {
    expect(changeWhat(change({ summary: 'image app: v1.4→v1.5' }))).toBe('image app: v1.4 → v1.5')
  })
  it('falls back to field paths, then to the operation', () => {
    expect(changeWhat(change({ fields: [{ path: 'spec.replicas', oldValue: 2, newValue: 3 }] }))).toBe('spec.replicas: 2 → 3')
    expect(changeWhat(change({ op: 'delete' }))).toBe('deleted')
    expect(changeWhat(change({ op: 'add' }))).toBe('created')
  })
})

describe('groupChangesByOwner', () => {
  it('groups by owner, newest first, with true counts', () => {
    const groups = groupChangesByOwner([
      change({ id: '1', kind: 'ReplicaSet', name: 'payments-abc', ownerKind: 'Deployment', ownerName: 'payments', observedAt: '2026-10-10T14:00:00Z' }),
      change({ id: '2', kind: 'Deployment', name: 'payments', observedAt: '2026-10-10T14:02:00Z' }),
      change({ id: '3', kind: 'ConfigMap', name: 'cfg', observedAt: '2026-10-10T13:00:00Z' }),
    ])
    expect(groups.map((g) => g.label)).toEqual(['Deployment/payments', 'ConfigMap/cfg'])
    expect(groups[0].changes.map((c) => c.id)).toEqual(['2', '1'])
  })
})

// PROJECT.md AD7: the Metrics tab's request and limit lines.
describe('perPodResourceLines', () => {
  const deploy = (containers: unknown[], podResources?: unknown): KubeObject => ({
    kind: 'Deployment',
    spec: { template: { spec: { containers, ...(podResources ? { resources: podResources } : {}) } } },
  })

  it('sums every container for one pod', () => {
    const obj = deploy([
      { name: 'app', resources: { requests: { cpu: '250m', memory: '256Mi' }, limits: { cpu: '1', memory: '512Mi' } } },
      { name: 'proxy', resources: { requests: { cpu: '50m', memory: '64Mi' }, limits: { cpu: '200m', memory: '128Mi' } } },
    ])
    expect(perPodResourceLines(obj, 'cpu')).toEqual([
      { value: 0.3, label: 'request per pod', kind: 'request' },
      { value: 1.2, label: 'limit per pod', kind: 'limit' },
    ])
    expect(perPodResourceLines(obj, 'memory').map((l) => l.value)).toEqual([320 * 1024 ** 2, 640 * 1024 ** 2])
  })

  it('draws no line when any container leaves the value unset', () => {
    const obj = deploy([
      { name: 'app', resources: { requests: { cpu: '250m' }, limits: { cpu: '1' } } },
      { name: 'sidecar', resources: { requests: { cpu: '50m' } } },
    ])
    expect(perPodResourceLines(obj, 'cpu')).toEqual([{ value: 0.3, label: 'request per pod', kind: 'request' }])
    expect(perPodResourceLines(obj, 'memory')).toEqual([])
  })

  it('prefers pod-level resources over the containers', () => {
    const obj = deploy([{ name: 'app' }], { requests: { memory: '1Gi' } })
    expect(perPodResourceLines(obj, 'memory')).toEqual([{ value: 1024 ** 3, label: 'request per pod', kind: 'request' }])
  })

  it('offers the Metrics tab on pods and workloads only', () => {
    expect(tabsFor('Deployment', 'apps', null)).toContain('metrics')
    expect(tabsFor('Pod', undefined, null)).toContain('metrics')
    expect(tabsFor('Service', undefined, null)).not.toContain('metrics')
  })
})
