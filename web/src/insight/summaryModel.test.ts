import { describe, expect, it } from 'vitest'
import { tabsFor } from './model'
import { conditionVerdict, connectedObjects, objectHealth, replicaBar, sortedConditions, workloadPods } from './summaryModel'
import type { KubeObject, NeighborhoodResult } from './types'

const dep = (status: Record<string, unknown>, replicas = 2): KubeObject => ({
  kind: 'Deployment',
  spec: { replicas, strategy: { type: 'RollingUpdate', rollingUpdate: { maxUnavailable: 0, maxSurge: '25%' } }, template: { spec: { containers: [] } } },
  status,
})

describe('conditionVerdict', () => {
  it('reads True as good except on the negative condition types', () => {
    expect(conditionVerdict({ type: 'Available', status: 'True' })).toBe('ok')
    expect(conditionVerdict({ type: 'Progressing', status: 'False' })).toBe('failing')
    expect(conditionVerdict({ type: 'MemoryPressure', status: 'True' })).toBe('failing')
    expect(conditionVerdict({ type: 'MemoryPressure', status: 'False' })).toBe('ok')
    expect(conditionVerdict({ type: 'Ready', status: 'Unknown' })).toBe('unknown')
  })

  it('sorts failing first, then unknown, then passing, keeping order within each', () => {
    const out = sortedConditions([
      { type: 'A', status: 'True' },
      { type: 'B', status: 'Unknown' },
      { type: 'C', status: 'False' },
      { type: 'D', status: 'False' },
    ])
    expect(out.map((c) => c.type)).toEqual(['C', 'D', 'B', 'A'])
  })
})

describe('objectHealth', () => {
  it('names the failing condition for a stuck rollout', () => {
    const h = objectHealth(
      dep({ observedGeneration: 1, readyReplicas: 2, updatedReplicas: 1, conditions: [{ type: 'Progressing', status: 'False', reason: 'ProgressDeadlineExceeded' }] }),
    )
    expect(h).toEqual({ word: 'Degraded', reason: 'Progressing is False: ProgressDeadlineExceeded' })
  })

  it('is Healthy only when every desired replica is ready and updated', () => {
    expect(objectHealth(dep({ observedGeneration: 1, readyReplicas: 2, updatedReplicas: 2 }))?.word).toBe('Healthy')
    expect(objectHealth(dep({ observedGeneration: 1, readyReplicas: 2, updatedReplicas: 1 }))?.word).toBe('Progressing')
    expect(objectHealth(dep({ observedGeneration: 1, readyReplicas: 1, updatedReplicas: 2 }))).toEqual({ word: 'Degraded', reason: '1 of 2 replicas ready' })
  })

  it('treats an omitted readyReplicas on an observed status as the API zero, and no status as unknown', () => {
    expect(objectHealth(dep({ observedGeneration: 1 }))?.reason).toBe('0 of 2 replicas ready')
    expect(objectHealth(dep({}))?.word).toBe('Unknown')
  })

  it('says scaled to zero rather than healthy or degraded', () => {
    expect(objectHealth(dep({ observedGeneration: 1 }, 0))?.word).toBe('Scaled to zero')
  })

  it('reads a crash-looping pod as Failing with the container named', () => {
    const pod: KubeObject = {
      kind: 'Pod',
      spec: { containers: [{ name: 'app' }] },
      status: { phase: 'Running', containerStatuses: [{ name: 'app', ready: false, state: { waiting: { reason: 'CrashLoopBackOff' } } }] },
    }
    expect(objectHealth(pod)).toEqual({ word: 'Failing', reason: 'Container app is waiting: CrashLoopBackOff' })
  })

  it('reads an unschedulable pod as Pending with the scheduler condition', () => {
    const pod: KubeObject = {
      kind: 'Pod',
      spec: { containers: [{ name: 'app' }] },
      status: { phase: 'Pending', conditions: [{ type: 'PodScheduled', status: 'False', reason: 'Unschedulable' }] },
    }
    expect(objectHealth(pod)).toEqual({ word: 'Pending', reason: 'PodScheduled is False: Unschedulable' })
  })

  it('gives a kind with no health signal no header at all', () => {
    expect(objectHealth({ kind: 'ConfigMap', metadata: { name: 'x' } })).toBeNull()
    expect(objectHealth({ kind: 'Service', spec: {}, status: {} })).toBeNull()
  })

  it('reads a node by Ready first, then its pressure conditions', () => {
    const node = (conds: { type: string; status: string }[]): KubeObject => ({ kind: 'Node', status: { conditions: conds } })
    expect(objectHealth(node([{ type: 'Ready', status: 'True' }]))?.word).toBe('Healthy')
    expect(objectHealth(node([{ type: 'Ready', status: 'True' }, { type: 'DiskPressure', status: 'True' }]))?.word).toBe('Degraded')
    expect(objectHealth(node([{ type: 'Ready', status: 'Unknown' }]))?.word).toBe('Failing')
  })
})

describe('replicaBar', () => {
  it('splits desired into ready and not ready, with the strategy in the detail line', () => {
    const bar = replicaBar(dep({ observedGeneration: 1, readyReplicas: 1, updatedReplicas: 2, availableReplicas: 1 }))
    expect(bar).toEqual({
      desired: 2,
      existing: 2,
      ready: 1,
      notReady: 1,
      detail: 'Desired 2 · updated 2 · available 1 · RollingUpdate (maxUnavailable 0, maxSurge 25%)',
    })
  })

  it('draws the replicas that exist when a rollout has surged past desired', () => {
    const bar = replicaBar(dep({ observedGeneration: 1, replicas: 2, readyReplicas: 1, updatedReplicas: 1 }, 1))
    expect(bar).toMatchObject({ desired: 1, existing: 2, ready: 1, notReady: 1 })
    expect(bar?.detail.startsWith('Desired 1 · existing 2 ·')).toBe(true)
  })

  it('draws nothing when the ready count is unknown or nothing is desired', () => {
    expect(replicaBar(dep({}))).toBeNull()
    expect(replicaBar(dep({ observedGeneration: 1 }, 0))).toBeNull()
    expect(replicaBar({ kind: 'ConfigMap' })).toBeNull()
  })
})

describe('workloadPods / connectedObjects', () => {
  const r: NeighborhoodResult = {
    root: { kind: 'Deployment', namespace: 'ns', name: 'api' },
    nodes: [
      { id: 'd', kind: 'Deployment', namespace: 'ns', name: 'api', status: 'healthy' },
      { id: 'p', kind: 'Pod', namespace: 'ns', name: 'api-1', status: 'healthy', summary: { phase: 'Running', nodeName: 'n1', restarts: 2 } },
      {
        id: 'g',
        kind: 'PodGroup',
        namespace: 'ns',
        name: 'api',
        status: 'degraded',
        summary: { podCount: 7, pods: [{ name: 'api-9', status: 'unhealthy', statusReason: 'CrashLoopBackOff' }] },
      },
      { id: 'o', kind: 'Pod', namespace: 'ns', name: 'other', status: 'healthy' },
      { id: 's', kind: 'Service', namespace: 'ns', name: 'api', status: 'neutral' },
    ],
    edges: [
      { id: '1', source: 'd', target: 'p', type: 'owns' },
      { id: '2', source: 'd', target: 'g', type: 'owns' },
      { id: '3', source: 's', target: 'o', type: 'routes-to' },
      { id: '4', source: 's', target: 'd', type: 'exposes' },
    ],
  }

  it('lists only owned pods, worst first, and counts collapsed members it did not list', () => {
    const pods = workloadPods(r)
    expect(pods.total).toBe(8)
    expect(pods.rows.map((p) => p.name)).toEqual(['api-9', 'api-1'])
    expect(pods.rows[1]).toMatchObject({ phase: 'Running', node: 'n1', restarts: 2, grouped: false })
  })

  it('previews adjacent non-pod objects only', () => {
    expect(connectedObjects(r).map((n) => `${n.kind}/${n.name}`)).toEqual(['Service/api'])
  })
})

describe('tabsFor — every tab on the row, most useful first', () => {
  const pending = { status: { phase: 'Pending' } } as never

  it('leads a Deployment with Rollout, then what is happening, and ends on YAML', () => {
    expect(tabsFor('Deployment', 'apps', null)).toEqual([
      'summary', 'rollout', 'events', 'logs', 'metrics', 'related', 'path', 'changes', 'permissions', 'policy', 'yaml',
    ])
  })

  it('leads a Pending pod with Scheduling, and gives every pod Connectivity', () => {
    const tabs = tabsFor('Pod', '', pending)
    expect(tabs.slice(0, 3)).toEqual(['summary', 'scheduling', 'events'])
    expect(tabs).toContain('path')
    expect(tabs[tabs.length - 1]).toBe('yaml')
  })

  it('leads a Service with Connectivity', () => {
    expect(tabsFor('Service', '', null).slice(0, 2)).toEqual(['summary', 'path'])
  })

  it('leads an autoscaler and a service account with their own question', () => {
    expect(tabsFor('HorizontalPodAutoscaler', 'autoscaling', null)[1]).toBe('autoscaler')
    expect(tabsFor('ServiceAccount', '', null)[1]).toBe('permissions')
  })

  it('offers no Connectivity where nothing routes, e.g. a ConfigMap', () => {
    expect(tabsFor('ConfigMap', '', null)).not.toContain('path')
  })
})
