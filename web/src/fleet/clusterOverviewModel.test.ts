import { describe, expect, it } from 'vitest'
import type { Incident, ResourceChange } from '../api/types'
import {
  certificatesExpiring,
  changeActivity,
  incidentsOpenedIn,
  inventoryGroups,
  openIncidentOn,
  opsText,
  postureDangerCount,
  recentlyClosed,
  windowGaps,
} from './clusterOverviewModel'

const change = (id: string, at: string, kind: string, name: string, ownerKind?: string, ownerName?: string, op: ResourceChange['op'] = 'update'): ResourceChange => ({
  id,
  clusterId: 'c',
  observedAt: at,
  kind,
  name,
  namespace: 'ns',
  ownerKind,
  ownerName,
  op,
  fields: [],
})

const incident = (over: Partial<Incident>): Incident =>
  ({
    id: 'i1',
    clusterId: 'c',
    clusterDisplayName: 'c',
    fingerprint: 'f',
    severity: 'high',
    state: 'Investigating',
    firstSeen: '2026-10-10T10:00:00Z',
    lastSeen: '2026-10-10T10:00:00Z',
    occurrenceCount: 1,
    ...over,
  }) as Incident

describe('inventoryGroups', () => {
  it('keeps every count with its detail, flags only the problem parts, and says why one is absent', () => {
    const groups = inventoryGroups({
      jobs: { total: 3, active: 1, succeeded: 1, failed: 1 },
      deployments: { total: 29, ready: 28, notReady: 1, scaledToZero: 1 },
      unavailable: ['services'],
    })
    expect(groups.map((g) => g.title)).toEqual(['Workloads', 'Batch', 'Networking', 'Config and storage'])
    const items = groups.flatMap((g) => g.items)
    expect(items.map((i) => i.label)).toEqual([
      'Deployments',
      'StatefulSets',
      'DaemonSets',
      'Jobs',
      'CronJobs',
      'Services',
      'Ingresses',
      'Namespaces',
      'ConfigMaps',
      'PersistentVolumeClaims',
    ])
    expect(items.find((i) => i.key === 'jobs')).toMatchObject({ value: 3, detail: [{ text: '1 failed', problem: true }, { text: '1 active', problem: false }] })
    expect(items.find((i) => i.key === 'deployments')?.detail).toEqual([
      { text: '1 not ready', problem: true },
      { text: '1 scaled to zero', problem: false },
    ])
    expect(items.find((i) => i.key === 'services')).toMatchObject({ value: null, absence: 'unavailable' })
    expect(items.find((i) => i.key === 'ingresses')).toMatchObject({ value: null, absence: 'unknown' })
  })
})

describe('changeActivity', () => {
  const start = Date.parse('2026-10-10T10:00:00Z')
  const end = start + 60 * 60 * 1000
  it('bins changes in the window, groups by owner newest first, and counts hidden objects and ops', () => {
    const out = changeActivity(
      [
        change('1', '2026-10-10T10:30:00Z', 'Pod', 'api-1', 'Deployment', 'api', 'delete'),
        change('2', '2026-10-10T10:45:00Z', 'Deployment', 'api'),
        change('3', '2026-10-10T10:50:00Z', 'ConfigMap', 'cfg', undefined, undefined, 'add'),
        change('4', '2026-10-10T09:00:00Z', 'Pod', 'old'),
      ],
      start,
      end,
      12,
      1,
    )
    expect(out.total).toBe(3)
    expect(out.bins).toEqual([0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0])
    expect(out.peak).toBe(1)
    expect(out.objects).toHaveLength(1)
    expect(out.objects[0]).toMatchObject({ kind: 'ConfigMap', name: 'cfg', count: 1, created: 1 })
    expect(out.hidden).toBe(1)
    expect(opsText({ created: 0, deleted: 1, updated: 1 })).toBe('1 changed · 1 deleted')
  })

  it('places incidents first seen in the window and matches one to a changed owner', () => {
    const inc = incident({ firstSeen: '2026-10-10T10:15:00Z', workloadKey: 'apps/v1/Deployment|ns|api', severity: 'critical' })
    const old = incident({ id: 'i2', firstSeen: '2026-10-09T10:15:00Z', objectName: 'cfg', objectGvk: 'v1/ConfigMap' })
    expect(incidentsOpenedIn([inc, old], start, end)).toEqual([{ incident: inc, at: 0.25 }])
    expect(openIncidentOn({ kind: 'Deployment', name: 'api', namespace: 'ns' }, [inc, old])?.id).toBe('i1')
    expect(openIncidentOn({ kind: 'ConfigMap', name: 'cfg', namespace: 'ns' }, [inc, old])?.id).toBe('i2')
    expect(openIncidentOn({ kind: 'Deployment', name: 'web', namespace: 'ns' }, [inc, old])).toBeNull()
    expect(openIncidentOn({ kind: 'Deployment', name: 'api', namespace: 'ns' }, [{ ...inc, state: 'Resolved' }])).toBeNull()
  })

  it('reports only gaps that overlap the window', () => {
    expect(
      windowGaps(
        [
          { from: '2026-10-10T08:00:00Z', to: '2026-10-10T09:00:00Z', reason: 'old' },
          { from: '2026-10-10T10:10:00Z', to: '2026-10-10T10:20:00Z', reason: 'agent restarted' },
        ],
        start,
        end,
      ),
    ).toEqual(['agent restarted'])
  })
})

describe('recentlyClosed', () => {
  it('fills only the rows left, most recently closed first, never an open incident', () => {
    const list = [
      incident({ id: 'open' }),
      incident({ id: 'a', state: 'Resolved', resolvedAt: '2026-10-10T09:00:00Z' }),
      incident({ id: 'b', state: 'Dismissed', lastSeen: '2026-10-10T11:00:00Z' }),
    ]
    expect(recentlyClosed(list, 5).map((i) => i.id)).toEqual(['b', 'a'])
    expect(recentlyClosed(list, 0)).toEqual([])
  })
})

describe('checks', () => {
  it('counts danger findings and marks a truncated answer as a lower bound', () => {
    expect(postureDangerCount({ findings: [{ severity: 'danger' }, { severity: 'warning' }], truncated: true })).toEqual({ value: 1, atLeast: true })
    expect(postureDangerCount(undefined)).toBeNull()
  })

  it('counts expiring certificates and keeps unknown expiry separate, never as expiring', () => {
    expect(certificatesExpiring({ certificates: [{ daysLeft: 3 }, { daysLeft: 45 }, { daysLeft: null }, {}] })).toEqual({ value: 1, unknown: 2, atLeast: false })
  })
})
