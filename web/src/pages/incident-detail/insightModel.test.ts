import { describe, expect, it } from 'vitest'
import type { IncidentDetail } from '../../api/types'
import { gitOpsQuickAction, gitOpsSource, incidentObject, incidentSubject, pendingPod, stepSeconds } from './insightModel'

function inc(over: Partial<IncidentDetail>): IncidentDetail {
  return { id: 'i', clusterId: 'c1', findingGroups: [], ownership: null, ...over } as unknown as IncidentDetail
}

describe('incidentSubject', () => {
  it('prefers the owning workload from a piped workload key', () => {
    expect(
      incidentSubject(inc({ workloadKey: 'apps/v1/Deployment|payments|api', objectGvk: 'v1/Pod', objectNamespace: 'payments', objectName: 'api-1' })),
    ).toEqual({ clusterId: 'c1', kind: 'Deployment', apiGroup: 'apps', namespace: 'payments', name: 'api' })
  })
  it('falls back to the object, in either GVK form', () => {
    expect(incidentSubject(inc({ objectGvk: 'apps/v1, Kind=StatefulSet', objectNamespace: 'db', objectName: 'pg' }))).toEqual({
      clusterId: 'c1',
      kind: 'StatefulSet',
      apiGroup: 'apps',
      namespace: 'db',
      name: 'pg',
    })
    expect(incidentObject(inc({}))).toBeNull()
  })
})

describe('pendingPod', () => {
  it('recognises a pod that will not schedule', () => {
    expect(pendingPod(inc({ objectGvk: 'v1/Pod', objectNamespace: 'p', objectName: 'x', openingReason: 'PendingTimeout' }))?.name).toBe('x')
    expect(
      pendingPod(inc({ objectGvk: 'v1/Pod', objectNamespace: 'p', objectName: 'x', findingGroups: [{ reason: 'FailedScheduling', count: 2, firstSeen: '', lastSeen: '' }] })),
    ).not.toBeNull()
  })
  it('ignores other faults, other kinds and pending PVCs', () => {
    expect(pendingPod(inc({ objectGvk: 'v1/Pod', objectNamespace: 'p', objectName: 'x', openingReason: 'OOMKilled' }))).toBeNull()
    expect(pendingPod(inc({ objectGvk: 'v1/PersistentVolumeClaim', objectNamespace: 'p', objectName: 'x', openingReason: 'PVCPendingTimeout' }))).toBeNull()
  })
})

describe('gitOpsSource / gitOpsQuickAction', () => {
  it('targets the Argo Application named by ownership', () => {
    const src = gitOpsSource(
      inc({
        ownership: {
          managedBy: 'argocd',
          sourceKind: 'Application',
          sourceName: 'shop',
          sourceNamespace: 'argocd',
          objectGvk: 'apps/v1/Deployment',
          objectNamespace: 'p',
          objectName: 'api',
        },
      }),
    )
    expect(src).toMatchObject({ kind: 'Application', apiGroup: 'argoproj.io', namespace: 'argocd', name: 'shop' })
    expect(gitOpsQuickAction(src)).toMatchObject({ action: 'argoRefresh', namespace: 'argocd', name: 'shop' })
  })
  it('treats Helm alone as not GitOps, and a Flux object as its own source', () => {
    expect(
      gitOpsSource(
        inc({ ownership: { managedBy: 'helm', sourceKind: 'Release', sourceName: 'x', sourceNamespace: 'p', objectGvk: '', objectNamespace: '', objectName: '' } }),
      ),
    ).toBeNull()
    const flux = gitOpsSource(inc({ objectGvk: 'kustomize.toolkit.fluxcd.io/v1/Kustomization', objectNamespace: 'flux-system', objectName: 'apps' }))
    expect(gitOpsQuickAction(flux)?.action).toBe('fluxReconcileKs')
  })
})

describe('stepSeconds', () => {
  it('parses Prometheus steps', () => {
    expect(stepSeconds('30s')).toBe(30)
    expect(stepSeconds('2m')).toBe(120)
    expect(stepSeconds('1h')).toBe(3600)
    expect(stepSeconds('bogus')).toBeUndefined()
  })
})
