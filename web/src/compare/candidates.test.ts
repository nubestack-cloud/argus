import { describe, expect, it } from 'vitest'
import type { KubeObject } from '../insight/types'
import { isHealthyStatus, podFamily, rankSearch, sameNameCandidates, sameNamespaceCandidates, searchQuery, siblingCandidates } from './candidates'

const pendingPod: KubeObject = {
  kind: 'Pod',
  metadata: {
    name: 'gwas-frontend-5dc7fb87d4-b65jw',
    namespace: 'apps',
    labels: { 'pod-template-hash': '5dc7fb87d4' },
    ownerReferences: [{ kind: 'ReplicaSet', name: 'gwas-frontend-5dc7fb87d4', controller: true }],
  },
}
const A = { clusterId: 'lab', kind: 'Pod', namespace: 'apps', name: 'gwas-frontend-5dc7fb87d4-b65jw' }
const hit = (name: string, status?: string, over: Record<string, string> = {}) => ({ clusterId: 'lab', clusterName: 'lab-dev', kind: 'Pod', namespace: 'apps', name, status, ...over })

describe('podFamily', () => {
  it('reads the Deployment prefix through the ReplicaSet’s template hash', () => {
    expect(podFamily(pendingPod)).toEqual({ owner: 'gwas-frontend-5dc7fb87d4', ownerKind: 'ReplicaSet', prefix: 'gwas-frontend' })
  })

  it('uses the owner name for other controllers, and null for a bare pod', () => {
    expect(podFamily({ metadata: { ownerReferences: [{ kind: 'StatefulSet', name: 'db', controller: true }] } })?.prefix).toBe('db')
    expect(podFamily({ metadata: {} })).toBeNull()
  })
})

describe('siblingCandidates', () => {
  it('offers replicas of the same family, healthy first, then same ReplicaSet, and never A itself', () => {
    const got = siblingCandidates(A, pendingPod, [
      hit('gwas-frontend-5dc7fb87d4-b65jw', 'Pending'),
      hit('gwas-frontend-5dc7fb87d4-zzzzz', 'CrashLoopBackOff'),
      hit('gwas-frontend-5dc7fb87d4-aaaaa', 'Running'),
      hit('gwas-frontend-86c9b566b8-thvcf', 'Running'),
      hit('gwas-frontend-api-xyz', 'Running', { name: 'other-thing' }),
      hit('gwas-frontend-86c9b566b8-other', 'Running', { namespace: 'staging' }),
    ])
    expect(got.map((c) => `${c.ref.name}:${c.status}`)).toEqual([
      'gwas-frontend-5dc7fb87d4-aaaaa:Running',
      'gwas-frontend-86c9b566b8-thvcf:Running',
      'gwas-frontend-5dc7fb87d4-zzzzz:CrashLoopBackOff',
    ])
  })
})

describe('Deployment defaults', () => {
  const dep = { clusterId: 'rke2', kind: 'Deployment', apiGroup: 'apps', namespace: 'argus-system', name: 'argus-agent' }
  const d = (clusterId: string, namespace: string, name: string, status = '1/1 ready') => ({ clusterId, clusterName: clusterId, kind: 'Deployment', apiGroup: 'apps', namespace, name, status })

  it('offers the same name elsewhere, same cluster first', () => {
    const got = sameNameCandidates(dep, [d('rke2', 'argus-system', 'argus-agent'), d('lab', 'argus-system', 'argus-agent'), d('rke2', 'staging', 'argus-agent'), d('lab', 'x', 'argus-agent-2')])
    expect(got.map((c) => `${c.ref.clusterId}/${c.ref.namespace}`)).toEqual(['rke2/staging', 'lab/argus-system'])
  })

  it('offers same-namespace neighbours, healthy first, skipping ones already offered', () => {
    const already = [{ ...dep, name: 'hub' }]
    const got = sameNamespaceCandidates(dep, [d('rke2', 'argus-system', 'zeta', '0/1 ready'), d('rke2', 'argus-system', 'hub'), d('rke2', 'argus-system', 'alpha'), d('rke2', 'other', 'beta')], already)
    expect(got.map((c) => c.ref.name)).toEqual(['alpha', 'zeta'])
  })

  it('orders typed results nearest first and keeps only the same kind', () => {
    const got = rankSearch(dep, [
      d('lab', 'argus-system', 'far'),
      { ...d('rke2', 'argus-system', 'pod'), kind: 'Pod', apiGroup: '' },
      d('rke2', 'other', 'same-cluster'),
      d('rke2', 'argus-system', 'same-ns'),
    ])
    expect(got.map((c) => c.ref.name)).toEqual(['same-ns', 'same-cluster', 'far'])
  })
})

describe('helpers', () => {
  it('calls only working statuses healthy', () => {
    expect(['Running', 'Succeeded', '3/3 ready'].every(isHealthyStatus)).toBe(true)
    expect(['Pending', 'CrashLoopBackOff', '1/3 ready', '0/0 ready', undefined].some(isHealthyStatus)).toBe(false)
  })

  it('builds the search grammar', () => {
    expect(searchQuery('Pod', ' web ', 'apps')).toBe('kind:Pod ns:apps web')
    expect(searchQuery(undefined, 'web')).toBe('web')
  })
})
