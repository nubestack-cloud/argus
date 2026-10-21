import { describe, expect, it } from 'vitest'
import type { KubeObject } from '../insight/types'
import { compareObjects } from './compare'
import { hideInstanceFields, revisionOf, sameWorkloadPods, TOKEN_VOLUME_PLACEHOLDER } from './instance'
import { pathText, stripNoise } from './normalize'

// Shaped on the live gwas-frontend pair on lab-dev (2026-10-11): one Pending
// pod of the new ReplicaSet against one Running pod of the old one, whose
// real difference is the whitelist ConfigMap checksum.
function gwas(hash: string, suffix: string, opts: { checksum: string; node: string; token: string; ip?: string }): KubeObject {
  const rs = `gwas-frontend-${hash}`
  return {
    apiVersion: 'v1',
    kind: 'Pod',
    metadata: {
      name: `${rs}-${suffix}`,
      generateName: `${rs}-`,
      namespace: 'apps',
      labels: { app: 'gwas-frontend', 'pod-template-hash': hash },
      annotations: {
        'checksum/config-gwas-whitelist': opts.checksum,
        ...(opts.ip ? { 'cni.projectcalico.org/podIP': `${opts.ip}/32`, 'cni.projectcalico.org/containerID': 'abc', 'k8s.v1.cni.cncf.io/network-status': '[]' } : {}),
      },
      ownerReferences: [{ apiVersion: 'apps/v1', kind: 'ReplicaSet', name: rs, controller: true }],
    },
    spec: {
      nodeName: opts.node,
      containers: [
        {
          name: 'gwas-frontend',
          image: 'mercury/gwasplots:1.9',
          env: [{ name: 'NODE_ENV', value: '[REDACTED]' }],
          volumeMounts: [
            { name: 'gwas-img', mountPath: '/img' },
            { name: opts.token, mountPath: '/var/run/secrets/kubernetes.io/serviceaccount', readOnly: true },
          ],
        },
      ],
      volumes: [{ name: 'gwas-img', persistentVolumeClaim: { claimName: 'gwas-img' } }, { name: opts.token, projected: { defaultMode: 420 } }],
    },
    status: { phase: opts.ip ? 'Running' : 'Pending', podIP: opts.ip, podIPs: opts.ip ? [{ ip: opts.ip }] : undefined, hostIP: '10.0.0.1' },
  } as unknown as KubeObject
}

const pending = gwas('5dc7fb87d4', 'b65jw', { checksum: '348ff9', node: 'pool-1', token: 'kube-api-access-ng6t6' })
const running = gwas('86c9b566b8', 'thvcf', { checksum: 'f74ac9', node: 'pool-0', token: 'kube-api-access-tpl67', ip: '10.42.254.204' })
const ref = { clusterId: 'lab', namespace: 'apps' }

describe('sameWorkloadPods (the option’s default)', () => {
  it('is true for two pods of one Deployment, even across ReplicaSets', () => {
    expect(sameWorkloadPods(ref, ref, pending, running)).toBe(true)
  })

  it('is false across clusters or namespaces, for a bare pod, or for non-pods', () => {
    expect(sameWorkloadPods(ref, { clusterId: 'rke2', namespace: 'apps' }, pending, running)).toBe(false)
    expect(sameWorkloadPods(ref, { clusterId: 'lab', namespace: 'other' }, pending, running)).toBe(false)
    expect(sameWorkloadPods(ref, ref, pending, { kind: 'Pod', metadata: { name: 'bare' } })).toBe(false)
    expect(sameWorkloadPods(ref, ref, { kind: 'Deployment' }, { kind: 'Deployment' })).toBe(false)
  })
})

describe('revisionOf', () => {
  it('names the Deployment and both ReplicaSets when they differ', () => {
    expect(revisionOf(pending, running)).toEqual({ deployment: 'gwas-frontend', replicaSetA: 'gwas-frontend-5dc7fb87d4', replicaSetB: 'gwas-frontend-86c9b566b8' })
  })

  it('is null for siblings of one ReplicaSet, and for owners that are not a Deployment’s ReplicaSet', () => {
    const sibling = gwas('5dc7fb87d4', 'zzzzz', { checksum: '348ff9', node: 'pool-2', token: 'kube-api-access-aaaaa' })
    expect(revisionOf(pending, sibling)).toBeNull()
    const sts = (n: string): KubeObject => ({ kind: 'Pod', metadata: { name: n, ownerReferences: [{ kind: 'StatefulSet', name: 'db', controller: true }] } })
    expect(revisionOf(sts('db-0'), sts('db-1'))).toBeNull()
    // A ReplicaSet whose name does not end in the pod-template-hash is not
    // recognisably a Deployment's revision: its difference is kept.
    const odd = (rs: string): KubeObject => ({ kind: 'Pod', metadata: { name: `${rs}-x`, labels: { 'pod-template-hash': 'zz' }, ownerReferences: [{ kind: 'ReplicaSet', name: rs, controller: true }] } })
    expect(revisionOf(odd('web-a'), odd('web-b'))).toBeNull()
  })
})

describe('hideInstanceFields', () => {
  const strip = (o: KubeObject) => stripNoise(o, { includeStatus: true, specOnly: false }).value

  it('hides per-instance fields and counts each distinct path across both sides', () => {
    const { a, b, hidden } = hideInstanceFields(strip(pending), strip(running), pending, running)
    expect(Object.fromEntries(hidden.map((h) => [h.category, h.count]))).toEqual({
      revision: 2,
      name: 1,
      generateName: 1,
      cni: 3,
      ips: 3,
      tokenVolume: 2,
    })
    const md = b.metadata as Record<string, unknown>
    expect(md).not.toHaveProperty('name')
    expect(md.annotations).toEqual({ 'checksum/config-gwas-whitelist': 'f74ac9' })
    expect(md.labels).toEqual({ app: 'gwas-frontend' })
    expect(md.ownerReferences).toEqual([{ apiVersion: 'apps/v1', kind: 'ReplicaSet', controller: true }])
    expect(JSON.stringify(a)).toContain(TOKEN_VOLUME_PLACEHOLDER)
    expect(JSON.stringify(a)).not.toContain('ng6t6')
    // nodeName is a real difference and stays.
    expect((a.spec as { nodeName: string }).nodeName).toBe('pool-1')
  })

  it('keeps the ReplicaSet owner and hash when they are not two revisions of one Deployment', () => {
    const sibling = gwas('5dc7fb87d4', 'zzzzz', { checksum: '348ff9', node: 'pool-2', token: 'kube-api-access-aaaaa' })
    const { b, hidden } = hideInstanceFields(strip(pending), strip(sibling), pending, sibling)
    expect(hidden.some((h) => h.category === 'revision')).toBe(false)
    expect((b.metadata as { labels: Record<string, string> }).labels['pod-template-hash']).toBe('5dc7fb87d4')
  })

  it('does not touch a volume that merely starts with kube-api-access', () => {
    const p = gwas('5dc7fb87d4', 'b65jw', { checksum: '1', node: 'n', token: 'kube-api-access-custom-volume' })
    const { a } = hideInstanceFields(strip(p), strip(p), p, p)
    expect(JSON.stringify(a)).toContain('kube-api-access-custom-volume')
  })
})

describe('the gwas-frontend comparison with the option on', () => {
  it('leads with the revision and leaves the checksum and nodeName as the differences', () => {
    const cmp = compareObjects(pending, running, { includeStatus: false, specOnly: false, ignoreInstance: true })
    expect(cmp.revision?.deployment).toBe('gwas-frontend')
    expect(cmp.changes.map((c) => pathText(c.path))).toEqual(['metadata.annotations.checksum/config-gwas-whitelist', 'spec.nodeName'])
    expect(cmp.redactedEqual).toBe(1)
  })

  it('reports every per-instance field when the option is off', () => {
    const cmp = compareObjects(pending, running, { includeStatus: false, specOnly: false, ignoreInstance: false })
    expect(cmp.revision).toBeNull()
    expect(cmp.instanceHidden).toEqual([])
    expect(cmp.changes.length).toBeGreaterThan(8)
  })
})
