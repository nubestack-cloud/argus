import { describe, expect, it } from 'vitest'
import type { KubeObject } from '../insight/types'
import { capGroups, changeLabel, diffFields, groupChanges, lineOfPath, pathText, stripNoise, summaryHeadline, toYaml } from './normalize'

const pod = (over: Record<string, unknown> = {}): KubeObject =>
  ({
    apiVersion: 'v1',
    kind: 'Pod',
    metadata: {
      name: 'web-abc',
      namespace: 'apps',
      uid: 'u-1',
      resourceVersion: '42',
      generation: 3,
      creationTimestamp: '2026-10-01T00:00:00Z',
      creationTimestampSecondsSince: 900,
      managedFields: [{ manager: 'kubelet' }],
      annotations: { 'kubectl.kubernetes.io/last-applied-configuration': '{}', team: 'core' },
      ownerReferences: [{ apiVersion: 'apps/v1', kind: 'ReplicaSet', name: 'web-6f9', uid: 'rs-uid', controller: true }],
    },
    spec: { containers: [{ name: 'app', image: 'r/app:1', env: [{ name: 'TOKEN', value: '[REDACTED]' }] }] },
    status: { phase: 'Running', conditions: [{ type: 'Ready', lastTransitionTime: 't', lastTransitionTimeSecondsSince: 5 }] },
    ...over,
  }) as unknown as KubeObject

describe('stripNoise', () => {
  it('removes bookkeeping fields and says which, without mutating the input', () => {
    const input = pod()
    const before = JSON.stringify(input)
    const { value, stripped } = stripNoise(input, { includeStatus: false, specOnly: false })
    expect(JSON.stringify(input)).toBe(before)
    const md = value.metadata as Record<string, unknown>
    for (const k of ['uid', 'resourceVersion', 'generation', 'creationTimestamp', 'managedFields', 'creationTimestampSecondsSince']) expect(md).not.toHaveProperty(k)
    expect(md.annotations).toEqual({ team: 'core' })
    expect(md.ownerReferences).toEqual([{ apiVersion: 'apps/v1', kind: 'ReplicaSet', name: 'web-6f9', controller: true }])
    expect(value).not.toHaveProperty('status')
    expect(stripped).toEqual(
      expect.arrayContaining(['managedFields', 'uid', 'resourceVersion', 'generation', 'creationTimestamp', 'last-applied-configuration', 'ownerReferences uid', 'status', 'relative times']),
    )
  })

  it('keeps status when asked, minus ARGUS’s relative-time helpers', () => {
    const { value } = stripNoise(pod(), { includeStatus: true, specOnly: false })
    expect(value.status).toEqual({ phase: 'Running', conditions: [{ type: 'Ready', lastTransitionTime: 't' }] })
  })

  it('keeps a "…SecondsSince" field that has no timestamp sibling (it is real data then)', () => {
    const { value } = stripNoise(pod({ spec: { activeDeadlineSecondsSince: 3 } }), { includeStatus: false, specOnly: false })
    expect(value.spec).toEqual({ activeDeadlineSecondsSince: 3 })
  })

  it('drops the empty annotations map left after removing last-applied', () => {
    const p = pod()
    p.metadata!.annotations = { 'kubectl.kubernetes.io/last-applied-configuration': '{}' }
    const { value } = stripNoise(p, { includeStatus: false, specOnly: false })
    expect(value.metadata).not.toHaveProperty('annotations')
  })

  it('spec only keeps what is left after apiVersion, kind, metadata and status', () => {
    const { value, stripped } = stripNoise(pod(), { includeStatus: true, specOnly: true })
    expect(Object.keys(value)).toEqual(['spec', 'status'])
    expect(stripped).toContain('metadata')
    const cm = stripNoise({ apiVersion: 'v1', kind: 'ConfigMap', metadata: { name: 'x' }, data: { a: '1' } }, { includeStatus: false, specOnly: true })
    expect(cm.value).toEqual({ data: { a: '1' } })
  })
})

describe('diffFields', () => {
  const strip = (o: KubeObject) => stripNoise(o, { includeStatus: false, specOnly: false }).value

  it('matches named list items by name, so one inserted env var is one change', () => {
    const a = strip(pod())
    const b = strip(
      pod({ spec: { containers: [{ name: 'app', image: 'r/app:2', env: [{ name: 'DEBUG', value: '1' }, { name: 'TOKEN', value: '[REDACTED]' }] }] } }),
    )
    const { changes } = diffFields(a, b)
    expect(changes.map((c) => [pathText(c.path), c.kind])).toEqual([
      ['spec.containers[app].env[DEBUG]', 'onlyB'],
      ['spec.containers[app].image', 'changed'],
    ])
  })

  it('reports a scalar list (args) as one changed field', () => {
    const { changes } = diffFields({ args: ['a', 'b', 'c'] }, { args: ['a', 'x', 'c', 'd'] })
    expect(changes).toEqual([{ path: [{ key: 'args' }], kind: 'changed' }])
  })

  it('never reports two redaction markers as differing, and counts them', () => {
    const { changes, redactedEqual } = diffFields({ env: [{ name: 'T', value: '[REDACTED]' }], arg: '--token=[REDACTED]' }, { env: [{ name: 'T', value: '[REDACTED]' }], arg: '--token=[REDACTED]' })
    expect(changes).toEqual([])
    expect(redactedEqual).toBe(2)
  })

  it('does report a difference when the marker itself differs', () => {
    expect(diffFields({ v: '[REDACTED]' }, { v: 'plain' }).changes).toEqual([{ path: [{ key: 'v' }], kind: 'changed' }])
    expect(diffFields({ v: '--a=[REDACTED]' }, { v: '--b=[REDACTED]' }).changes).toHaveLength(1)
  })

  it('falls back to indices for lists without unique names', () => {
    const { changes } = diffFields({ t: [{ key: 'a' }, { key: 'b' }] }, { t: [{ key: 'a' }] })
    expect(changes.map((c) => pathText(c.path))).toEqual(['t[1]'])
  })
})

describe('summaries', () => {
  it('labels a change by its last key, and a named item by key and name', () => {
    expect(changeLabel([{ key: 'spec' }, { key: 'replicas' }])).toBe('replicas')
    expect(changeLabel([{ key: 'spec' }, { key: 'env' }, { name: 'TOKEN' }])).toBe('env TOKEN')
    expect(changeLabel([{ key: 'containers' }, { name: 'app' }, { key: 'image' }])).toBe('image')
  })

  it('headlines the count and groups repeated keys', () => {
    const c = (...keys: string[]) => ({ path: keys.map((k) => ({ key: k })), kind: 'changed' as const })
    const env = (n: string) => ({ path: [{ key: 'env' }, { name: n }], kind: 'onlyB' as const })
    expect(summaryHeadline([c('spec', 'replicas'), c('x', 'image'), env('A'), env('B')])).toBe('4 fields differ: replicas, image, 2 × env')
    expect(summaryHeadline([c('a')])).toBe('1 field differs: a')
    expect(summaryHeadline([])).toBe('No fields differ')
    expect(summaryHeadline(['a', 'b', 'c', 'd'].map((k) => c(k)), 2)).toBe('4 fields differ: a, b, …')
  })
})

describe('lineOfPath', () => {
  const yaml = toYaml({ spec: { containers: [{ name: 'app', image: 'x', env: [{ name: 'A', value: '1' }] }], replicas: 2 } })

  it('finds a key, a named item and an indexed item in toYaml output', () => {
    const lines = yaml.split('\n')
    expect(lines[lineOfPath(yaml, [{ key: 'spec' }, { key: 'replicas' }])!]).toContain('replicas: 2')
    expect(lines[lineOfPath(yaml, [{ key: 'spec' }, { key: 'containers' }, { name: 'app' }, { key: 'image' }])!]).toContain('image: x')
    expect(lines[lineOfPath(yaml, [{ key: 'spec' }, { key: 'containers' }, { index: 0 }, { key: 'env' }, { name: 'A' }])!]).toContain('name: A')
  })

  it('falls back to the deepest ancestor present', () => {
    const lines = yaml.split('\n')
    expect(lines[lineOfPath(yaml, [{ key: 'spec' }, { key: 'containers' }, { name: 'missing' }])!]).toContain('containers:')
  })

  it('sorts keys so two objects line up', () => {
    expect(toYaml({ b: 1, a: 2 })).toBe('a: 2\nb: 1')
  })
})

describe('groupChanges', () => {
  it('puts spec first, then identity (metadata, selectors, template labels), then status', () => {
    const k = (...keys: string[]) => keys.map((key) => ({ key }))
    const groups = groupChanges([
      { path: k('metadata', 'labels', 'app'), kind: 'changed' },
      { path: [...k('spec', 'template', 'spec', 'containers'), { name: 'api' }, ...k('image')], kind: 'changed' },
      { path: k('spec', 'selector', 'matchLabels', 'app'), kind: 'changed' },
      { path: k('spec', 'template', 'metadata', 'labels', 'app'), kind: 'changed' },
      { path: k('status', 'readyReplicas'), kind: 'changed' },
    ])
    expect(groups.map((g) => [g.key, g.changes.length])).toEqual([
      ['spec', 1],
      ['identity', 3],
      ['status', 1],
    ])
    expect(groupChanges([])).toEqual([])
    // Capped across groups in order: spec survives the cap before identity.
    expect(capGroups(groups, 2).map((g) => [g.key, g.shown.length, g.changes.length])).toEqual([
      ['spec', 1, 1],
      ['identity', 1, 3],
    ])
  })
})

describe('diffFields, a renamed single container', () => {
  it('compares the one container a side by position, naming what differs inside it', () => {
    const a = { spec: { containers: [{ name: 'api', image: 'busybox', resources: { limits: { cpu: '200m' } } }] } }
    const b = { spec: { containers: [{ name: 'edge', image: 'busybox', resources: { limits: { cpu: '100m' } } }] } }
    expect(diffFields(a, b).changes.map((c) => pathText(c.path))).toEqual(['spec.containers[0].name', 'spec.containers[0].resources.limits.cpu'])
  })
})
