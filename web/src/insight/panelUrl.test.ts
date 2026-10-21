import { describe, expect, it } from 'vitest'
import { decodeObjectPanel, encodeObjectPanel, splitGVK, withObjectPanel } from './panelUrl'

describe('object panel URL state', () => {
  it('round-trips namespaced and cluster-scoped objects', () => {
    const a = { clusterId: 'cl_1', kind: 'Deployment', apiGroup: 'apps', namespace: 'prod', name: 'payments' }
    expect(decodeObjectPanel(encodeObjectPanel(a))).toEqual(a)
    const b = { clusterId: 'cl_1', kind: 'Node', name: 'worker-1' }
    expect(decodeObjectPanel(encodeObjectPanel(b))).toEqual({ ...b, apiGroup: undefined, namespace: undefined })
  })
  it('rejects malformed values', () => {
    expect(decodeObjectPanel('inc_123')).toBeNull()
    expect(decodeObjectPanel('obj:cl_1:Pod')).toBeNull()
    expect(decodeObjectPanel(null)).toBeNull()
  })
  it('closing removes the panel and its tab', () => {
    const p = withObjectPanel(new URLSearchParams('panel=x&ptab=yaml&q=1'), null)
    expect(p.toString()).toBe('q=1')
  })
  it('splits agent GVK strings', () => {
    expect(splitGVK('apps/v1/Deployment')).toEqual({ apiGroup: 'apps', kind: 'Deployment' })
    expect(splitGVK('v1/Pod')).toEqual({ apiGroup: undefined, kind: 'Pod' })
  })
})
