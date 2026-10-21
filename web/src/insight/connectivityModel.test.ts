import { describe, expect, it } from 'vitest'
import { entryPointsFrom } from './connectivityModel'

describe('entryPointsFrom', () => {
  it('keeps the Services and routes in front of an object, Services first, once each', () => {
    const out = entryPointsFrom({
      nodes: [
        { id: '1', kind: 'Pod', namespace: 'apps', name: 'web-1' },
        { id: '2', kind: 'Ingress', namespace: 'apps', name: 'web' },
        { id: '3', kind: 'Service', namespace: 'apps', name: 'web' },
        { id: '4', kind: 'Service', namespace: 'apps', name: 'web' },
        { id: '5', kind: 'ConfigMap', namespace: 'apps', name: 'cfg' },
      ],
    })
    expect(out).toEqual([
      { kind: 'Service', namespace: 'apps', name: 'web' },
      { kind: 'Ingress', namespace: 'apps', name: 'web' },
    ])
  })

  it('is empty when nothing routes to the object', () => {
    expect(entryPointsFrom({ nodes: [{ id: '1', kind: 'Pod', namespace: 'apps', name: 'p' }] })).toEqual([])
    expect(entryPointsFrom(undefined)).toEqual([])
  })
})
