import { describe, expect, it } from 'vitest'
import { compareHref, panelObject, readCompare, sameKind, sameObject, writeCompare, type CompareState } from './compareUrl'

const podA = { clusterId: 'cl_rke2', kind: 'Pod', namespace: 'apps', name: 'web-6f9-a' }
const podB = { clusterId: 'cl_lab', kind: 'Pod', namespace: 'apps', name: 'web-6f9-b' }
const deploy = { clusterId: 'cl_lab', kind: 'Deployment', apiGroup: 'apps', namespace: 'apps', name: 'web' }

describe('compare URL', () => {
  it('round-trips two refs on different clusters and every view option', () => {
    const s: CompareState = { a: podA, b: podB, layout: 'unified', showAll: true, specOnly: true, includeStatus: true, ignoreInstance: false, pick: 'b' }
    const back = readCompare(new URLSearchParams(writeCompare(s).toString()))
    expect(back).toEqual({ ...s, a: { ...podA, apiGroup: undefined }, b: { ...podB, apiGroup: undefined } })
  })

  it('leaves defaults out of the link and reads them back as defaults', () => {
    const p = writeCompare({ a: deploy, b: null, layout: 'split', showAll: false, specOnly: false, includeStatus: false, ignoreInstance: null, pick: null })
    expect([...p.keys()]).toEqual(['a'])
    const s = readCompare(p)
    expect(s.a).toEqual(deploy)
    expect(s).toMatchObject({ b: null, layout: 'split', showAll: false, specOnly: false, includeStatus: false, ignoreInstance: null, pick: null })
    expect(readCompare(new URLSearchParams('inst=1')).ignoreInstance).toBe(true)
    expect(readCompare(new URLSearchParams('inst=0')).ignoreInstance).toBe(false)
  })

  it('keeps unrelated params such as an open panel', () => {
    const p = writeCompare({ a: podA, b: podB, layout: 'split', showAll: false, specOnly: false, includeStatus: false, ignoreInstance: null, pick: null }, new URLSearchParams('panel=x'))
    expect(p.get('panel')).toBe('x')
  })

  it('ignores garbage', () => {
    const s = readCompare(new URLSearchParams('a=nope&view=weird&pick=c'))
    expect(s).toMatchObject({ a: null, layout: 'split', pick: null })
  })

  it('builds the panel’s Compare… link with B’s picker open', () => {
    const href = compareHref(deploy)
    expect(href.startsWith('/compare?')).toBe(true)
    const s = readCompare(new URLSearchParams(href.split('?')[1]))
    expect(s.a).toEqual(deploy)
    expect(s.pick).toBe('b')
    expect(compareHref(null)).toBe('/compare')
  })

  it('reads the object open in the inspector', () => {
    expect(panelObject('?panel=obj:c1:apps/Deployment:ns/web')).toEqual({ clusterId: 'c1', kind: 'Deployment', apiGroup: 'apps', namespace: 'ns', name: 'web' })
    expect(panelObject('')).toBeNull()
  })

  it('compares kinds by group and kind', () => {
    expect(sameKind(podA, podB)).toBe(true)
    expect(sameKind(podA, deploy)).toBe(false)
    expect(sameKind(deploy, { ...deploy, apiGroup: 'extensions' })).toBe(false)
    expect(sameObject(podA, { ...podA })).toBe(true)
  })
})
