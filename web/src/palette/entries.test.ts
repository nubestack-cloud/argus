import { describe, expect, it } from 'vitest'
import type { Cluster, Incident } from '../api/types'
import { CAP_AUDIT_READ, CAP_CLUSTER_INSPECT } from '../api/capabilities'
import { clusterEntries, compareEntry, incidentEntries, objectEntries, pageEntries, paletteResults, recentIncidents } from './entries'

const incident = (id: string, objectName: string, lastSeen: string) =>
  ({ id, objectName, openingReason: 'OOMKilled', fingerprint: 'f'.repeat(64), clusterDisplayName: 'prod', severity: 'high', state: 'Detected', lastSeen }) as unknown as Incident

describe('palette entries', () => {
  it('lists every page, marking (not hiding) one the viewer lacks the capability for', () => {
    const pages = pageEntries(new Set([CAP_AUDIT_READ]))
    const audit = pages.find((p) => p.to === '/audit-log')!
    expect(audit.disabledReason).toMatch(/audit:read/)
    expect(pages.find((p) => p.to === '/incidents')!.disabledReason).toBeUndefined()
    expect(pageEntries(null).every((p) => !p.disabledReason)).toBe(true)
  })

  it('shows pages then recent incidents for a blank query', () => {
    const incidents = [incident('i1', 'old', '2026-01-01T00:00:00Z'), incident('i2', 'new', '2026-02-01T00:00:00Z')]
    const results = paletteResults('', {
      pages: pageEntries(null),
      incidents: incidentEntries(incidents),
      recent: incidentEntries(recentIncidents(incidents, 1)),
      clusters: [],
      objects: [],
      canSearch: true,
    })
    expect(results.at(-1)?.label).toBe('new')
    expect(results.filter((r) => r.category === 'Incidents')).toHaveLength(1)
  })

  it('ranks pages, incidents and clusters together, then objects, then a full-search link', () => {
    const results = paletteResults('pay', {
      pages: pageEntries(null),
      incidents: incidentEntries([incident('i1', 'payments-api', '2026-01-01T00:00:00Z')]),
      recent: [],
      clusters: clusterEntries([{ id: 'c1', displayName: 'pay-prod', state: 'Active' } as Cluster]),
      objects: objectEntries([{ clusterId: 'c1', clusterName: 'pay-prod', score: 100, kind: 'Deployment', namespace: 'shop', name: 'payments' }]),
      canSearch: true,
    })
    expect(results.map((r) => r.category)).toEqual(['Clusters', 'Incidents', 'Objects', 'Search'])
    expect(results[2].object).toEqual({ clusterId: 'c1', kind: 'Deployment', apiGroup: undefined, namespace: 'shop', name: 'payments' })
    expect(results[3].to).toBe('/search?q=pay')
  })

  it('offers Compare objects, starting from the open panel’s object and disabled (not hidden) without cluster:inspect', () => {
    const plain = compareEntry(null, null)
    expect(plain).toMatchObject({ label: 'Compare objects', to: '/compare', category: 'Pages' })
    const from = compareEntry({ clusterId: 'c1', kind: 'Pod', namespace: 'apps', name: 'web-1' }, new Set())
    expect(from.sublabel).toBe('Starting from Pod web-1')
    expect(from.to).toMatch(/^\/compare\?a=obj%3Ac1%3A%2FPod%3Aapps%2Fweb-1&pick=b$/)
    expect(compareEntry(null, new Set([CAP_CLUSTER_INSPECT])).disabledReason).toMatch(/cluster:inspect/)
  })
})
