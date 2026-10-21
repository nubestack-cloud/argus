import { describe, expect, it } from 'vitest'
import { buildPathModel, HOP_STATE_LABEL, type PathHopInput, type PathTrace } from './model'

const trace = (o: Partial<PathTrace>): PathTrace => ({
  subject: { kind: 'Service', namespace: 'shop', name: 'payments' },
  upstreams: [],
  downstream: [],
  verdict: 'healthy',
  brokenAt: -1,
  ...o,
})

const svc: PathHopInput = { resource: { kind: 'Service', namespace: 'shop', name: 'payments' }, edge: 'subject' }
const pods = (findings: PathHopInput['findings'] = []): PathHopInput => ({
  resource: { kind: 'Pods', namespace: 'shop', name: 'payments' },
  edge: 'Service->Pods',
  findings,
})

describe('buildPathModel — first broken hop up front', () => {
  it('headlines the broken hop with its finding and marks later hops as not reached', () => {
    const m = buildPathModel(trace({
      verdict: 'broken',
      brokenAt: 0,
      downstream: [
        { ...svc, findings: [{ code: 'svc:no-ready-endpoints', severity: 'critical', message: 'has no ready endpoints', command: 'kubectl -n shop get endpointslices -l kubernetes.io/service-name=payments' }] },
        pods(),
      ],
    }))
    expect(m.headline).toBe('Breaks at: Service payments — has no ready endpoints')
    expect(m.verdictLabel).toBe('Broken')
    expect(m.brokenHopIndex).toBe(0)
    expect(m.hops.map(h => h.state)).toEqual(['broken', 'after-break'])
    expect(m.hops[0].findings[0].command).toContain('endpointslices')
    expect(HOP_STATE_LABEL[m.hops[0].state]).toBe('Breaks here')
  })

  it('offsets the broken index past the upstream entries', () => {
    const m = buildPathModel(trace({
      verdict: 'broken',
      brokenAt: 1,
      upstreams: [{ resource: { kind: 'Ingress', namespace: 'shop', name: 'web' } }],
      downstream: [svc, pods([{ code: 'pods:no-ready-endpoints', severity: 'critical', message: '0 of 2 pods ready' }])],
    }))
    expect(m.hops.map(h => h.label)).toEqual(['Ingress web', 'Service payments', 'Pods payments'])
    expect(m.brokenHopIndex).toBe(2)
    expect(m.hops[2].state).toBe('broken')
    expect(m.headline).toBe('Breaks at: Pods payments — 0 of 2 pods ready')
  })

  it('judges parallel upstreams independently: one broken entry does not condemn the path', () => {
    const m = buildPathModel(trace({
      verdict: 'healthy',
      upstreams: [
        { resource: { kind: 'Ingress', name: 'old' }, findings: [{ code: 'ingress:no-controller', severity: 'critical', message: 'No ingress controller' }] },
        { resource: { kind: 'Ingress', name: 'new' } },
      ],
      downstream: [svc, pods()],
    }))
    expect(m.hops.map(h => h.state)).toEqual(['broken', 'ok', 'ok', 'ok'])
    expect(m.brokenHopIndex).toBe(-1)
    expect(m.headline).toMatch(/^No break found/)
  })

  it('names the first broken entry when every entry is broken and no downstream hop is anchored', () => {
    const m = buildPathModel(trace({
      verdict: 'broken',
      brokenAt: -1,
      reason: 'all entry paths into this resource are unreachable',
      upstreams: [
        { resource: { kind: 'Ingress', name: 'a' }, findings: [{ code: 'ingress:no-address', severity: 'critical', message: 'Ingress has no address' }] },
        { resource: { kind: 'Ingress', name: 'b' }, findings: [{ code: 'ingress:no-address', severity: 'critical', message: 'Ingress has no address' }] },
      ],
      downstream: [svc],
    }))
    expect(m.brokenHopIndex).toBe(0)
    expect(m.headline).toBe('Breaks at: Ingress a — Ingress has no address')
    expect(m.hops[2].state).toBe('ok')
  })

  it('leads with the reason, not an optimistic server headline, when broken without a finding', () => {
    const m = buildPathModel(trace({
      verdict: 'broken',
      reason: 'all entry paths into this resource are unreachable',
      headline: 'No break found',
      downstream: [svc],
    }))
    expect(m.headline).toBe('all entry paths into this resource are unreachable')
  })

  it('reads a degraded anchor as degraded, and keeps judging the hops after it', () => {
    const m = buildPathModel(trace({
      verdict: 'degraded',
      brokenAt: 1,
      reason: '1 of 2 routes broken - other routes still deliver',
      downstream: [
        { resource: { kind: 'HTTPRoute', name: 'r' } },
        { resource: { kind: 'Service', name: 'a' } },
        { resource: { kind: 'Service', name: 'b' } },
      ],
    }))
    expect(m.hops.map(h => h.state)).toEqual(['ok', 'degraded', 'ok'])
    expect(m.headline).toBe('Degraded at: Service a — 1 of 2 routes broken - other routes still deliver')
    expect(m.verdictLabel).toBe('Degraded')
  })

  it('does not let an upstream missing-reference headline the path', () => {
    const m = buildPathModel(trace({
      verdict: 'degraded',
      upstreams: [{ resource: { kind: 'HTTPRoute', name: 'r' }, findings: [{ code: 'missing_ref:service', severity: 'critical', message: 'sibling backend missing' }] }],
      downstream: [{ ...svc, findings: [{ code: 'svc:targetport-no-listener', severity: 'warning', message: 'targetPort 8080 has no listener' }] }],
    }))
    expect(m.headline).toBe('targetPort 8080 has no listener')
  })
})

describe('buildPathModel — findings and edge cases', () => {
  it('attaches top-level findings by hop and sorts each hop critical first', () => {
    const m = buildPathModel(trace({
      verdict: 'broken',
      brokenAt: 1,
      upstreams: [{ resource: { kind: 'Ingress', name: 'web' } }],
      downstream: [svc, pods()],
      findings: [
        { code: 'netpol:advisory', hop: 1, severity: 'info', message: 'a NetworkPolicy selects these pods' },
        { code: 'pods:no-ready-endpoints', hop: 'downstream:1', severity: 'critical', message: '0 of 1 pods ready' },
        { code: 'ingress:no-address', hop: 'upstream:0', severity: 'warning', message: 'no address yet' },
        { code: 'odd', hop: 'downstream:9', severity: 'info', message: 'unplaced' },
      ],
    }))
    expect(m.hops[2].findings.map(f => f.code)).toEqual(['pods:no-ready-endpoints', 'netpol:advisory'])
    expect(m.hops[0].state).toBe('degraded')
    expect(m.hops[1].findings.map(f => f.code)).toEqual(['odd'])
    expect(m.headline).toBe('Breaks at: Pods payments — 0 of 1 pods ready')
  })

  it('ignores an out-of-range brokenAt', () => {
    const m = buildPathModel(trace({ verdict: 'broken', brokenAt: 7, downstream: [svc] }))
    expect(m.brokenHopIndex).toBe(-1)
    expect(m.hops[0].state).toBe('ok')
    expect(m.headline).toBe('Traffic cannot reach a ready pod')
  })

  it('shows the subject alone when the trace has no downstream hops', () => {
    const m = buildPathModel(trace({ verdict: 'unknown' }))
    expect(m.hops).toHaveLength(1)
    expect(m.hops[0]).toMatchObject({ label: 'Service payments', state: 'unknown', role: 'downstream' })
    expect(m.verdictLabel).toBe('Could not verify')
    expect(m.headline).toBe('Could not determine whether traffic reaches a ready pod')
  })

  it('never claims reachability for a healthy static verdict', () => {
    const m = buildPathModel(trace({ downstream: [svc, pods()] }))
    expect(m.verdictLabel).toBe('No break found')
    expect(m.headline).toContain('no traffic sent')
    expect(m.headline.toLowerCase()).not.toContain('reachable')
  })

  it('prefers the server headline on a healthy verdict and carries truncation', () => {
    const m = buildPathModel(trace({ headline: 'No break found - 3 of 3 pods ready', truncated: true, downstream: [svc] }))
    expect(m.headline).toBe('No break found - 3 of 3 pods ready')
    expect(m.truncated).toBe(true)
  })
})

describe('agent hop encoding', () => {
  it('attaches "downstream[1]" findings to that hop', () => {
    const m = buildPathModel({
      subject: { kind: 'Service', namespace: 'prod', name: 'payments' },
      upstreams: [],
      downstream: [{ resource: { kind: 'Service', namespace: 'prod', name: 'payments' } }, { resource: { kind: 'Pods', namespace: 'prod', name: '' } }],
      verdict: 'broken',
      brokenAt: 1,
      findings: [{ code: 'pods:no-ready-endpoints', hop: 'downstream[1]', severity: 'critical', message: '0 of 1 pods ready' }],
    })
    expect(m.hops.find((h) => h.kind === 'Pods')?.findings).toHaveLength(1)
  })
})

