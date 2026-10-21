import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CAP_CLUSTER_INSPECT } from '../api/capabilities'
import type { NetworkPolicyMap } from '../api/types'
import { findingsFor, isolationOf, isolationParts, peerLabel, sortWorkloads } from './netpolModel'

const mockInspect = vi.fn()
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return { ...actual, inspectCluster: (...a: unknown[]) => mockInspect(...a) }
})
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 't' }) }))
const caps = new Set<string>()
vi.mock('../auth/useCapabilities', () => ({
  useMissingCapabilities: (list: string[]) => ({ resolved: true, missing: list.filter((c) => !caps.has(c)) }),
}))

import { NetworkPolicyPanel } from './NetworkPolicyPanel'

// Shaped like get_network_policy_map's answer for rke2's nebula namespace
// (2026-10-13), cut down: a default-deny with role policies, a peer in
// another namespace, a node address, and one rule the other side refuses.
const nebula: NetworkPolicyMap = {
  observedAt: '2026-10-13T16:00:00Z',
  note: 'Predicted from core NetworkPolicy objects.',
  namespace: 'nebula',
  policies: [
    { name: 'nebula-default-deny', types: ['Ingress', 'Egress'], workloads: ['Deployment payments-api', 'Deployment nebula-ops-bff'] },
    { name: 'payments-api', types: ['Ingress', 'Egress'], workloads: ['Deployment payments-api'] },
  ],
  workloads: [
    {
      kind: 'Deployment', name: 'payments-api', pods: 3, ingressIsolated: true, egressIsolated: true,
      policies: ['payments-api', 'nebula-default-deny'],
      ingress: [
        { peer: { type: 'namespace', namespace: 'ingress-nginx' }, ports: ['TCP 8080'], policies: ['payments-api'] },
        { peer: { type: 'cidr', cidr: '10.0.1.187/32', nodes: ['worker-1'] }, ports: ['TCP 8080'], policies: ['payments-api'] },
        { peer: { type: 'workload', kind: 'Deployment', namespace: 'nebula', name: 'nebula-ops-bff' }, ports: ['TCP 8080'], policies: ['payments-api'], effective: 'blocked', blockedBy: ['nebula/nebula-default-deny'] },
      ],
      egress: [{ peer: { type: 'namespace', namespace: 'kube-system' }, ports: ['UDP 53', 'TCP 53'], policies: ['nebula-default-deny'] }],
    },
    {
      kind: 'Deployment', name: 'nebula-ops-bff', pods: 2, ingressIsolated: true, egressIsolated: true,
      policies: ['nebula-default-deny'],
      ingress: [], egress: [{ peer: { type: 'namespace', namespace: 'kube-system' }, ports: ['UDP 53'], policies: ['nebula-default-deny'] }],
    },
    {
      kind: 'Deployment', name: 'stray', pods: 1, ingressIsolated: false, egressIsolated: false, policies: [],
      ingress: [{ peer: { type: 'anywhere' }, ports: ['all ports'] }], egress: [{ peer: { type: 'anywhere' }, ports: ['all ports'] }],
    },
  ],
  findings: [
    { code: 'egress-open', severity: 'review', title: 'Inbound is restricted but outbound is not', fix: 'Add Egress', objects: ['Deployment other'] },
    {
      code: 'half-open', severity: 'warning', title: 'Allowed on one side, refused on the other: this traffic can never arrive', fix: 'Add the matching rule',
      objects: ['Deployment payments-api from Deployment nebula/nebula-ops-bff on TCP 8080, refused by nebula/nebula-default-deny'],
    },
    { code: 'open-ingress', severity: 'warning', title: 'Accepts traffic from anywhere: no policy restricts its inbound', fix: 'Select these pods', objects: ['Deployment stray'] },
  ],
}

const index: NetworkPolicyMap = {
  observedAt: '2026-10-13T16:00:00Z',
  note: 'n',
  namespaces: [
    { name: 'nebula', workloads: 3, policies: 2, open: 1, warnings: 2, reviews: 1 },
    { name: 'argocd', workloads: 7, policies: 7, open: 0, warnings: 0, reviews: 0 },
  ],
}

function wrap() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/clusters/cl_1?tab=netpol']}>
        <NetworkPolicyPanel clusterId="cl_1" liveness={{ stale: false }} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  caps.clear()
  caps.add(CAP_CLUSTER_INSPECT)
  mockInspect.mockImplementation((_c: string, _t: string, args: { namespace?: string }) =>
    Promise.resolve({ tool: 'get_network_policy_map', receivedAt: '2026-10-13T16:00:00Z', result: args.namespace ? nebula : index }),
  )
})

describe('netpol model', () => {
  it('names peers in words', () => {
    expect(peerLabel({ type: 'anywhere' }, 'in', 'nebula')).toBe('Anyone, including outside the cluster')
    expect(peerLabel({ type: 'namespace', namespace: 'nebula' }, 'in', 'nebula')).toBe('Every pod in this namespace')
    expect(peerLabel({ type: 'workload', kind: 'Deployment', namespace: 'nebula-openbao', name: 'bao' }, 'out', 'nebula')).toBe('Deployment bao in nebula-openbao')
    expect(peerLabel({ type: 'cidr', cidr: '10.0.0.1/32', nodes: ['w1'] }, 'in', 'nebula')).toBe('10.0.0.1/32 (node w1)')
    expect(peerLabel({ type: 'none', selector: 'pods app=gone' }, 'in', 'nebula')).toBe('Matches nothing: pods app=gone')
  })

  it('matches a recommendation to its workload by exact name, not prefix', () => {
    const api = nebula.workloads![0]
    expect(findingsFor(api, nebula.findings!)).toHaveLength(1)
    expect(findingsFor({ ...api, name: 'nebula' }, nebula.findings!)).toHaveLength(0)
  })

  it('calls an allow-all policy open, not restricted', () => {
    const allowAll = {
      kind: 'Deployment', name: 'coredns', pods: 2, ingressIsolated: true, egressIsolated: true, policies: ['allow-all'],
      ingress: [{ peer: { type: 'anywhere' as const }, ports: ['all ports'] }],
      egress: [{ peer: { type: 'anywhere' as const }, ports: ['all ports'] }],
    }
    expect(isolationOf(allowAll)).toBe('inboundOpen')
    expect(isolationOf({ ...allowAll, ingress: [] })).toBe('outboundOpen')
  })

  it('puts workloads with warnings first and splits isolation in words', () => {
    const order = sortWorkloads(nebula.workloads!, nebula.findings!).map((w) => w.name)
    expect(order.slice(0, 2).sort()).toEqual(['payments-api', 'stray'])
    expect(order[2]).toBe('nebula-ops-bff')
    expect(isolationParts(nebula.workloads!).map((p) => `${p.value} ${p.label}`)).toEqual([
      '2 restricted both ways', '0 outbound open', '1 accept from anyone', '0 on the host network',
    ])
  })
})

describe('NetworkPolicyPanel', () => {
  it('opens on the namespace with the most warnings and draws its workloads', async () => {
    wrap()
    expect(await screen.findByRole('list', { name: 'Workloads in nebula' })).toBeTruthy()
    expect(mockInspect).toHaveBeenCalledWith('cl_1', 'get_network_policy_map', { namespace: 'nebula' }, 't')
    expect(screen.getByRole('button', { name: /^nebula/, pressed: true })).toBeTruthy()
    // Recommendations warnings first.
    const card = screen.getByRole('heading', { name: 'Recommendations' }).closest('.card') as HTMLElement
    const titles = [...card.querySelectorAll('.upgrade-fgroup-head strong')].map((e) => e.textContent)
    expect(titles[titles.length - 1]).toBe('Inbound is restricted but outbound is not')
    expect(card.querySelectorAll('.upgrade-fgroup-head .badge')[0].textContent).toBe('Warning')
  })

  it('says a refused rule is refused, and by what, in words', async () => {
    wrap()
    const from = (await screen.findAllByRole('list', { name: 'Can be reached from' }))[0]
    const refused = within(from).getByText('Deployment nebula-ops-bff').closest('li')!
    expect(refused.getAttribute('data-tone')).toBe('blocked')
    expect(refused.textContent).toContain('refused by nebula/nebula-default-deny')
    expect(within(from).getByText('10.0.1.187/32 (node worker-1)')).toBeTruthy()
  })

  it('filters to workloads that accept from anyone, with an honest empty state', async () => {
    wrap()
    await screen.findByRole('list', { name: 'Workloads in nebula' })
    fireEvent.click(screen.getByRole('button', { name: /Accept from anyone/ }))
    const list = screen.getByRole('list', { name: 'Workloads in nebula' })
    const rows = list.querySelectorAll('.netpol-wl')
    expect(rows).toHaveLength(1)
    expect(rows[0].querySelector('.netpol-wl-name')?.textContent).toContain('stray')
    expect(rows[0].querySelector('.netpol-wl-iso')?.textContent).toBe('Accepts from anyone')
  })

  it('without cluster:inspect, says what is missing instead of drawing an empty map', async () => {
    caps.clear()
    wrap()
    expect(mockInspect).not.toHaveBeenCalled()
    expect(await screen.findByText(/cluster:inspect/)).toBeTruthy()
  })
})
