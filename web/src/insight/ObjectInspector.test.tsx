import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CAP_CLUSTER_INSPECT, CAP_CLUSTER_READ } from '../api/capabilities'
import { encodeObjectPanel } from './panelUrl'

const mockInspect = vi.fn()
const mockGetCluster = vi.fn()
const mockGetChanges = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    inspectCluster: (...a: unknown[]) => mockInspect(...a),
    getCluster: (...a: unknown[]) => mockGetCluster(...a),
    getResourceChanges: (...a: unknown[]) => mockGetChanges(...a),
  }
})
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 't' }) }))
const granted = new Set<string>()
vi.mock('../auth/useCapabilities', () => ({ useHasCapability: (c: string) => granted.has(c) }))
vi.mock('../graph/GraphCanvas', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../graph/GraphCanvas')>()
  return { ...actual, GraphCanvas: () => <div data-testid="graph" /> }
})

import { ObjectInspectorHost } from './ObjectInspector'

function renderAt(kind: string, apiGroup: string | undefined, name: string, ptab?: string) {
  const panel = encodeObjectPanel({ clusterId: 'c1', kind, apiGroup, namespace: 'payments', name })
  const qs = new URLSearchParams({ panel })
  if (ptab) qs.set('ptab', ptab)
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={[`/x?${qs}`]}>
        <ObjectInspectorHost />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const deployment = {
  apiVersion: 'apps/v1',
  kind: 'Deployment',
  metadata: { name: 'api', namespace: 'payments', labels: { app: 'api' }, annotations: { 'secret-token': '[REDACTED]' } },
  spec: { replicas: 2, template: { spec: { containers: [{ name: 'app', image: 'r/app:1' }] } } },
  status: { observedGeneration: 1, readyReplicas: 1 },
}

beforeEach(() => {
  granted.clear()
  mockInspect.mockReset()
  mockGetCluster.mockResolvedValue({ id: 'c1', displayName: 'prod-eu', state: 'Active', lastHeartbeatAt: new Date().toISOString() })
  mockGetChanges.mockResolvedValue({ changes: [], gaps: [] })
  mockInspect.mockImplementation((_c: string, tool: string) =>
    Promise.resolve({ tool, receivedAt: new Date().toISOString(), result: tool === 'describe_resource' ? { object: deployment, events: [] } : {} }),
  )
})

describe('ObjectInspector', () => {
  it('titles the panel with kind and name, and the subtitle with namespace and cluster name', async () => {
    granted.add(CAP_CLUSTER_INSPECT).add(CAP_CLUSTER_READ)
    renderAt('Deployment', 'apps', 'api')
    expect(screen.getByRole('dialog').textContent).toContain('Deployment')
    await waitFor(() => expect(screen.getByText('payments · prod-eu')).toBeTruthy())
  })

  it('lists every relevant tab on one row, most useful first, and none that are not', async () => {
    granted.add(CAP_CLUSTER_INSPECT).add(CAP_CLUSTER_READ)
    renderAt('Deployment', 'apps', 'api')
    // No "More" menu: everything is a tab, ordered by importance for the kind.
    const row = screen.getAllByRole('tab').map((t) => t.textContent)
    expect(row).toEqual(['Summary', 'Rollout', 'Events', 'Logs', 'Metrics', 'Related', 'Connectivity', 'Changes', 'Permissions', 'Policy', 'YAML'])
    expect(row).not.toContain('Scheduling')
    expect(screen.queryByRole('button', { name: /^More/ })).toBeNull()
  })

  it('moves between tabs with the arrow keys, which also scrolls a long row', async () => {
    granted.add(CAP_CLUSTER_INSPECT).add(CAP_CLUSTER_READ)
    renderAt('Deployment', 'apps', 'api')
    const summary = screen.getByRole('tab', { name: 'Summary' })
    summary.focus()
    fireEvent.keyDown(summary, { key: 'ArrowRight' })
    await waitFor(() => expect(screen.getByRole('tab', { name: 'Rollout' }).getAttribute('aria-selected')).toBe('true'))
    fireEvent.keyDown(screen.getByRole('tab', { name: 'Rollout' }), { key: 'End' })
    await waitFor(() => expect(screen.getByRole('tab', { name: 'YAML' }).getAttribute('aria-selected')).toBe('true'))
  })

  it('keeps a tab the viewer cannot use on the row, disabled with its reason', async () => {
    granted.add(CAP_CLUSTER_READ)
    renderAt('Deployment', 'apps', 'api')
    const policy = screen.getByRole('tab', { name: 'Policy' }) as HTMLButtonElement
    expect(policy.disabled).toBe(true)
    expect(policy.title).toContain(CAP_CLUSTER_INSPECT)
  })

  it('leads the Summary with the health word and the failing condition, failing conditions first', async () => {
    granted.add(CAP_CLUSTER_INSPECT).add(CAP_CLUSTER_READ)
    const stuck = {
      ...deployment,
      spec: { replicas: 1, template: { spec: { containers: [{ name: 'app', image: 'r/app:1', resources: { requests: { cpu: '100m' }, limits: { memory: '512Mi' } } }] } } },
      status: {
        observedGeneration: 2,
        replicas: 2,
        readyReplicas: 1,
        updatedReplicas: 1,
        conditions: [
          { type: 'Available', status: 'True', reason: 'MinimumReplicasAvailable' },
          { type: 'Progressing', status: 'False', reason: 'ProgressDeadlineExceeded', message: 'ReplicaSet api-2 has timed out progressing.' },
        ],
      },
    }
    mockInspect.mockImplementation((_c: string, tool: string) =>
      Promise.resolve({
        tool,
        receivedAt: new Date().toISOString(),
        result:
          tool === 'describe_resource'
            ? { object: stuck, events: [] }
            : {
                root: { kind: 'Deployment', namespace: 'payments', name: 'api' },
                nodes: [
                  { id: 'd', kind: 'Deployment', namespace: 'payments', name: 'api', status: 'degraded' },
                  { id: 'p1', kind: 'Pod', namespace: 'payments', name: 'api-new', status: 'degraded', statusReason: 'ContainerCreating', summary: { phase: 'Pending', nodeName: 'pool-1', restarts: 0 } },
                  { id: 's', kind: 'Service', namespace: 'payments', name: 'api-svc', status: 'healthy' },
                ],
                edges: [
                  { id: 'e1', source: 'd', target: 'p1', type: 'owns' },
                  { id: 'e2', source: 's', target: 'd', type: 'exposes' },
                ],
              },
      }),
    )
    renderAt('Deployment', 'apps', 'api')
    await waitFor(() => expect(screen.getByText('Degraded')).toBeTruthy())
    expect(screen.getByText('Progressing is False: ProgressDeadlineExceeded')).toBeTruthy()
    const items = screen.getAllByRole('listitem').filter((li) => li.className === 'check-list-item')
    expect(items[0].textContent).toContain('Progressing')
    expect(items[0].getAttribute('data-verdict')).toBe('failing')
    expect(screen.getByRole('img', { name: '2 replicas exist for 1 desired: 1 ready, 1 not ready' })).toBeTruthy()
    // Requests and limits, with an unset one said rather than blanked.
    expect(screen.getByTitle('request 100m · limit not set')).toBeTruthy()
    // The pod and the connected Service come from the shared neighbourhood read.
    await waitFor(() => expect(screen.getByRole('button', { name: 'api-new' })).toBeTruthy())
    expect(screen.getByText('Degraded · ContainerCreating')).toBeTruthy()
    expect(screen.getByRole('button', { name: /api-svc/ })).toBeTruthy()
  })

  it('disables, never hides, every live tab when the viewer lacks cluster:inspect', async () => {
    granted.add(CAP_CLUSTER_READ)
    renderAt('Deployment', 'apps', 'api')
    const yaml = screen.getByRole('tab', { name: 'YAML' }) as HTMLButtonElement
    expect(yaml.disabled).toBe(true)
    expect(yaml.title).toContain(CAP_CLUSTER_INSPECT)
    // Changes reads the hub's own history, gated by cluster:read instead.
    expect((screen.getByRole('tab', { name: 'Changes' }) as HTMLButtonElement).disabled).toBe(false)
    expect(mockInspect).not.toHaveBeenCalled()
  })

  it('says why in place when no tab at all is usable', () => {
    renderAt('Deployment', 'apps', 'api')
    expect(screen.getByText(/Restricted —/).textContent).toContain(CAP_CLUSTER_INSPECT)
  })

  it('marks redacted values in the YAML rather than showing them blank', async () => {
    granted.add(CAP_CLUSTER_INSPECT).add(CAP_CLUSTER_READ)
    renderAt('Deployment', 'apps', 'api', 'yaml')
    await waitFor(() => expect(screen.getAllByText('‹redacted›').length).toBeGreaterThan(0))
    expect(screen.getByText(/removed at capture time/)).toBeTruthy()
  })

  it('stamps the data stale when the cluster is not Active', async () => {
    granted.add(CAP_CLUSTER_INSPECT).add(CAP_CLUSTER_READ)
    mockGetCluster.mockResolvedValue({ id: 'c1', displayName: 'prod-eu', state: 'Disconnected', lastHeartbeatAt: null })
    renderAt('Deployment', 'apps', 'api')
    await waitFor(() => expect(screen.getByText(/Stale — as of/)).toBeTruthy())
    expect(screen.getByText(/cluster is Disconnected/)).toBeTruthy()
  })
})

describe('ObjectInspector — Connectivity', () => {
  const answer = (tool: string, args: Record<string, unknown>) => {
    switch (tool) {
      case 'describe_resource':
        return { object: deployment, events: [] }
      case 'get_neighborhood':
        return {
          nodes: [
            { id: 'd', kind: 'Deployment', namespace: 'payments', name: 'api' },
            { id: 's', kind: 'Service', namespace: 'payments', name: 'api-svc' },
          ],
          edges: [],
        }
      case 'trace_service_path':
        return { verdict: 'ok', headline: `Traffic to ${String(args.name)} reaches 2 ready pods`, subject: { kind: 'Service', namespace: 'payments', name: String(args.name) } }
      case 'evaluate_network_policy':
        return {
          verdict: { verdict: 'denied', direction: 'ingress', decidingPolicies: ['payments/default-deny'] },
          backends: 2,
          explanations: [{ policy: 'payments/default-deny', direction: 'ingress', explanation: { effect: 'doesNotAdmit', reason: 'no ingress rule admits the source' } }],
          note: 'Static prediction from core NetworkPolicy objects only.',
        }
      default:
        return {}
    }
  }

  beforeEach(() => {
    mockInspect.mockImplementation((_c: string, tool: string, args: Record<string, unknown>) =>
      Promise.resolve({ tool, receivedAt: new Date().toISOString(), result: answer(tool, args) }),
    )
  })

  it('traces a workload through the Service in front of it, found two hops out', async () => {
    granted.add(CAP_CLUSTER_INSPECT).add(CAP_CLUSTER_READ)
    renderAt('Deployment', 'apps', 'api', 'path')
    expect(await screen.findByText(/Traffic to api-svc reaches 2 ready pods/)).toBeTruthy()
    const nb = mockInspect.mock.calls.find((c) => c[1] === 'get_neighborhood')
    expect(nb?.[2]).toMatchObject({ kind: 'Deployment', hops: 2 })
  })

  it('checks NetworkPolicy from outside the cluster and states the verdict in words', async () => {
    granted.add(CAP_CLUSTER_INSPECT).add(CAP_CLUSTER_READ)
    renderAt('Deployment', 'apps', 'api', 'path')
    await screen.findByText(/Traffic to api-svc/)
    fireEvent.click(screen.getByRole('button', { name: 'Check' }))
    expect(await screen.findByText('Denied')).toBeTruthy()
    expect(screen.getByText(/Blocked by ingress policy/)).toBeTruthy()
    expect(screen.getByText('does not admit')).toBeTruthy()
    const call = mockInspect.mock.calls.find((c) => c[1] === 'evaluate_network_policy')
    expect(call?.[2]).toEqual({ source: { external: true }, destination: { kind: 'Service', namespace: 'payments', name: 'api-svc' } })
  })

  it('will not check from a pod until the pod is named', async () => {
    granted.add(CAP_CLUSTER_INSPECT).add(CAP_CLUSTER_READ)
    renderAt('Deployment', 'apps', 'api', 'path')
    await screen.findByText(/Traffic to api-svc/)
    fireEvent.click(screen.getByLabelText('A pod'))
    expect((screen.getByRole('button', { name: 'Check' }) as HTMLButtonElement).disabled).toBe(true)
    expect(screen.getByText('Name the source pod and its namespace.')).toBeTruthy()
  })
})

describe('ObjectInspector — Compare…', () => {
  it('offers Compare… in the header, disabled with the reason without cluster:inspect', () => {
    granted.add(CAP_CLUSTER_READ)
    renderAt('Deployment', 'apps', 'api')
    const btn = screen.getByRole('button', { name: 'Compare…' }) as HTMLButtonElement
    expect(btn.disabled).toBe(true)
    expect(btn.title).toMatch(/cluster:inspect/)
  })

  it('is enabled for a viewer who can inspect', () => {
    granted.add(CAP_CLUSTER_INSPECT).add(CAP_CLUSTER_READ)
    renderAt('Pod', undefined, 'api-1')
    expect((screen.getByRole('button', { name: 'Compare…' }) as HTMLButtonElement).disabled).toBe(false)
  })
})
