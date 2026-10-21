import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CAP_CLUSTER_INSPECT, CAP_REMEDIATION_EXECUTE_INPLACE } from '../../api/capabilities'
import { ApiError, PROBLEM_OBJECT_NOT_FOUND } from '../../api/client'
import type { IncidentDetail } from '../../api/types'

const mockInspect = vi.fn()
const mockMetrics = vi.fn()
const mockPreceding = vi.fn()
const mockQuick = vi.fn()

vi.mock('../../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../api/client')>()
  return {
    ...actual,
    inspectCluster: (...a: unknown[]) => mockInspect(...a),
    getCluster: () => Promise.resolve({ id: 'c1', displayName: 'prod-eu', state: 'Active', lastHeartbeatAt: null }),
    getIncidentMetrics: (...a: unknown[]) => mockMetrics(...a),
    getIncidentPrecedingChanges: (...a: unknown[]) => mockPreceding(...a),
    requestQuickAction: (...a: unknown[]) => mockQuick(...a),
  }
})
vi.mock('../../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 't' }) }))
const granted = new Set<string>()
vi.mock('../../auth/useCapabilities', () => ({ useHasCapability: (c: string) => granted.has(c) }))
vi.mock('../../graph/GraphCanvas', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../graph/GraphCanvas')>()
  return { ...actual, GraphCanvas: () => <div data-testid="graph" /> }
})

import { AffectedObjects, GitVsCluster, PrecedingChanges, ResourceUsage, WhyNotScheduled } from './InsightSections'

function incident(over: Partial<IncidentDetail>): IncidentDetail {
  return {
    id: 'inc_1',
    clusterId: 'c1',
    clusterDisplayName: 'prod-eu',
    findingGroups: [],
    ownership: null,
    objectGvk: 'v1/Pod',
    objectNamespace: 'payments',
    objectName: 'api-1',
    ...over,
  } as unknown as IncidentDetail
}

const argo = {
  managedBy: 'argocd' as const,
  sourceKind: 'Application',
  sourceName: 'shop',
  sourceNamespace: 'argocd',
  objectGvk: 'apps/v1/Deployment',
  objectNamespace: 'payments',
  objectName: 'api',
}

function renderUi(ui: React.ReactNode) {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  )
}

function openSection(title: string) {
  const details = screen.getByText(title).closest('details')!
  details.open = true
  fireEvent(details, new Event('toggle'))
}

const ok = (result: unknown) => Promise.resolve({ tool: 'x', receivedAt: new Date().toISOString(), result })

beforeEach(() => {
  granted.clear()
  mockInspect.mockReset()
  mockMetrics.mockReset()
  mockPreceding.mockReset()
  mockQuick.mockReset()
  mockPreceding.mockResolvedValue({ changes: [], gaps: [] })
})

describe('WhyNotScheduled (CI-S9)', () => {
  it('opens by default on a Pending pod and shows reason groups with counts', async () => {
    granted.add(CAP_CLUSTER_INSPECT)
    mockInspect.mockReturnValue(
      ok({ verdict: '0/9 nodes can run this pod: 6 untolerated taint.', nodesEvaluated: 9, nodes: [{ predicate: 'taint', reason: 'untolerated taint gpu=true', count: 6, examples: ['n1'] }] }),
    )
    renderUi(<WhyNotScheduled incident={incident({ openingReason: 'PendingTimeout' })} />)
    expect(await screen.findByText('0/9 nodes can run this pod: 6 untolerated taint.')).toBeTruthy()
    expect(screen.getByText('6')).toBeTruthy()
    expect(mockInspect).toHaveBeenCalledWith('c1', 'explain_scheduling', { namespace: 'payments', pod: 'api-1' }, 't')
  })

  it('says plainly that the pod is gone, and folds itself away', async () => {
    granted.add(CAP_CLUSTER_INSPECT)
    mockInspect.mockRejectedValue(new ApiError('The agent could not answer', 502, 'The agent reported: pod payments/api-1 not found.'))
    renderUi(<WhyNotScheduled incident={incident({ openingReason: 'PendingTimeout' })} />)
    expect(await screen.findByText(/Pod api-1 no longer exists — nothing left to schedule/)).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
    const details = screen.getByText("Why it isn't scheduled").closest('details')!
    expect(details.open).toBe(false)
  })

  it('reads the hub\'s object-not-found 404 as the pod being gone', async () => {
    granted.add(CAP_CLUSTER_INSPECT)
    mockInspect.mockRejectedValue(new ApiError('Not found', 404, 'The agent reported: Pod payments/api-1 not found.', PROBLEM_OBJECT_NOT_FOUND))
    renderUi(<WhyNotScheduled incident={incident({ openingReason: 'PendingTimeout' })} />)
    expect(await screen.findByText(/Pod api-1 no longer exists — nothing left to schedule/)).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('keeps an unrelated agent failure as an error, open', async () => {
    granted.add(CAP_CLUSTER_INSPECT)
    mockInspect.mockRejectedValue(new ApiError('The agent could not answer', 502, 'The agent did not answer in time.'))
    renderUi(<WhyNotScheduled incident={incident({ openingReason: 'PendingTimeout' })} />)
    expect(await screen.findByRole('alert')).toBeTruthy()
    expect(screen.getByText("Why it isn't scheduled").closest('details')!.open).toBe(true)
  })

  it('starts folded on a closed incident', () => {
    renderUi(<WhyNotScheduled incident={incident({ openingReason: 'PendingTimeout', state: 'Resolved' })} />)
    expect(screen.getByText("Why it isn't scheduled").closest('details')!.open).toBe(false)
  })

  it('renders nothing for an incident that is not a pending pod', () => {
    const { container } = renderUi(<WhyNotScheduled incident={incident({ openingReason: 'OOMKilled' })} />)
    expect(container.textContent).toBe('')
  })
})

describe('GitVsCluster quick actions (CI-S15)', () => {
  it('disables the request and names the capability when the viewer lacks it', () => {
    renderUi(<GitVsCluster incident={incident({ ownership: argo })} />)
    const button = screen.getByRole('button', { name: 'Request Argo refresh' }) as HTMLButtonElement
    expect(button.disabled).toBe(true)
    expect(screen.getAllByText(/You do not have permission/).some((el) => el.textContent?.includes(CAP_REMEDIATION_EXECUTE_INPLACE))).toBe(true)
  })

  it('says it is awaiting approval and links to the queue on success', async () => {
    granted.add(CAP_REMEDIATION_EXECUTE_INPLACE)
    mockQuick.mockResolvedValue({ recommendationId: 'r', gateOutcome: 'NeedsApproval', gateReason: 'policy' })
    renderUi(<GitVsCluster incident={incident({ ownership: argo })} />)
    fireEvent.click(screen.getByRole('button', { name: 'Request Argo refresh' }))
    expect(await screen.findByText(/awaiting approval/)).toBeTruthy()
    expect(screen.getByRole('link', { name: /approval queue/ }).getAttribute('href')).toBe('/approvals')
    expect(mockQuick).toHaveBeenCalledWith('inc_1', { action: 'argoRefresh', namespace: 'argocd', name: 'shop' }, 't')
  })

  it('explains a 409 as "analyse first"', async () => {
    granted.add(CAP_REMEDIATION_EXECUTE_INPLACE)
    mockQuick.mockRejectedValue(new ApiError('Analyse first', 409, 'no analysis', 'https://argus.io/errors/invalid-state'))
    renderUi(<GitVsCluster incident={incident({ ownership: argo })} />)
    fireEvent.click(screen.getByRole('button', { name: 'Request Argo refresh' }))
    expect((await screen.findByRole('alert')).textContent).toMatch(/^Analyse first/)
  })
})

describe('ResourceUsage (CI-S8)', () => {
  it("shows the server's reason instead of an empty chart", async () => {
    mockMetrics.mockResolvedValue({ available: false, reason: 'no Prometheus is configured for this cluster', panels: [] })
    renderUi(<ResourceUsage incident={incident({})} />)
    openSection('Resource usage')
    expect(await screen.findByText(/no Prometheus is configured/)).toBeTruthy()
    expect(screen.queryByRole('img')).toBeNull()
  })

  it('disables the time-range buttons with the reason once the hub says there is no metrics source', async () => {
    mockMetrics.mockResolvedValue({ available: false, reason: 'no Prometheus is configured for this cluster', panels: [] })
    renderUi(<ResourceUsage incident={incident({})} />)
    openSection('Resource usage')
    await screen.findByText(/no Prometheus is configured/)
    for (const r of ['1h', '6h', '24h']) {
      const b = screen.getByRole('button', { name: r }) as HTMLButtonElement
      expect(b.disabled).toBe(true)
      expect(b.title).toMatch(/no Prometheus is configured/)
    }
  })
})

describe('AffectedObjects (CI-S1)', () => {
  it('states a truncated graph above the canvas', async () => {
    granted.add(CAP_CLUSTER_INSPECT)
    mockInspect.mockReturnValue(
      ok({
        root: { kind: 'Pod', namespace: 'payments', name: 'api-1' },
        nodes: [
          { id: 'a', kind: 'Pod', namespace: 'payments', name: 'api-1', status: 'unhealthy' },
          { id: 'b', kind: 'Service', namespace: 'payments', name: 'api', status: 'healthy' },
        ],
        edges: [{ id: 'e', source: 'b', target: 'a', type: 'routes-to' }],
        truncated: true,
      }),
    )
    renderUi(<AffectedObjects incident={incident({})} />)
    openSection('Affected objects')
    expect(await screen.findByText(/Partial graph — the neighbourhood hit its size cap/)).toBeTruthy()
    expect(screen.getByTestId('graph')).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Export as PNG' })).toBeTruthy()
  })

  it('treats a pod that is gone as an empty state, not an error', async () => {
    granted.add(CAP_CLUSTER_INSPECT)
    mockInspect.mockRejectedValue(new ApiError('Not found', 404, 'The agent reported: Pod payments/api-1 not found.', PROBLEM_OBJECT_NOT_FOUND))
    renderUi(<AffectedObjects incident={incident({})} />)
    openSection('Affected objects')
    expect(await screen.findByText(/is no longer on the cluster, so there are no relationships to show/)).toBeTruthy()
    expect(screen.queryByRole('alert')).toBeNull()
  })

  it('says the section is restricted without cluster:inspect', () => {
    renderUi(<AffectedObjects incident={incident({})} />)
    openSection('Affected objects')
    expect(screen.getByText(/Restricted —/).textContent).toContain(CAP_CLUSTER_INSPECT)
    expect(mockInspect).not.toHaveBeenCalled()
  })
})

describe('PrecedingChanges (CI-S2)', () => {
  it('renders newest first, grouped by owner, with a gap banner', async () => {
    mockPreceding.mockResolvedValue({
      changes: [
        { id: '1', clusterId: 'c1', observedAt: '2026-10-10T13:00:00Z', kind: 'ReplicaSet', name: 'api-abc', namespace: 'payments', ownerKind: 'Deployment', ownerName: 'api', op: 'update', fields: [], summary: 'replicas: 1→0' },
        { id: '2', clusterId: 'c1', observedAt: '2026-10-10T14:02:00Z', kind: 'Deployment', name: 'api', namespace: 'payments', op: 'update', fields: [], summary: 'image app: v1.4→v1.5' },
      ],
      gaps: [{ from: '2026-10-10T12:00:00Z', to: '2026-10-10T12:10:00Z', reason: 'agent disconnected' }],
    })
    renderUi(<PrecedingChanges incident={incident({})} />)
    openSection('Changes before this incident')
    expect(await screen.findByText(/Change history incomplete/)).toBeTruthy()
    expect(screen.getByText('×2 changes')).toBeTruthy()
    expect(screen.getByText(/image app: v1.4 → v1.5/)).toBeTruthy()
    // The older change is behind the group's disclosure until expanded.
    expect(screen.queryByText(/replicas: 1 → 0/)).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /×2 changes/ }))
    expect(screen.getByText(/replicas: 1 → 0/)).toBeTruthy()
  })
})

describe('waits for open', () => {
  it('fetches nothing until a collapsed section is opened', async () => {
    renderUi(<ResourceUsage incident={incident({})} />)
    await waitFor(() => expect(mockMetrics).not.toHaveBeenCalled())
  })
})
