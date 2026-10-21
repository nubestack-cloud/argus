import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, within } from '@testing-library/react'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CAP_CLUSTER_INSPECT, CAP_CLUSTER_READ } from '../api/capabilities'

// Cluster detail's tabs (docs/CLUSTER_INSIGHT_SPECS.md CI-S11 and the views
// under it): the active tab is in the URL, and the live-read tabs are
// disabled — not hidden — with the capability named when it is missing.

const mockGetCluster = vi.fn()
const mockGetIncidents = vi.fn()
const mockLatestScan = vi.fn()
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    getCluster: (...a: unknown[]) => mockGetCluster(...a),
    getIncidents: (...a: unknown[]) => mockGetIncidents(...a),
    getLatestUpgradeScan: (...a: unknown[]) => mockLatestScan(...a),
    getResourceChanges: vi.fn().mockResolvedValue({ changes: [], gaps: [] }),
    getFleetUpgradeScans: vi.fn().mockResolvedValue({ scans: [] }),
    inspectCluster: vi.fn().mockResolvedValue({ tool: 'x', receivedAt: '2026-10-10T10:00:00Z', result: { available: false, reason: 'no Prometheus' } }),
  }
})
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 't' }) }))
const caps = new Set<string>()
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (c: string) => caps.has(c),
  useMissingCapabilities: (list: string[]) => ({ resolved: true, missing: list.filter((c) => !caps.has(c)) }),
}))

import { ClusterDetailPage } from './ClusterDetailPage'

function Loc() {
  return <p data-testid="loc">{useLocation().search}</p>
}

function renderAt(url: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>
        <Routes>
          <Route path="/clusters/:id" element={<><ClusterDetailPage /><Loc /></>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  caps.clear()
  caps.add(CAP_CLUSTER_READ)
  mockGetCluster.mockResolvedValue({
    id: 'cl_1',
    displayName: 'prod-eu',
    state: 'Active',
    agentVersion: '1.0.0',
    lastHeartbeatAt: '2026-10-10T10:00:00Z',
    createdAt: '2026-01-01T00:00:00Z',
    archivedAt: null,
    compatibility: { verdict: 'compatible', label: 'Compatible', agentVersion: '1.0.0', minSupportedVersion: '1.0.0', recommendedVersion: '1.0.0', reason: '' },
    facts: { kubernetesVersion: '1.31.4', nodeCount: 1, nodes: [], reachable: true },
    factsUpdatedAt: '2026-10-10T10:00:00Z',
  })
  mockGetIncidents.mockResolvedValue({ incidents: [], counts: {} })
  mockLatestScan.mockResolvedValue({ scan: null })
})

describe('ClusterDetailPage tabs', () => {
  it('disables the live-read tabs with the capability named, never hiding them', async () => {
    renderAt('/clusters/cl_1')
    const posture = await screen.findByRole('tab', { name: 'Posture' })
    expect((posture as HTMLButtonElement).disabled).toBe(true)
    expect(posture.getAttribute('title')).toMatch(CAP_CLUSTER_INSPECT)
    expect((screen.getByRole('tab', { name: /^Upgrade/ }) as HTMLButtonElement).disabled).toBe(false)
    expect(screen.getByRole('tab', { name: 'Overview' }).getAttribute('aria-selected')).toBe('true')
    expect(screen.getByText(/No health summary yet/)).toBeTruthy()
  })

  it('keeps the active tab in the URL', async () => {
    caps.add(CAP_CLUSTER_INSPECT)
    renderAt('/clusters/cl_1?tab=upgrade')
    expect(await screen.findByText(/No upgrade scan has run for this cluster yet/)).toBeTruthy()
    fireEvent.click(screen.getByRole('tab', { name: 'Traffic' }))
    expect(screen.getByTestId('loc').textContent).toBe('?tab=traffic')
    expect(await screen.findByText(/no Prometheus/)).toBeTruthy()
  })

  // The owner's rule for this redesign: nothing that was on the page before
  // is lost. These are the figures most easily dropped in a re-layout.
  it('keeps every existing figure on the Overview: identity strip, node usage per node, counts, coverage', async () => {
    mockGetCluster.mockResolvedValue({
      id: 'cl_1',
      displayName: 'prod-eu',
      state: 'Active',
      agentVersion: '1.0.0',
      lastHeartbeatAt: '2026-10-10T10:00:00Z',
      createdAt: '2026-01-01T00:00:00Z',
      archivedAt: null,
      compatibility: { verdict: 'compatible', label: 'Compatible', agentVersion: '1.0.0', minSupportedVersion: '1.0.0', recommendedVersion: '1.0.0', reason: '' },
      facts: {
        kubernetesVersion: '1.31.4',
        nodeCount: 2,
        nodes: [
          { name: 'node-a', ready: true, cpuAllocatable: '4', memoryAllocatable: '8Gi', cpuUsed: '1', memoryUsed: '2Gi' },
          { name: 'node-b', ready: false, cpuAllocatable: '4', memoryAllocatable: '8Gi' },
        ],
        reachable: true,
        summary: {
          resourceCounts: {
            pods: { total: 10, running: 9, pending: 1, failed: 0, succeeded: 0 },
            nodes: { total: 2, ready: 1, notReady: 1, cordoned: 0 },
          },
          networkPolicyCoverage: { policies: 1, coveredWorkloads: 2, totalWorkloads: 5 },
          gitopsControllers: [],
        },
      },
      factsUpdatedAt: '2026-10-10T10:00:00Z',
    })
    mockGetIncidents.mockResolvedValue({ incidents: [], counts: { open: 0 } })
    renderAt('/clusters/cl_1')
    // Identity strip.
    expect(await screen.findByText('1.31.4')).toBeTruthy()
    // The header line carries the same five facts the old tile strip did.
    const facts = screen.getByRole('list', { name: 'Cluster facts' })
    expect(facts.textContent).toMatch(/heartbeat/)
    expect(facts.textContent).toMatch(/facts/)
    expect(facts.textContent).toMatch(/Kubernetes 1\.31\.4/)
    expect(facts.textContent).toMatch(/agent /)
    // Node table, with per-node CPU and memory use; an unreported one says so.
    const table = screen.getByRole('table')
    const rowA = within(table).getByRole('row', { name: /node-a/ })
    expect(within(rowA).getByRole('img', { name: /25% of 4 cores in use/ })).toBeTruthy()
    expect(within(rowA).getByRole('img', { name: /25% of 8 GiB in use/ })).toBeTruthy()
    const rowB = within(table).getByRole('row', { name: /node-b/ })
    expect(within(rowB).getAllByText('Not reported')).toHaveLength(2)
    // Cluster roll-up (was the "CPU in use"/"Memory in use" tiles).
    const use = screen.getByRole('region', { name: 'Resource use' })
    expect(within(use).getByText(/1 of 4 cores · 25%/)).toBeTruthy()
    expect(within(use).getAllByText('across 1 of 2 nodes')).toHaveLength(2)
    // Rings, coverage and GitOps.
    expect(within(screen.getByRole('region', { name: 'Pods' })).getByText(/9 running/)).toBeTruthy()
    expect(within(screen.getByRole('region', { name: 'Nodes' })).getByText(/1 not ready/)).toBeTruthy()
    expect(screen.getByText(/2 of 5 workloads selected/)).toBeTruthy()
    expect(screen.getByText('None detected')).toBeTruthy()
  })
})
