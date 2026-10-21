import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { Cluster, ClusterDetail, IncidentOverview } from '../api/types'

// The whole page with every section fed realistic payloads, so a runtime error
// in any card fails here rather than as a blank Overview. The figures each card
// derives are covered by overview/model.test.ts; this checks they arrive on
// the page, and that the whole-set numbers come from the hub's aggregates.

const compat = { verdict: 'current', label: 'Current', agentVersion: '0.14.2', minSupportedVersion: '0.1.0', recommendedVersion: '0.14.2', reason: '' }
const clusters: Cluster[] = [
  { id: 'cl_eu', displayName: 'prod-eu-1', state: 'Active', agentVersion: '0.14.2', lastHeartbeatAt: '2026-10-12T11:59:00Z', createdAt: '2026-01-01T00:00:00Z', archivedAt: null, compatibility: compat },
  { id: 'cl_edge', displayName: 'edge-01', state: 'Disconnected', agentVersion: '0.14.1', lastHeartbeatAt: '2026-10-12T09:00:00Z', createdAt: '2026-01-01T00:00:00Z', archivedAt: null, compatibility: { ...compat, verdict: 'unknown' } },
] as Cluster[]

const details: Record<string, ClusterDetail> = {
  cl_eu: {
    ...clusters[0],
    facts: {
      kubernetesVersion: 'v1.29.8',
      nodeCount: 2,
      reachable: true,
      nodes: [
        { name: 'eu-w01', ready: true, cpuAllocatable: '4', memoryAllocatable: '8Gi', cpuUsed: '2', memoryUsed: '7Gi' },
        { name: 'eu-w02', ready: false, cpuAllocatable: '4', memoryAllocatable: '8Gi', cpuUsed: '1', memoryUsed: '6Gi' },
      ],
    },
  } as unknown as ClusterDetail,
  cl_edge: { ...clusters[1], facts: { kubernetesVersion: 'v1.30.2', nodeCount: 1, reachable: false, nodes: [{ name: 'edge-1', ready: true, cpuAllocatable: '2', memoryAllocatable: '4Gi' }] } } as unknown as ClusterDetail,
}

const overview: IncidentOverview = {
  days: 14,
  generatedAt: '2026-10-12T12:00:00Z',
  byState: [
    { state: 'Detected', count: 1 },
    { state: 'AwaitingApproval', count: 1 },
    { state: 'Validating', count: 2 },
  ],
  byCluster: [{ clusterId: 'cl_eu', critical: 1, high: 1, medium: 2, low: 0, open: 4, requiresAction: 2, fixNotHeld: 0 }],
  daily: Array.from({ length: 14 }, (_, i) => ({
    date: new Date(Date.UTC(2026, 8, 29 + i)).toISOString().slice(0, 10),
    opened: { critical: i === 13 ? 1 : 0, high: i === 10 ? 1 : 0, medium: 0, low: 0 },
    resolved: 0,
    openAtEnd: 2 + Math.floor(i / 5),
  })),
}

// The hub's stored checks for prod-eu-1; edge-01 is disconnected and has not
// been read. The fleet size is a test parameter so the caps can be exercised.
const at = '2026-10-12T11:55:00Z'
const ok = <T,>(summary: T) => ({ summary, summaryAt: at, error: null, errorAt: null })
let extraClusters: Cluster[] = []
function fleetSummary() {
  const all = [...clusters, ...extraClusters]
  return {
    intervalSeconds: 600,
    clusters: all.map((c) => ({
      clusterId: c.id,
      facts: details[c.id]?.facts ?? { kubernetesVersion: 'v1.29.8', nodeCount: 1, reachable: true, nodes: [{ name: `${c.id}-n1`, ready: true }] },
      factsUpdatedAt: at,
      checksReadable: true,
      checks:
        c.id === 'cl_eu'
          ? {
              certificates: ok({ listed: 3, unknown: 0, later: 2, due: [{ name: 'ingress-tls', namespace: 'payments', daysLeft: 6 }], dueTotal: 1, truncated: false }),
              posture: ok({ danger: 3, warning: 4, categories: { Security: { danger: 3, warning: 2, passing: 10 }, Reliability: { danger: 0, warning: 2, passing: 5 }, Efficiency: { danger: 0, warning: 0, passing: 5 } } }),
              helm: ok({ total: 2, listed: 2, failing: 1, truncated: false }),
              gitops: ok({ total: 1, listed: 1, problems: 0, truncated: false }),
            }
          : c.id === 'cl_edge'
            ? {}
            : {
                posture: ok({ danger: 0, warning: 1, categories: { Security: { danger: 0, warning: 1, passing: 3 } } }),
                helm: ok({ total: 3, listed: 3, failing: 0, truncated: false }),
              },
    })),
  }
}

vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 'test-token' }) }))
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: () => true,
  useMissingCapabilities: () => ({ resolved: true, missing: [] }),
}))
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    getClusters: async () => ({ clusters: [...clusters, ...extraClusters] }),
    getCluster: async () => {
      throw new Error('the Overview must not read clusters one by one')
    },
    getFleetSummary: async () => fleetSummary(),
    getIncidentCounts: async () => ({ all: 30, requiresAction: 2, open: 4, resolvedLast7Days: 5, fixNotHeld: 0, critical: 1, high: 1, medium: 2 }),
    getIncidentOverview: async () => overview,
    getIncidentQueue: async () => ({
      incidents: [
        { id: 'inc_a', clusterId: 'cl_eu', clusterDisplayName: 'prod-eu-1', fingerprint: 'f', severity: 'critical', state: 'AwaitingApproval', firstSeen: '2026-10-11T12:00:00Z', lastSeen: '2026-10-12T11:00:00Z', occurrenceCount: 3, objectName: 'kafka-broker', objectGvk: 'apps/v1/StatefulSet', objectNamespace: 'streaming' },
        { id: 'inc_b', clusterId: 'cl_eu', clusterDisplayName: 'prod-eu-1', fingerprint: 'g', severity: 'high', state: 'Detected', firstSeen: '2026-10-12T10:00:00Z', lastSeen: '2026-10-12T11:00:00Z', occurrenceCount: 1, objectName: 'search-indexer' },
      ],
      counts: { all: 2, requiresAction: 2, open: 2, resolvedLast7Days: 0, fixNotHeld: 0, critical: 1, high: 1, medium: 0 },
    }),
    getApprovals: async () => ({ approvals: [{ incidentId: 'inc_a', alreadyApproved: false, plan: { createdAt: '2026-10-10T08:00:00Z' } }], counts: { pending: 1 } }),
    getSpendToday: async () => ({ todaySpendUsd: 4.12, dailySpendCeilingUsd: 25, spendCountable: true, pricingConfigured: true, ceilingBreached: false }),
    getSettings: async () => ({ llm: { providerKind: 'api', baseUrl: 'http://llm', cliRunnerUrl: '' }, autonomy: { unattendedExecutionEnabled: false, unattendedNamespaces: [], effectiveMaxUnattendedPerCluster: 2, effectiveMaxUnattendedFleetWide: 5, effectiveUnattendedWindowSeconds: 3600 } }),
    getCircuitBreaker: async () => ({ enabled: true, open: [], history: [] }),
    getAutomationWindows: async () => ({
      windows: [{ id: 'w', kind: 'freeze', schedule: '0 18 * * 5', durationSeconds: 172800, timezone: 'UTC', createdAt: 'x', openNow: false, reason: 'weekend', upcoming: [{ start: '2026-10-16T18:00:00Z', end: '2026-10-18T18:00:00Z' }] }],
      automationOpenNow: true,
      decisionReason: '',
    }),
    getFleetUpgradeScans: async () => ({ scans: [{ id: 's', clusterId: 'cl_eu', currentVersion: '1.29.8', targetVersion: '1.30', verdict: 'blocked', reviewedThrough: '1.30', scannedAt: '2026-10-11T00:00:00Z' }] }),
    inspectCluster: async () => {
      throw new Error('the Overview must not call agents on load')
    },
  }
})

import { OverviewPage } from './OverviewPage'

describe('OverviewPage — every section renders from realistic payloads', () => {
  // The fixtures are dated around 2026-10-12T12:00Z, and every wait is
  // measured from the clock, so the clock is pinned there.
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(new Date('2026-10-12T12:00:00Z'))
  })
  afterEach(() => vi.useRealTimers())

  it('draws the tiles, the three bands and the automation line', async () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <OverviewPage />
        </MemoryRouter>
      </QueryClientProvider>,
    )
    expect(await screen.findByRole('heading', { level: 1, name: 'Overview' })).toBeTruthy()
    // Whole-set figures, from the counts and the overview aggregate.
    const open = await screen.findByRole('link', { name: /Open incidents/ })
    expect(within(open).getByText('4')).toBeTruthy()
    expect(within(open).getByRole('img', { name: /Open incidents by where they are in the loop/ })).toBeTruthy()
    // Nodes from the clusters' facts: 2 of 3 ready, one NotReady.
    expect(await screen.findByText('1 NotReady')).toBeTruthy()
    // The queue: the decision is measured from its plan, and the silent cluster is listed.
    const queue = screen.getByRole('region', { name: 'Waiting on a person' })
    expect(within(queue).getByText('kafka-broker')).toBeTruthy()
    expect(within(queue).getByText('2 d 4 h')).toBeTruthy()
    expect(within(queue).getByText('edge-01')).toBeTruthy()
    // Bands and their cards.
    for (const name of ['Now', 'Next 90 days', 'Standing']) expect(screen.getByRole('region', { name })).toBeTruthy()
    expect(await screen.findByText('6 d')).toBeTruthy()
    expect(screen.getByRole('link', { name: /prod-eu-1 runs 1.29; upgrade to 1.30: Blocked/ })).toBeTruthy()
    expect(await screen.findByText('1 failing')).toBeTruthy()
    expect(screen.getByText('Unattended execution off')).toBeTruthy()
    expect(screen.getByText('$4.12')).toBeTruthy()
    // The stored checks say how old they are.
    expect(screen.getAllByText(/checked 5m ago/).length).toBeGreaterThan(0)
  })

  it('at fleet scale, every card draws at most eight rows and counts the rest', async () => {
    extraClusters = Array.from({ length: 20 }, (_, i) => ({
      ...clusters[0],
      id: `cl_x${String(i).padStart(2, '0')}`,
      displayName: `fleet-${String(i).padStart(2, '0')}`,
    }))
    try {
      const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
      render(
        <QueryClientProvider client={qc}>
          <MemoryRouter>
            <OverviewPage />
          </MemoryRouter>
        </QueryClientProvider>,
      )
      const rings = await screen.findByRole('region', { name: 'Clusters' })
      // The first list is the rings; the second is the severity legend.
      expect(within(within(rings).getAllByRole('list')[0]).getAllByRole('listitem')).toHaveLength(8)
      expect(within(rings).getByText(/\+ 14 more clusters/)).toBeTruthy()

      const posture = screen.getByRole('region', { name: 'Posture' })
      expect(within(posture).getAllByRole('row')).toHaveLength(1 + 8)
      // 21 reachable clusters (edge-01 is disconnected): 8 rows, 13 counted.
      expect(within(posture).getByText(/\+ 13 more clusters/)).toBeTruthy()

      // 21 clusters on 1.29, 20 of them unscanned: one version-path row for those.
      const ladder = screen.getByRole('region', { name: 'Upgrade ladder' })
      expect(within(ladder).getByText('20 clusters')).toBeTruthy()

      const delivery = screen.getByRole('region', { name: 'Delivery & agents' })
      expect(within(delivery).getByText(/\+ 13 more clusters/)).toBeTruthy()
    } finally {
      extraClusters = []
    }
  })
})
