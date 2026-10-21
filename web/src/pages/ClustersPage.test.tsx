import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { AgentCompatibility, Cluster, ClusterGroupsResponse, ClustersResponse, Incident, IncidentsResponse } from '../api/types'
import { CAP_CLUSTER_ACCEPT, CAP_CLUSTER_DELETE, CAP_CLUSTER_ONBOARD } from '../api/capabilities'

// T16: every Cluster now carries a server-computed compatibility verdict.
// This fixture's default matches what the real policy returns for a
// currently-typical agent version — 'current', no missing features, no
// upgrade guidance — so tests that don't care about compatibility don't
// have to say so on every call to cluster(...).
const CURRENT_COMPATIBILITY: AgentCompatibility = {
  verdict: 'current',
  label: 'Current',
  agentVersion: '1.0.0',
  minSupportedVersion: '1.0.0',
  recommendedVersion: '1.0.0',
  reason: 'Agent version 1.0.0 meets the recommended version 1.0.0.',
}

// BACKLOG P3. ClustersPage layers search/state/version filters and four
// quick views over one fetched cluster array, plus a second, independently
// truncatable fetch (incidents) whose only job on this page is a derived
// per-cluster open-incident count — the exact count D7c fixed after it
// rendered a bare, healthy-looking `0` for a cluster whose incidents had
// all fallen past the fetch cap. These tests drive the rendered table and
// its action controls rather than re-deriving the filter predicates, same
// discipline as IncidentsPage/UsersPage.

const mockGetClusters = vi.fn()
const mockGetIncidents = vi.fn()
const mockAcceptCluster = vi.fn()
const mockDecommissionCluster = vi.fn()
const mockCreateEnrollmentToken = vi.fn()
const mockGetClusterGroups = vi.fn()

const mockGetFleetUpgradeScans = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    getClusters: (...args: unknown[]) => mockGetClusters(...args),
    getIncidents: (...args: unknown[]) => mockGetIncidents(...args),
    acceptCluster: (...args: unknown[]) => mockAcceptCluster(...args),
    decommissionCluster: (...args: unknown[]) => mockDecommissionCluster(...args),
    createEnrollmentToken: (...args: unknown[]) => mockCreateEnrollmentToken(...args),
    getClusterGroups: (...args: unknown[]) => mockGetClusterGroups(...args),
    getFleetUpgradeScans: (...args: unknown[]) => mockGetFleetUpgradeScans(...args),
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ accessToken: 'test-token' }),
}))

const capabilities = new Set<string>([CAP_CLUSTER_ONBOARD, CAP_CLUSTER_ACCEPT, CAP_CLUSTER_DELETE])
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (capability: string) => capabilities.has(capability),
}))

import { ClustersPage } from './ClustersPage'

function cluster(over: Partial<Cluster>): Cluster {
  return {
    id: 'cl_default',
    displayName: 'default-cluster',
    state: 'Active',
    agentVersion: '1.0.0',
    lastHeartbeatAt: '2026-08-25T09:00:00Z',
    createdAt: '2026-08-01T00:00:00Z',
    // Null unless a test is about a retired cluster: the hub always sends
    // the key, and sends a timestamp only for a decommissioned one.
    archivedAt: null,
    compatibility: CURRENT_COMPATIBILITY,
    ...over,
  }
}

const PROD = cluster({ id: 'cl_prod', displayName: 'prod-eu', state: 'Active', agentVersion: '1.2.0' })
const PENDING = cluster({ id: 'cl_pending', displayName: 'staging-new', state: 'PendingApproval', agentVersion: '1.1.0' })
const DISCONNECTED = cluster({ id: 'cl_disc', displayName: 'edge-1', state: 'Disconnected', agentVersion: '1.0.0' })
const ARCHIVED = cluster({ id: 'cl_archived', displayName: 'old-cluster', state: 'Archived', agentVersion: '1.0.0' })

function clustersResponse(clusters: Cluster[]): ClustersResponse {
  return { clusters }
}

function clusterGroupsResponse(groups: ClusterGroupsResponse['clusterGroups'] = []): ClusterGroupsResponse {
  return { clusterGroups: groups }
}

function incidentsResponse(incidents: Incident[], nextCursor?: string): IncidentsResponse {
  return {
    incidents,
    nextCursor,
    counts: { all: incidents.length, requiresAction: incidents.length, open: incidents.length, resolvedLast7Days: 0, fixNotHeld: 0, critical: 0, high: 0, medium: 0 },
  }
}

function openIncident(over: Partial<Incident>): Incident {
  return {
    id: 'inc_default',
    clusterId: 'cl_prod',
    clusterDisplayName: 'prod-eu',
    fingerprint: 'fp_default',
    severity: 'medium',
    state: 'Detected',
    firstSeen: '2026-08-20T10:00:00Z',
    lastSeen: '2026-08-20T10:00:00Z',
    occurrenceCount: 1,
    ...over,
  }
}

function renderPage(path = '/clusters') {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <ClustersPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  mockGetClusters.mockReset()
  mockGetIncidents.mockReset().mockResolvedValue(incidentsResponse([]))
  mockAcceptCluster.mockReset()
  mockDecommissionCluster.mockReset()
  mockCreateEnrollmentToken.mockReset()
  mockGetClusterGroups.mockReset().mockResolvedValue(clusterGroupsResponse())
  mockGetFleetUpgradeScans.mockReset().mockResolvedValue({ scans: [] })
  capabilities.clear()
  capabilities.add(CAP_CLUSTER_ONBOARD)
  capabilities.add(CAP_CLUSTER_ACCEPT)
  capabilities.add(CAP_CLUSTER_DELETE)
})

describe('ClustersPage — loading, empty, error', () => {
  it('shows the empty state when there are no clusters at all', async () => {
    mockGetClusters.mockResolvedValue(clustersResponse([]))
    renderPage()
    expect(await screen.findByText(/No clusters yet/i)).toBeTruthy()
  })

  it('renders the hub error message rather than swallowing the failure', async () => {
    const { ApiError } = await import('../api/client')
    mockGetClusters.mockRejectedValue(new ApiError('Request failed', 500, 'the cluster service is unreachable'))
    renderPage()
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/Request failed/)
    expect(alert.textContent).toMatch(/the cluster service is unreachable/)
  })
})

// BACKLOG.md S3 — read-only here: a filter and a per-row line, no management
// control (that lives on Settings → Roles & access; see ClusterGroupsCard).
describe('ClustersPage — cluster group filter and per-row membership (BACKLOG S3)', () => {
  it('shows no group filter and no group line when no cluster group exists', async () => {
    mockGetClusters.mockResolvedValue(clustersResponse([PROD]))
    renderPage()
    await screen.findByText('prod-eu')
    expect(screen.queryByLabelText('Filter by cluster group')).toBeNull()
    expect(screen.queryByText(/^Group:/)).toBeNull()
  })

  it("shows a cluster's group membership inline, and only for a cluster that has one", async () => {
    mockGetClusters.mockResolvedValue(clustersResponse([PROD, PENDING]))
    mockGetClusterGroups.mockResolvedValue(
      clusterGroupsResponse([{ id: 'clg_1', name: 'payments-team', clusterIds: ['cl_prod'] }]),
    )
    renderPage()
    await screen.findByText('prod-eu')
    const prodRow = screen.getByText('prod-eu').closest('tr') as HTMLElement
    expect(within(prodRow).getByText('Group: payments-team')).toBeTruthy()
    const pendingRow = screen.getByText('staging-new').closest('tr') as HTMLElement
    expect(within(pendingRow).queryByText(/^Group:/)).toBeNull()
  })

  it('filtering by group narrows the table to that group\'s members only', async () => {
    mockGetClusters.mockResolvedValue(clustersResponse([PROD, PENDING]))
    mockGetClusterGroups.mockResolvedValue(
      clusterGroupsResponse([{ id: 'clg_1', name: 'payments-team', clusterIds: ['cl_prod'] }]),
    )
    renderPage()
    await screen.findByText('prod-eu')
    expect(screen.getByText('staging-new')).toBeTruthy()

    fireEvent.change(screen.getByLabelText('Filter by cluster group'), { target: { value: 'payments-team' } })

    expect(screen.getByText('prod-eu')).toBeTruthy()
    expect(screen.queryByText('staging-new')).toBeNull()
  })
})

describe('ClustersPage — search, state, version filters and quick views', () => {
  beforeEach(() => {
    mockGetClusters.mockResolvedValue(clustersResponse([PROD, PENDING, DISCONNECTED]))
  })

  it('renders one row per cluster with its state badge', async () => {
    renderPage()
    expect(await screen.findByText('prod-eu')).toBeTruthy()
    expect(screen.getByText('staging-new')).toBeTruthy()
    expect(screen.getByText('edge-1')).toBeTruthy()
    expect(within(screen.getByText('prod-eu').closest('tr') as HTMLElement).getByText('Active')).toBeTruthy()
    expect(within(screen.getByText('staging-new').closest('tr') as HTMLElement).getByText('Pending approval')).toBeTruthy()
    expect(within(screen.getByText('edge-1').closest('tr') as HTMLElement).getByText('Disconnected')).toBeTruthy()
  })

  it('search narrows the table by cluster name', async () => {
    renderPage()
    await screen.findByText('prod-eu')
    fireEvent.change(screen.getByPlaceholderText(/Search by name, ID, or version/i), { target: { value: 'edge' } })

    expect(screen.queryByText('prod-eu')).toBeNull()
    expect(screen.queryByText('staging-new')).toBeNull()
    expect(screen.getByText('edge-1')).toBeTruthy()
  })

  // "List Filter Layouts" option C (owner, 2026-10-12): no state dropdown —
  // the views reach those states. A ?state= value from an old link still
  // filters, and is shown as a chip so the narrowing is never invisible.
  it('honours a ?state= link with a visible, removable chip instead of a state dropdown', async () => {
    renderPage('/clusters?state=PendingApproval')
    await screen.findByText('staging-new')
    expect(screen.queryByLabelText(/Filter by state/i)).toBeNull()
    expect(screen.queryByText('prod-eu')).toBeNull()
    expect(screen.queryByText('edge-1')).toBeNull()
    expect(screen.getByText(/State: Pending approval/i)).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: /Clear the state filter/i }))
    expect(await screen.findByText('prod-eu')).toBeTruthy()
    expect(screen.queryByText(/State: Pending approval/i)).toBeNull()
  })

  it('offers no version or compatibility dropdown when every cluster shares one value', async () => {
    mockGetClusters.mockResolvedValue(clustersResponse([PROD]))
    renderPage()
    await screen.findByText('prod-eu')
    expect(screen.queryByLabelText(/Filter by agent version/i)).toBeNull()
    expect(screen.queryByLabelText(/Filter by agent compatibility/i)).toBeNull()
  })

  // ClustersPage-specific: the version filter's option list is derived from
  // the fetched clusters themselves (there is no fixed enum, unlike state).
  it('the agent-version dropdown isolates clusters on that version', async () => {
    renderPage()
    await screen.findByText('prod-eu')
    fireEvent.change(screen.getByLabelText(/Filter by agent version/i), { target: { value: '1.0.0' } })

    expect(screen.queryByText('prod-eu')).toBeNull()
    expect(screen.queryByText('staging-new')).toBeNull()
    expect(screen.getByText('edge-1')).toBeTruthy()
  })

  // T16 acceptance criterion: "incompatible or feature-limited agents are
  // filterable fleet-wide." This drives the filter through the real
  // rendered <select>, the same way the state/version tests just above do —
  // not by calling a predicate function directly — so it also proves the
  // column actually shows the server-provided label rather than some other
  // text.
  it('the agent-compatibility dropdown isolates clusters with that verdict', async () => {
    mockGetClusters.mockResolvedValue(
      clustersResponse([
        PROD,
        PENDING,
        cluster({
          id: 'cl_disc',
          displayName: 'edge-1',
          state: 'Disconnected',
          agentVersion: '0.5.0',
          compatibility: {
            verdict: 'upgrade_required',
            label: 'Upgrade required',
            agentVersion: '0.5.0',
            minSupportedVersion: '1.0.0',
            recommendedVersion: '1.0.0',
            reason: 'Agent version 0.5.0 is older than 1.0.0, the oldest version this hub still accepts.',
          },
        }),
      ]),
    )
    renderPage()
    await screen.findByText('prod-eu')
    expect(within(screen.getByText('edge-1').closest('tr') as HTMLElement).getByText('Upgrade required')).toBeTruthy()

    fireEvent.change(screen.getByLabelText(/Filter by agent compatibility/i), { target: { value: 'upgrade_required' } })

    expect(screen.queryByText('prod-eu')).toBeNull()
    expect(screen.queryByText('staging-new')).toBeNull()
    expect(screen.getByText('edge-1')).toBeTruthy()
  })

  it('the "Pending approval" quick view matches the same predicate as the state filter', async () => {
    renderPage()
    await screen.findByText('prod-eu')
    fireEvent.click(screen.getByRole('button', { name: /^Pending approval/ }))

    expect(screen.queryByText('prod-eu')).toBeNull()
    expect(screen.getByText('staging-new')).toBeTruthy()
    expect(screen.queryByText('edge-1')).toBeNull()
  })

  it('the "Needs attention" quick view includes every non-healthy state, not just one', async () => {
    renderPage()
    await screen.findByText('prod-eu')
    fireEvent.click(screen.getByRole('button', { name: /^Needs attention/ }))

    expect(screen.queryByText('prod-eu')).toBeNull()
    expect(screen.getByText('staging-new')).toBeTruthy()
    expect(screen.getByText('edge-1')).toBeTruthy()
  })

  it('shows a "no clusters match" panel with a working Clear filters button', async () => {
    renderPage()
    await screen.findByText('prod-eu')
    fireEvent.change(screen.getByPlaceholderText(/Search by name, ID, or version/i), { target: { value: 'no-such-cluster' } })

    expect(await screen.findByText(/No clusters match these filters/i)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /Clear filters/i }))

    expect(await screen.findByText('prod-eu')).toBeTruthy()
    expect(screen.getByText('staging-new')).toBeTruthy()
    expect(screen.getByText('edge-1')).toBeTruthy()
  })
})

describe('ClustersPage — capability-gated actions are disabled, not hidden', () => {
  beforeEach(() => {
    mockGetClusters.mockResolvedValue(clustersResponse([PENDING]))
  })

  it('disables "Enroll a cluster" with the missing-capability reason when the actor lacks cluster:onboard', async () => {
    capabilities.delete(CAP_CLUSTER_ONBOARD)
    renderPage()
    await screen.findByText('staging-new')

    const enrollButton = screen.getByRole('button', { name: /Enroll a cluster/i })
    expect(enrollButton).toHaveProperty('disabled', true)
    expect(enrollButton.title).toMatch(new RegExp(CAP_CLUSTER_ONBOARD))
  })

  it('disables the row "Accept" button with the missing-capability reason when the actor lacks cluster:accept', async () => {
    capabilities.delete(CAP_CLUSTER_ACCEPT)
    renderPage()
    await screen.findByText('staging-new')

    const acceptButton = screen.getByRole('button', { name: /^Accept$/i })
    expect(acceptButton).toHaveProperty('disabled', true)
    expect(acceptButton.title).toMatch(new RegExp(CAP_CLUSTER_ACCEPT))
  })

  it('disables the "Decommission" menu item (but still shows it) when the actor lacks cluster:delete', async () => {
    capabilities.delete(CAP_CLUSTER_DELETE)
    renderPage()
    await screen.findByText('staging-new')

    fireEvent.click(screen.getByRole('button', { name: /Actions for staging-new/i }))
    const decommissionItem = screen.getByRole('menuitem', { name: /Decommission/i })
    expect(decommissionItem).toHaveProperty('disabled', true)
    expect(decommissionItem.title).toMatch(new RegExp(CAP_CLUSTER_DELETE))
  })
})

describe('ClustersPage — accepting a pending cluster is a real mutation', () => {
  it('calls the API with that cluster\'s id, and the row leaves the pending state once it refetches', async () => {
    // Dispatches on the ?archived= argument rather than counting calls in
    // order: this page issues TWO cluster requests (the live fleet, and the
    // retired list behind the Retired quick view), so a pair of
    // mockResolvedValueOnce would hand the retired query the value this test
    // meant for the refetch.
    let liveFleetCalls = 0
    mockGetClusters.mockImplementation((_accessToken: unknown, archived?: unknown) => {
      if (archived === 'only') return Promise.resolve(clustersResponse([]))
      liveFleetCalls += 1
      return Promise.resolve(
        clustersResponse([liveFleetCalls === 1 ? PENDING : { ...PENDING, state: 'Provisioning' }]),
      )
    })
    mockAcceptCluster.mockResolvedValue({ clusterId: 'cl_pending', state: 'Provisioning' })

    renderPage()
    await screen.findByText('staging-new')
    const row = () => screen.getByText('staging-new').closest('tr') as HTMLElement
    expect(within(row()).getByText('Pending approval')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: /^Accept$/i }))

    await waitFor(() => expect(mockAcceptCluster).toHaveBeenCalledWith('cl_pending', 'test-token'))
    await waitFor(() => expect(within(row()).getByText('Provisioning')).toBeTruthy())
    expect(within(row()).queryByText('Pending approval')).toBeNull()
  })
})

describe('ClustersPage — the open-incident column never fabricates a zero over a truncated fetch (D7c)', () => {
  it('renders a real zero when the incident fetch is complete', async () => {
    mockGetClusters.mockResolvedValue(clustersResponse([PROD]))
    mockGetIncidents.mockResolvedValue(incidentsResponse([]))
    renderPage()
    await screen.findByText('prod-eu')

    const row = screen.getByText('prod-eu').closest('tr') as HTMLElement
    expect(within(row).getByText('0')).toBeTruthy()
  })

  it('renders "N+" with a truncation title when the cluster has open incidents inside a truncated fetch', async () => {
    mockGetClusters.mockResolvedValue(clustersResponse([PROD]))
    mockGetIncidents.mockResolvedValue(
      incidentsResponse(
        [openIncident({ id: 'inc_1', clusterId: 'cl_prod', state: 'Detected' })],
        'more-incidents-cursor',
      ),
    )
    renderPage()
    await screen.findByText('prod-eu')

    const row = screen.getByText('prod-eu').closest('tr') as HTMLElement
    const countLink = within(row).getByText('1+')
    expect(countLink).toBeTruthy()
    expect(countLink.title).toMatch(/truncated/i)
  })

  // The exact D7c defect: a cluster whose open incidents all fell past the
  // fetch cap must NOT render a literal 0 — that reads as "healthy," which is
  // not what a truncated, zero-in-the-prefix result means.
  it('renders a dash, never a bare zero, when the fetch is truncated and no matching row was in the prefix', async () => {
    mockGetClusters.mockResolvedValue(clustersResponse([PROD]))
    mockGetIncidents.mockResolvedValue(
      incidentsResponse(
        [openIncident({ id: 'inc_other', clusterId: 'cl_other_cluster', state: 'Detected' })],
        'more-incidents-cursor',
      ),
    )
    renderPage()
    await screen.findByText('prod-eu')

    const row = screen.getByText('prod-eu').closest('tr') as HTMLElement
    expect(within(row).queryByText('0')).toBeNull()
    const dash = within(row).getByText('—')
    expect(dash.title).toMatch(/not proof/i)
  })
})

// BUGS.md's owner note ("a chclist selection style button on the clusters
// page ... where we can select and perform bulk action like decommissioning
// the clusters"): row checkboxes, select-all, the bulk-action bar, and
// bulk decommission calling the exact same per-item endpoint the row
// "Decommission" menu item already calls, once per selected cluster.
describe('ClustersPage — bulk selection and bulk decommission (BUGS.md\'s owner note)', () => {
  beforeEach(() => {
    mockGetClusters.mockResolvedValue(clustersResponse([PROD, PENDING, ARCHIVED]))
  })

  it('checking rows shows the bulk action bar with the right count, and Clear selection empties it', async () => {
    renderPage()
    await screen.findByText('prod-eu')

    expect(screen.queryByText(/selected$/)).toBeNull()

    fireEvent.click(screen.getByLabelText('Select prod-eu'))
    expect(await screen.findByText('1 cluster selected')).toBeTruthy()

    fireEvent.click(screen.getByLabelText('Select staging-new'))
    expect(screen.getByText('2 clusters selected')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: /Clear selection/i }))
    expect(screen.queryByText(/selected$/)).toBeNull()
  })

  it('an already-terminal cluster\'s checkbox is disabled (never silently selectable), and "select all" skips it', async () => {
    renderPage()
    await screen.findByText('prod-eu')

    const archivedCheckbox = screen.getByLabelText('Select old-cluster') as HTMLInputElement
    expect(archivedCheckbox.disabled).toBe(true)
    expect(archivedCheckbox.title).toMatch(/Already Archived/i)

    fireEvent.click(screen.getByLabelText('Select all eligible clusters on this page'))
    expect(await screen.findByText('2 clusters selected')).toBeTruthy()
    expect(archivedCheckbox.checked).toBe(false)
  })

  it('disables the bulk "Decommission…" action with the missing-capability reason when the actor lacks cluster:delete', async () => {
    capabilities.delete(CAP_CLUSTER_DELETE)
    renderPage()
    await screen.findByText('prod-eu')

    fireEvent.click(screen.getByLabelText('Select prod-eu'))
    const bulkButton = await screen.findByRole('button', { name: /^Decommission…$/ })
    expect(bulkButton).toHaveProperty('disabled', true)
    expect(bulkButton.title).toMatch(new RegExp(CAP_CLUSTER_DELETE))
  })

  it('a successful bulk decommission calls the endpoint once per selected cluster and reports success for each', async () => {
    mockDecommissionCluster.mockResolvedValue({ clusterId: 'x', state: 'Archived' })
    renderPage()
    await screen.findByText('prod-eu')

    fireEvent.click(screen.getByLabelText('Select prod-eu'))
    fireEvent.click(screen.getByLabelText('Select staging-new'))
    fireEvent.click(await screen.findByRole('button', { name: /^Decommission…$/ }))

    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText(/Type DECOMMISSION to confirm/i), {
      target: { value: 'DECOMMISSION' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /^Decommission 2$/ }))

    await waitFor(() => expect(mockDecommissionCluster).toHaveBeenCalledTimes(2))
    expect(mockDecommissionCluster).toHaveBeenCalledWith('cl_prod', 'test-token')
    expect(mockDecommissionCluster).toHaveBeenCalledWith('cl_pending', 'test-token')

    expect(await screen.findByText('2 of 2 succeeded.')).toBeTruthy()
    expect(within(dialog).getByText('prod-eu')).toBeTruthy()
    expect(within(dialog).getByText('staging-new')).toBeTruthy()
    expect(within(dialog).getAllByText('Succeeded')).toHaveLength(2)
  })

  // The task's own "no fabricated data" rule: a partial failure must show
  // the REAL per-row outcome, not a rounded or assumed count.
  it('a partially failed bulk decommission shows which succeeded and which failed, with the real reason', async () => {
    const { ApiError } = await import('../api/client')
    mockDecommissionCluster.mockImplementation((clusterId: string) =>
      clusterId === 'cl_prod'
        ? Promise.resolve({ clusterId, state: 'Archived' })
        : Promise.reject(new ApiError('Conflict', 409, 'cluster is in state "PendingApproval"')),
    )
    renderPage()
    await screen.findByText('prod-eu')

    fireEvent.click(screen.getByLabelText('Select prod-eu'))
    fireEvent.click(screen.getByLabelText('Select staging-new'))
    fireEvent.click(await screen.findByRole('button', { name: /^Decommission…$/ }))

    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText(/Type DECOMMISSION to confirm/i), {
      target: { value: 'decommission' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /^Decommission 2$/ }))

    expect(await screen.findByText('1 of 2 succeeded, 1 failed.')).toBeTruthy()
    expect(within(dialog).getByText('Succeeded')).toBeTruthy()
    expect(within(dialog).getByText(/Failed — Conflict/)).toBeTruthy()
  })
})

// Item 10 (cluster retirement UI) and item 6 (partial-fleet banner) from the
// external product review, tested together because their failure mode is the
// interaction between them: making retired clusters visible must not make
// them count as unwatched ones.
//
// The hub returns the two sets through two different requests — GET /clusters
// with no parameter is the live fleet, ?archived=only is the retired one — so
// these tests drive the mock the same way, dispatching on the argument. A
// mock that ignored it would prove nothing about the separation, which is the
// whole property under test.
function clustersByArchival(live: Cluster[], retired: Cluster[]) {
  return (_accessToken: unknown, archived?: unknown) =>
    Promise.resolve(clustersResponse(archived === 'only' ? retired : live))
}

const RETIRED_ONE = cluster({
  id: 'cl_ret_1',
  displayName: 'old-eu-1',
  state: 'Archived',
  archivedAt: '2026-06-01T10:00:00Z',
})
const RETIRED_TWO = cluster({
  id: 'cl_ret_2',
  displayName: 'old-eu-2',
  state: 'Archived',
  archivedAt: '2026-07-02T10:00:00Z',
})

describe('ClustersPage — retired clusters are shown and filterable, never merged into the fleet (review item 10)', () => {
  it('keeps retired clusters out of the default table and out of every quick-view count except its own', async () => {
    mockGetClusters.mockImplementation(clustersByArchival([PROD, DISCONNECTED], [RETIRED_ONE, RETIRED_TWO]))
    renderPage()
    await screen.findByText('prod-eu')

    expect(screen.queryByText('old-eu-1')).toBeNull()
    expect(screen.queryByText('old-eu-2')).toBeNull()

    // "All" is the live fleet, not the live fleet plus its history.
    const allTab = screen.getByRole('button', { name: /^All/ })
    expect(allTab.textContent).toMatch(/All2$/)
    await waitFor(() => expect(screen.getByRole('button', { name: /^Retired/ }).textContent).toMatch(/Retired2$/))
  })

  it('the Retired quick view shows them, with the date they were retired', async () => {
    mockGetClusters.mockImplementation(clustersByArchival([PROD], [RETIRED_ONE]))
    renderPage()
    await screen.findByText('prod-eu')

    fireEvent.click(await screen.findByRole('button', { name: /^Retired/ }))

    const row = (await screen.findByText('old-eu-1')).closest('tr') as HTMLElement
    expect(within(row).getByText(/^Retired /)).toBeTruthy()
    expect(screen.queryByText('prod-eu')).toBeNull()
  })

  it('offers no destructive control on a retired cluster — it is removed from the fleet, never deleted', async () => {
    mockGetClusters.mockImplementation(clustersByArchival([PROD], [RETIRED_ONE]))
    renderPage()
    await screen.findByText('prod-eu')
    fireEvent.click(await screen.findByRole('button', { name: /^Retired/ }))
    await screen.findByText('old-eu-1')

    expect((screen.getByLabelText('Select old-eu-1') as HTMLInputElement).disabled).toBe(true)
    fireEvent.click(screen.getByRole('button', { name: /Actions for old-eu-1/i }))
    // Disabled with the reason, not omitted — and with nothing harsher
    // beneath it. Retirement removes a cluster from the fleet; it never
    // destroys its incidents, audit rows or history.
    const decommission = screen.getByRole('menuitem', { name: /Decommission/i })
    expect(decommission).toHaveProperty('disabled', true)
    expect(decommission.title).toMatch(/Already Archived/i)
    expect(screen.queryByRole('menuitem', { name: /Delete|Purge|Erase/i })).toBeNull()
  })

  it('says "nothing has been decommissioned" rather than "no results for these filters" when the retired list is genuinely empty', async () => {
    mockGetClusters.mockImplementation(clustersByArchival([PROD], []))
    renderPage()
    await screen.findByText('prod-eu')
    fireEvent.click(await screen.findByRole('button', { name: /^Retired/ }))

    expect(await screen.findByText(/No cluster has been decommissioned/i)).toBeTruthy()
    expect(screen.queryByText(/No clusters match these filters/i)).toBeNull()
  })

  // The em-dash rule (ListFreshness's, applied to the one count on this page
  // with its own independently-failable request): a failed fetch is not
  // evidence that nothing has ever been decommissioned.
  it('renders the retired count as an em dash, never 0, when that request fails', async () => {
    const { ApiError } = await import('../api/client')
    mockGetClusters.mockImplementation((_token: unknown, archived?: unknown) =>
      archived === 'only'
        ? Promise.reject(new ApiError('Request failed', 500, 'could not list clusters'))
        : Promise.resolve(clustersResponse([PROD])),
    )
    renderPage()
    await screen.findByText('prod-eu')

    const retiredTab = await screen.findByRole('button', { name: /^Retired/ })
    await waitFor(() => expect(retiredTab.textContent).toMatch(/Retired—$/))
    expect(retiredTab.textContent).not.toMatch(/Retired0$/)
  })

  it('surfaces the failure rather than an empty table when the retired list could not be loaded', async () => {
    const { ApiError } = await import('../api/client')
    mockGetClusters.mockImplementation((_token: unknown, archived?: unknown) =>
      archived === 'only'
        ? Promise.reject(new ApiError('Request failed', 500, 'could not list clusters'))
        : Promise.resolve(clustersResponse([PROD])),
    )
    renderPage()
    await screen.findByText('prod-eu')
    fireEvent.click(await screen.findByRole('button', { name: /^Retired/ }))

    expect(await screen.findByText(/could not be loaded/i)).toBeTruthy()
    expect(screen.queryByText(/No cluster has been decommissioned/i)).toBeNull()
  })
})

describe('ClustersPage — the partial-fleet banner (review item 6)', () => {
  it('states how much of the fleet is unwatched, breaking it down by state', async () => {
    mockGetClusters.mockImplementation(
      clustersByArchival(
        [
          PROD,
          DISCONNECTED,
          cluster({ id: 'cl_disc2', displayName: 'edge-2', state: 'Disconnected' }),
          PENDING,
        ],
        [],
      ),
    )
    renderPage()
    await screen.findByText('prod-eu')

    const banner = await screen.findByRole('status')
    expect(banner.textContent).toMatch(/3 of 4 clusters are not reporting to ARGUS\./)
    // Never colour alone: the states are named in the text.
    expect(banner.textContent).toMatch(/2 Disconnected/)
    expect(banner.textContent).toMatch(/1 Pending approval/)
  })

  // The interaction these two items share, and the reason they were built
  // together: 352 retired clusters on the development instance would have
  // swamped a banner that counted "everything not Active".
  it('does not count retired clusters — a large retirement history leaves the numbers untouched', async () => {
    const manyRetired = Array.from({ length: 50 }, (_, index) =>
      cluster({
        id: `cl_ret_${index}`,
        displayName: `retired-${index}`,
        state: 'Archived',
        archivedAt: '2026-05-01T00:00:00Z',
      }),
    )
    mockGetClusters.mockImplementation(clustersByArchival([PROD, DISCONNECTED], manyRetired))
    renderPage()
    await screen.findByText('prod-eu')

    const banner = await screen.findByRole('status')
    expect(banner.textContent).toMatch(/1 of 2 clusters are not reporting to ARGUS\./)
    expect(banner.textContent).not.toMatch(/Archived/)
    expect(banner.textContent).not.toMatch(/51 of 52/)
  })

  it('makes no claim at all when every cluster is reporting', async () => {
    mockGetClusters.mockImplementation(clustersByArchival([PROD], [RETIRED_ONE]))
    renderPage()
    await screen.findByText('prod-eu')

    expect(screen.queryByRole('status')).toBeNull()
  })

  // No fabricated number: with the fleet fetch failed there is no numerator
  // and no denominator, so there is no sentence either.
  it('makes no claim when the fleet could not be fetched', async () => {
    const { ApiError } = await import('../api/client')
    mockGetClusters.mockRejectedValue(new ApiError('Request failed', 500, 'the cluster service is unreachable'))
    renderPage()
    await screen.findByRole('alert')

    expect(screen.queryByRole('status')).toBeNull()
    expect(screen.queryByText(/not reporting to ARGUS/)).toBeNull()
  })

  it('its action filters the table to exactly the clusters it counted', async () => {
    mockGetClusters.mockImplementation(clustersByArchival([PROD, DISCONNECTED, PENDING], [RETIRED_ONE]))
    renderPage()
    await screen.findByText('prod-eu')

    fireEvent.click(await screen.findByRole('button', { name: /Show the clusters that are not reporting/i }))

    expect(screen.queryByText('prod-eu')).toBeNull()
    expect(screen.getByText('edge-1')).toBeTruthy()
    expect(screen.getByText('staging-new')).toBeTruthy()
    expect(screen.queryByText('old-eu-1')).toBeNull()
    // The banner's number and the view it opens are one expression, so the
    // tab it selects must show the same count it claimed.
    const banner = await screen.findByRole('status')
    expect(banner.textContent).toMatch(/2 of 3 clusters are not reporting/)
    expect(screen.getByRole('button', { name: /^Not reporting/ }).textContent).toMatch(/Not reporting2$/)
  })
})

describe('ClustersPage — upgrade readiness column (CI-S5)', () => {
  it('shows each scanned cluster\'s verdict as a word and "Not scanned" otherwise', async () => {
    mockGetClusters.mockResolvedValue(clustersResponse([PROD, DISCONNECTED]))
    mockGetFleetUpgradeScans.mockResolvedValue({
      scans: [
        { id: 'ups_1', clusterId: 'cl_prod', currentVersion: '1.31.4', targetVersion: '1.32', verdict: 'blocked', reviewedThrough: '1.34', scannedAt: '2026-10-10T09:00:00Z' },
      ],
    })
    renderPage()
    expect(await screen.findByRole('columnheader', { name: /^Upgrade to 1\.32/ })).toBeTruthy()
    const prodRow = screen.getByRole('row', { name: /prod-eu/ })
    expect(within(prodRow).getByText('Blocked')).toBeTruthy()
    expect(within(prodRow).getByRole('link', { name: /Blocked/ }).getAttribute('href')).toBe('/clusters/cl_prod?tab=upgrade')
    expect(within(screen.getByRole('row', { name: /edge-1/ })).getByText('Not scanned')).toBeTruthy()
  })
})

// Owner QA 2026-10-11: clicking a row did nothing here, unlike Incidents,
// Signals and Search; and two clusters enrolled close together both read
// "ID cl_01m3p" because the head of a ULID is its timestamp.
describe('ClustersPage — row navigation and ids', () => {
  function WhereAmI() {
    return <p data-testid="where">{useLocation().pathname}</p>
  }
  function renderWithLocation() {
    const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    return render(
      <QueryClientProvider client={queryClient}>
        <MemoryRouter initialEntries={['/clusters']}>
          <ClustersPage />
          <WhereAmI />
        </MemoryRouter>
      </QueryClientProvider>,
    )
  }

  it('opens a cluster from a click anywhere on its row, and from Enter on the focused row', async () => {
    mockGetClusters.mockResolvedValue(clustersResponse([PROD, DISCONNECTED]))
    renderWithLocation()
    const row = (await screen.findByRole('link', { name: 'prod-eu' })).closest('tr')!
    // A plain cell — not the name link — is what a row click means.
    fireEvent.click(within(row).getByText('ID cl_prod'))
    expect(screen.getByTestId('where').textContent).toBe('/clusters/cl_prod')
    const edge = screen.getByRole('link', { name: 'edge-1' }).closest('tr')!
    fireEvent.keyDown(edge, { key: 'Enter' })
    expect(screen.getByTestId('where').textContent).toBe('/clusters/cl_disc')
  })

  it('does not open the row when its checkbox is clicked', async () => {
    mockGetClusters.mockResolvedValue(clustersResponse([PROD]))
    renderWithLocation()
    fireEvent.click(await screen.findByRole('checkbox', { name: 'Select prod-eu' }))
    expect(screen.getByTestId('where').textContent).toBe('/clusters')
  })

  it('shows the random tail of two same-day cluster ids so they differ', async () => {
    mockGetClusters.mockResolvedValue(
      clustersResponse([
        cluster({ id: 'cl_01m3pq7x8yzab12cdefg34hjkm', displayName: 'lab-dev' }),
        cluster({ id: 'cl_01m3pq9w2vqrs56tuvwx78yzab', displayName: 'rke2' }),
      ]),
    )
    renderPage()
    expect(await screen.findByText('ID cl_…fg34hjkm')).toBeTruthy()
    expect(screen.getByText('ID cl_…wx78yzab')).toBeTruthy()
  })
})
