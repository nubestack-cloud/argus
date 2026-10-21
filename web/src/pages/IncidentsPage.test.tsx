import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, within, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { KeyboardShortcutProvider } from '../keyboard/shortcuts'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { Incident, IncidentsResponse } from '../api/types'
import { CAP_CLUSTER_READ, CAP_INCIDENT_TRIAGE } from '../api/capabilities'
import { incidentRequiresAction, isClosedIncidentState, STATE_DISPOSITION } from '../utils/incidents'

// BACKLOG P3. IncidentsPage is the highest logic-density untested page: a
// free-text search, two dropdown filters, five quick-view tabs, sortable
// columns and a quick-view modal all run client-side over one fetched array
// (utils/incidents.ts's own comment: this can be a PREFIX of the real set,
// but everything below still has to behave correctly over what arrived).
// These tests exercise that logic through the actual rendered table rather
// than by re-deriving the filtering/sorting predicates in isolation, because
// the thing that has broken here before (BUGS.md 68, 73) was the row
// markup disagreeing with the data, not the predicates themselves.

const mockGetIncidents = vi.fn()
const mockDismissIncident = vi.fn()
const mockGetClusters = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    getIncidents: (...args: unknown[]) => mockGetIncidents(...args),
    dismissIncident: (...args: unknown[]) => mockDismissIncident(...args),
    getClusters: (...args: unknown[]) => mockGetClusters(...args),
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ accessToken: 'test-token' }),
}))

// Same pattern as ClustersPage.test.tsx's capability mock — a mutable Set so
// individual tests can delete a capability to exercise the disabled-not-
// hidden path.
const capabilities = new Set<string>([CAP_INCIDENT_TRIAGE])
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (capability: string) => capabilities.has(capability),
  useMissingCapabilities: (caps: string[]) => ({ resolved: true, missing: caps.filter((c) => !capabilities.has(c)) }),
}))

import { IncidentsPage } from './IncidentsPage'
import { ApiError } from '../api/client'

function incident(over: Partial<Incident>): Incident {
  return {
    id: 'inc_default',
    clusterId: 'cl_1',
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

const CRITICAL = incident({
  id: 'inc_1',
  fingerprint: 'fp_critical',
  severity: 'critical',
  state: 'Detected',
  occurrenceCount: 5,
  lastSeen: '2026-08-20T12:00:00Z',
  objectGvk: 'apps/v1/Deployment',
  objectNamespace: 'payments',
  objectName: 'payments-api',
  openingReason: 'OOMKilled',
})

const RESOLVED = incident({
  id: 'inc_2',
  fingerprint: 'fp_resolved',
  clusterDisplayName: 'staging',
  severity: 'medium',
  state: 'Resolved',
  occurrenceCount: 1,
  lastSeen: '2026-08-20T09:00:00Z',
  objectGvk: 'apps/v1/Deployment',
  objectNamespace: 'checkout',
  objectName: 'checkout-worker',
  openingReason: 'CrashLoopBackOff',
})

const AWAITING = incident({
  id: 'inc_3',
  fingerprint: 'fp_awaiting',
  severity: 'low',
  state: 'AwaitingApproval',
  occurrenceCount: 2,
  lastSeen: '2026-08-20T11:00:00Z',
  objectGvk: 'batch/v1/CronJob',
  objectNamespace: 'billing',
  objectName: 'billing-cron',
  openingReason: 'ImagePullBackOff',
})

// A real edge of orchestrator.allowedTransitions: Investigating has NO edge
// to Dismissed at all (another writer — the running analysis — owns the
// state), so this fixture must be excluded from bulk-dismiss selection
// entirely, same as handleDismissIncident's own 409 for this state.
const RUNNING = incident({
  id: 'inc_4',
  fingerprint: 'fp_running',
  severity: 'high',
  state: 'Investigating',
  occurrenceCount: 1,
  lastSeen: '2026-08-20T13:00:00Z',
  objectGvk: 'apps/v1/Deployment',
  objectNamespace: 'search',
  objectName: 'search-indexer',
  openingReason: 'CrashLoopBackOff',
})

// The two states the review's finding 9 is actually about, and the state its
// finding 6 introduced. Both are "open" under either definition — what they
// prove is that the QUICK VIEW now divides on who owes work, not on
// terminality: RUNNING (Investigating) is open and drops OUT of the view,
// DIAGNOSED is finished and stays IN it.
const DIAGNOSED = incident({
  id: 'inc_5',
  fingerprint: 'fp_diagnosed',
  severity: 'medium',
  state: 'Diagnosed',
  occurrenceCount: 3,
  lastSeen: '2026-08-20T14:00:00Z',
  objectGvk: 'apps/v1/StatefulSet',
  objectNamespace: 'data',
  objectName: 'kafka-broker',
  openingReason: 'FailedMount',
})

const REJECTED = incident({
  id: 'inc_6',
  fingerprint: 'fp_rejected',
  severity: 'high',
  state: 'PlanRejected',
  occurrenceCount: 4,
  lastSeen: '2026-08-20T15:00:00Z',
  objectGvk: 'apps/v1/Deployment',
  objectNamespace: 'auth',
  objectName: 'auth-gateway',
  openingReason: 'OOMKilled',
})

function renderPage(path = '/incidents') {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[path]}>
        <IncidentsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function resolveIncidents(incidents: Incident[]): IncidentsResponse {
  return {
    incidents,
    counts: {
      all: incidents.length,
      // The server's own definition, mirrored: the states where nothing moves
      // until a person acts — NOT "everything that is not terminal", which is
      // what this stood in for before the counter was renamed and would now
      // make the tab's number disagree with the rows under it.
      requiresAction: incidents.filter((i) => incidentRequiresAction(i.state)).length,
      // Mirrored the same way: "open" is the complement of the closed set, a
      // WIDER bucket than requiresAction (an incident ARGUS is investigating,
      // or one awaiting a merge, is open and owes a human nothing). Computed
      // rather than pinned so a fixture cannot claim more open incidents than
      // it has rows.
      open: incidents.filter((i) => !isClosedIncidentState(i.state)).length,
      // No fixture here exercises resolved_at, so this is honestly 0 rather
      // than a made-up figure — the pages under test read it only to render a
      // tile, and a wrong number would be a test asserting a fiction.
      resolvedLast7Days: 0,
      // No fixture here drives a failed or reopened execution, so 0 is the
      // honest value rather than a number invented to make a tile look alive.
      fixNotHeld: 0,
      critical: incidents.filter((i) => i.severity === 'critical').length,
      high: incidents.filter((i) => i.severity === 'high').length,
      medium: incidents.filter((i) => i.severity === 'medium').length,
    },
    breakdown: breakdownOf(incidents),
  }
}

// The server's status × severity matrix (incidentBreakdownFor), computed the
// same way: disposition by STATE_DISPOSITION, one cell per pair present.
function breakdownOf(incidents: Incident[]): NonNullable<IncidentsResponse['breakdown']> {
  const cells = new Map<string, { status: 'requiresAction' | 'inProgress' | 'closed'; severity: Incident['severity']; count: number }>()
  for (const i of incidents) {
    const status = STATE_DISPOSITION[i.state]
    const key = `${status}/${i.severity}`
    const cell = cells.get(key) ?? { status, severity: i.severity, count: 0 }
    cell.count++
    cells.set(key, cell)
  }
  return [...cells.values()]
}

function inStatus(incident: Incident, status?: string): boolean {
  const d = STATE_DISPOSITION[incident.state]
  if (!status) return true
  if (status === 'open') return d !== 'closed'
  return d === status
}

// fakeServerIncidents stands in for internal/api/incidents.go's ?search=/
// ?sort=/?direction= handling (BACKLOG P10) — real filtering/sorting logic
// over `all`, keyed off the same positional arguments client.ts's
// getIncidents actually sends, rather than a canned response every call
// returns regardless of what the page asked for. That is deliberate: these
// tests are exercising IncidentsPage's search box, sort headers and quick
// views end to end through a real (mocked) round trip, not asserting on
// getIncidents' call arguments directly.
function fakeServerIncidents(all: Incident[]) {
  return (
    _accessToken: string,
    _clusterId?: string,
    state?: string,
    _fleetGroupId?: string,
    _workloadGroupId?: string,
    search?: string,
    sort?: string,
    direction?: 'asc' | 'desc',
    _objectGroupId?: string,
    severity?: string,
    status?: string,
  ): Promise<IncidentsResponse> => {
    // ?state= is a SCOPE parameter: internal/api/incidents.go's
    // incidentScopeFilter is shared between handleListIncidents' row query
    // AND incidentCountsFor's aggregate, so it narrows the rows and the
    // counts together — unlike ?search=, which narrows only the rows.
    const inScope = state ? all.filter((incident) => incident.state === state) : all
    let rows = inScope
    if (search) {
      const term = search.toLocaleLowerCase()
      rows = rows.filter((incident) =>
        [
          incident.fingerprint,
          incident.id,
          incident.clusterDisplayName,
          incident.clusterId,
          incident.openingReason,
          incident.objectName,
          incident.objectNamespace,
        ].some((value) => (value ?? '').toLocaleLowerCase().includes(term)),
      )
    }
    if (sort === 'occurrences') {
      rows = [...rows].sort((a, b) =>
        direction === 'asc' ? a.occurrenceCount - b.occurrenceCount : b.occurrenceCount - a.occurrenceCount,
      )
    }
    // The breakdown lifts status and severity (the axes it counts) but keeps
    // every other filter, search included — incidentBreakdownFor.
    const breakdown = breakdownOf(rows)
    rows = rows.filter((incident) => inStatus(incident, status) && (!severity || incident.severity === severity))
    // `counts` stays over the state-scoped set, ignoring ?search=, as the real
    // endpoint's incidentCounts does.
    return Promise.resolve({ ...resolveIncidents(inScope), incidents: rows, breakdown })
  }
}

beforeEach(() => {
  mockGetIncidents.mockReset()
  mockDismissIncident.mockReset()
  mockGetClusters.mockReset()
  mockGetClusters.mockResolvedValue({ clusters: [{ id: 'cl_a', displayName: 'rke2' }, { id: 'cl_b', displayName: 'lab-dev' }] })
  capabilities.clear()
  capabilities.add(CAP_INCIDENT_TRIAGE)
})

describe('IncidentsPage — loading, empty, error', () => {
  it('shows the empty state when the fleet has no incidents at all', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([]))
    renderPage()
    expect(await screen.findByText(/No incidents yet/i)).toBeTruthy()
  })

  it('renders the hub error message rather than swallowing the failure', async () => {
    mockGetIncidents.mockRejectedValue(new ApiError('Request failed', 500, 'the analysis service is unreachable'))
    renderPage()
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/Request failed/)
    expect(alert.textContent).toMatch(/the analysis service is unreachable/)
  })
})

const statusTab = (name: RegExp) =>
  within(screen.getByRole('navigation', { name: 'Incident status' })).getByRole('button', { name })
const lastCall = () => mockGetIncidents.mock.calls[mockGetIncidents.mock.calls.length - 1]

// The two filter axes (pages/incidentFilters.ts), every one applied by the
// server: status tabs (Open by default) and a severity dropdown, with state
// and cluster dropdowns beside them. Driven through fakeServerIncidents, which
// filters the way the endpoint does, so these exercise the round trip.
describe('IncidentsPage — status tabs, severity and state filters', () => {
  beforeEach(() => {
    mockGetIncidents.mockImplementation(fakeServerIncidents([CRITICAL, RESOLVED, AWAITING]))
  })

  it('opens on the Open tab: closed incidents are not listed, and the request says so', async () => {
    renderPage()
    expect(await screen.findByText('payments-api')).toBeTruthy()
    expect(screen.getByText('billing-cron')).toBeTruthy()
    expect(screen.queryByText('checkout-worker')).toBeNull()
    expect(statusTab(/^Open/).getAttribute('aria-pressed')).toBe('true')
    expect(lastCall()[10]).toBe('open')
  })

  it('counts every tab under the other filters, from the server breakdown', async () => {
    renderPage()
    await screen.findByText('payments-api')
    expect(within(statusTab(/^Open/)).getByText('2')).toBeTruthy()
    expect(within(statusTab(/^Needs action/)).getByText('2')).toBeTruthy()
    expect(within(statusTab(/^In progress/)).getByText('0')).toBeTruthy()
    expect(within(statusTab(/^Closed/)).getByText('1')).toBeTruthy()
    expect(within(statusTab(/^All/)).getByText('3')).toBeTruthy()

    // A severity narrows the tab counts too: only the critical one is open.
    fireEvent.change(screen.getByLabelText('Filter by severity'), { target: { value: 'critical' } })
    await waitFor(() => expect(within(statusTab(/^Open/)).getByText('1')).toBeTruthy())
    expect(within(statusTab(/^Closed/)).getByText('0')).toBeTruthy()
  })

  it('reads the counts from the server, not from the rows that arrived', async () => {
    mockGetIncidents.mockResolvedValue({
      incidents: [CRITICAL],
      nextCursor: 'cur_1',
      counts: { all: 37, requiresAction: 30, open: 31, resolvedLast7Days: 0, fixNotHeld: 0, critical: 12, high: 10, medium: 8 },
      breakdown: [
        { status: 'requiresAction', severity: 'critical', count: 12 },
        { status: 'requiresAction', severity: 'medium', count: 18 },
        { status: 'inProgress', severity: 'high', count: 1 },
        { status: 'closed', severity: 'high', count: 6 },
      ],
    })
    const { container } = renderPage()
    await screen.findByText('payments-api')
    expect(within(statusTab(/^Open/)).getByText('31')).toBeTruthy()
    expect(within(statusTab(/^All/)).getByText('37')).toBeTruthy()
    // Exact over the whole set, so no "at least" mark beside it.
    const resultCount = container.querySelector('.list-result-count')
    expect(resultCount?.textContent).toContain('31 matching incidents')
    expect(resultCount?.querySelector('.figure-partial')).toBeNull()
    expect(screen.getByText(/Showing the first 1 of 31 matching incidents/)).toBeTruthy()
    // The severity options count within the chosen status.
    const critical = within(screen.getByLabelText('Filter by severity')).getByRole('option', { name: /Critical/ })
    expect(critical.textContent).toBe('Critical (12)')
  })

  it('narrows to the matching row when searching by object name', async () => {
    renderPage()
    await screen.findByText('payments-api')
    fireEvent.change(screen.getByPlaceholderText(/Search incidents/i), { target: { value: 'billing' } })
    // Positive and negative together: during the debounced refetch every row
    // is briefly absent, which would let a negative-only check pass early.
    await waitFor(() => {
      expect(screen.getByText('billing-cron')).toBeTruthy()
      expect(screen.queryByText('payments-api')).toBeNull()
    })
    expect(screen.getByText(/^1 matching incident$/)).toBeTruthy()
  })

  it('searching by the opening reason also matches, not just the object name', async () => {
    renderPage()
    await screen.findByText('payments-api')
    fireEvent.change(screen.getByPlaceholderText(/Search incidents/i), { target: { value: 'OOMKilled' } })
    await waitFor(() => {
      expect(screen.getByText('payments-api')).toBeTruthy()
      expect(screen.queryByText('billing-cron')).toBeNull()
    })
  })

  it('sends the severity to the server and shows only those rows', async () => {
    renderPage()
    await screen.findByText('payments-api')
    fireEvent.change(screen.getByLabelText('Filter by severity'), { target: { value: 'critical' } })
    await waitFor(() => {
      expect(lastCall()[9]).toBe('critical')
      expect(screen.getByText('payments-api')).toBeTruthy()
      expect(screen.queryByText('billing-cron')).toBeNull()
    })
  })

  it('offers only the states inside the chosen status, and sends the chosen one', async () => {
    renderPage()
    await screen.findByText('payments-api')
    const stateSelect = () => screen.getByLabelText(/Filter by state/i) as HTMLSelectElement
    const values = () => Array.from(stateSelect().options).map((o) => o.value)
    expect(values()).toContain('AwaitingApproval')
    expect(values()).not.toContain('Resolved')

    fireEvent.click(statusTab(/^Closed/))
    await waitFor(() => expect(values()).toEqual(['', 'Resolved', 'Dismissed', 'Expired']))
    fireEvent.change(stateSelect(), { target: { value: 'Resolved' } })
    await waitFor(() => {
      expect(lastCall()[2]).toBe('Resolved')
      expect(screen.getByText('checkout-worker')).toBeTruthy()
      expect(screen.queryByText('payments-api')).toBeNull()
    })
  })

  it('switching to a status that cannot hold the chosen state clears it', async () => {
    renderPage()
    await screen.findByText('payments-api')
    fireEvent.change(screen.getByLabelText(/Filter by state/i), { target: { value: 'AwaitingApproval' } })
    await waitFor(() => expect(lastCall()[2]).toBe('AwaitingApproval'))
    fireEvent.click(statusTab(/^Closed/))
    await waitFor(() => {
      expect(lastCall()[2]).toBeUndefined()
      expect(lastCall()[10]).toBe('closed')
    })
  })

  // Who owes work, not what is terminal: an investigation ARGUS is running is
  // open but in progress; a finished diagnosis with a live fault needs a person.
  it('Needs action keeps a Diagnosed incident; In progress holds the running investigation', async () => {
    mockGetIncidents.mockImplementation(fakeServerIncidents([DIAGNOSED, RUNNING, REJECTED]))
    renderPage()
    await screen.findByText('kafka-broker')

    fireEvent.click(statusTab(/^Needs action/))
    await waitFor(() => {
      expect(screen.getByText('kafka-broker')).toBeTruthy()
      expect(screen.getByText('auth-gateway')).toBeTruthy()
      expect(screen.queryByText('search-indexer')).toBeNull()
    })

    fireEvent.click(statusTab(/^In progress/))
    await waitFor(() => {
      expect(screen.getByText('search-indexer')).toBeTruthy()
      expect(screen.queryByText('kafka-broker')).toBeNull()
    })
  })

  // Finding 6: a refused plan has to be legible as a refused plan.
  it('renders a rejected plan as its own state rather than as a closed incident', async () => {
    mockGetIncidents.mockImplementation(fakeServerIncidents([REJECTED]))
    renderPage()
    await screen.findByText('auth-gateway')
    const row = screen.getByText('auth-gateway').closest('tr')!
    expect(within(row).getByText('Fix rejected')).toBeTruthy()
    expect(within(row).queryByText('Dismissed')).toBeNull()
    expect(within(row).queryByText('Resolved')).toBeNull()
  })

  it('says "Nothing is open" when only closed incidents exist, and offers them', async () => {
    mockGetIncidents.mockImplementation(fakeServerIncidents([RESOLVED]))
    renderPage()
    expect(await screen.findByText('Nothing is open')).toBeTruthy()
    expect(screen.queryByText(/fleet is quiet/i)).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: 'Show closed' }))
    expect(await screen.findByText('checkout-worker')).toBeTruthy()
  })

  it('shows a "no rows match" panel with a working Clear filters button, distinct from the true empty state', async () => {
    renderPage()
    await screen.findByText('payments-api')
    fireEvent.change(screen.getByPlaceholderText(/Search incidents/i), { target: { value: 'no-such-incident-exists' } })

    expect(await screen.findByText(/No incidents match this view/i)).toBeTruthy()
    expect(screen.queryByText(/fleet is quiet/i)).toBeNull()

    const clear = screen.getAllByRole('button', { name: /Clear filters/i })
    fireEvent.click(clear[clear.length - 1])
    expect(await screen.findByText('payments-api')).toBeTruthy()
    expect(screen.getByText('billing-cron')).toBeTruthy()
  })

  it('shows Clear filters in the toolbar only when the view is not the default', async () => {
    const { container } = renderPage()
    await screen.findByText('payments-api')
    expect(container.querySelector('.incidents-clear-filters')).toBeNull()
    fireEvent.click(statusTab(/^All/))
    await waitFor(() => expect(container.querySelector('.incidents-clear-filters')).toBeTruthy())
  })

  // BACKLOG P10: sort is server-side now — clicking a header changes
  // ?sort=/?direction= and triggers a real (mocked) round trip rather than a
  // synchronous client re-sort, so each order check waits for that response
  // via waitFor instead of reading the DOM immediately after the click.
  it('sorting by Detections actually reorders the rows, and reverses on a second click', async () => {
    // Closed rows are only listed under All.
    renderPage('/incidents?status=all')
    await screen.findByText('payments-api')

    const rowsInOrder = () =>
      within(screen.getByRole('table')).getAllByRole('row').slice(1).map((row) => row.textContent ?? '')

    fireEvent.click(screen.getByRole('button', { name: /Detections/i }))
    // Switching to a new sort key defaults to descending for 'occurrences'
    // (IncidentsPage's own changeSort rule) — highest count first.
    await waitFor(() => {
      const order = rowsInOrder()
      expect(order.findIndex((r) => r.includes('payments-api'))).toBeLessThan(
        order.findIndex((r) => r.includes('checkout-worker')),
      )
    })

    fireEvent.click(screen.getByRole('button', { name: /Detections/i }))
    await waitFor(() => {
      const order = rowsInOrder()
      expect(order.findIndex((r) => r.includes('checkout-worker'))).toBeLessThan(
        order.findIndex((r) => r.includes('payments-api')),
      )
    })
  })

  it('opening Quick view from the row menu shows that incident\'s own detail, not the wrong row\'s', async () => {
    // Closed rows are only listed under All.
    renderPage('/incidents?status=all')
    await screen.findByText('payments-api')

    // Named by the incident's object, never its sha256 fingerprint (live QA
    // 2026-10-11): the fingerprint is not what anyone scanning the row reads.
    expect(screen.queryByRole('button', { name: /Actions for incident fp_/i })).toBeNull()
    fireEvent.click(screen.getByRole('button', { name: /Actions for incident checkout-worker/i }))
    fireEvent.click(screen.getByRole('menuitem', { name: /Quick view/i }))

    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText('staging')).toBeTruthy()
    expect(within(dialog).getByText(/fp_resolved/)).toBeTruthy()
  })
})

// BUGS.md's owner note names clusters/decommission as the example; it names
// no specific incident action, so this page offers the most conservative of
// the two existing close-out verdicts (dismiss, not resolve — see
// ConfirmBulkDismissModal.tsx's own comment for why) as a bulk action,
// reusing POST /incidents/{id}/dismiss once per selected row.
describe('IncidentsPage — bulk selection and bulk dismiss (BUGS.md\'s owner note)', () => {
  beforeEach(() => {
    mockGetIncidents.mockImplementation(fakeServerIncidents([CRITICAL, RESOLVED, AWAITING, RUNNING]))
  })

  it('checking rows shows the bulk action bar with the right count, and Clear selection empties it', async () => {
    renderPage()
    await screen.findByText('payments-api')

    expect(screen.queryByText(/selected$/)).toBeNull()

    fireEvent.click(screen.getByLabelText('Select incident payments-api'))
    expect(await screen.findByText('1 incident selected')).toBeTruthy()

    fireEvent.click(screen.getByLabelText('Select incident billing-cron'))
    expect(screen.getByText('2 incidents selected')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: /Clear selection/i }))
    expect(screen.queryByText(/selected$/)).toBeNull()
  })

  it('a Resolved incident and one still Investigating are both excluded from selection, and "select all" skips them', async () => {
    // Closed rows are only listed under All.
    renderPage('/incidents?status=all')
    await screen.findByText('payments-api')

    const resolvedCheckbox = screen.getByLabelText('Select incident checkout-worker') as HTMLInputElement
    expect(resolvedCheckbox.disabled).toBe(true)
    expect(resolvedCheckbox.title).toMatch(/Already Resolved/i)

    const runningCheckbox = screen.getByLabelText('Select incident search-indexer') as HTMLInputElement
    expect(runningCheckbox.disabled).toBe(true)
    expect(runningCheckbox.title).toMatch(/investigation is currently running/i)

    fireEvent.click(screen.getByLabelText('Select all eligible incidents on this page'))
    // Only CRITICAL (Detected) and AWAITING (AwaitingApproval) are eligible.
    expect(await screen.findByText('2 incidents selected')).toBeTruthy()
    expect(resolvedCheckbox.checked).toBe(false)
    expect(runningCheckbox.checked).toBe(false)
  })

  it('disables the bulk "Dismiss…" action with the missing-capability reason when the actor lacks incident:triage', async () => {
    capabilities.delete(CAP_INCIDENT_TRIAGE)
    renderPage()
    await screen.findByText('payments-api')

    fireEvent.click(screen.getByLabelText('Select incident payments-api'))
    const bulkButton = await screen.findByRole('button', { name: /^Dismiss…$/ })
    expect(bulkButton).toHaveProperty('disabled', true)
    expect(bulkButton.title).toMatch(new RegExp(CAP_INCIDENT_TRIAGE))
  })

  it('a successful bulk dismiss calls the endpoint once per selected incident with the shared note, and reports success for each', async () => {
    mockDismissIncident.mockResolvedValue({
      incidentId: 'x',
      verdict: 'dismissed',
      incidentState: 'Dismissed',
      message: 'Dismissed',
    })
    renderPage()
    await screen.findByText('payments-api')

    fireEvent.click(screen.getByLabelText('Select incident payments-api'))
    fireEvent.click(screen.getByLabelText('Select incident billing-cron'))
    fireEvent.click(await screen.findByRole('button', { name: /^Dismiss…$/ }))

    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText(/Why are these being dismissed/i), {
      target: { value: 'known-broken dev workloads, tracked in JIRA-1234' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /^Dismiss 2$/ }))

    await waitFor(() => expect(mockDismissIncident).toHaveBeenCalledTimes(2))
    expect(mockDismissIncident).toHaveBeenCalledWith(
      'inc_1',
      'known-broken dev workloads, tracked in JIRA-1234',
      'test-token',
    )
    expect(mockDismissIncident).toHaveBeenCalledWith(
      'inc_3',
      'known-broken dev workloads, tracked in JIRA-1234',
      'test-token',
    )

    expect(await screen.findByText('2 of 2 succeeded.')).toBeTruthy()
    expect(within(dialog).getByText('payments-api')).toBeTruthy()
    expect(within(dialog).getByText('billing-cron')).toBeTruthy()
    expect(within(dialog).getAllByText('Succeeded')).toHaveLength(2)
  })

  // The task's own "no fabricated data" rule: a partial failure must show
  // the REAL per-row outcome, not a rounded or assumed count.
  it('a partially failed bulk dismiss shows which succeeded and which failed, with the real reason', async () => {
    mockDismissIncident.mockImplementation((incidentId: string) =>
      incidentId === 'inc_1'
        ? Promise.resolve({ incidentId, verdict: 'dismissed', incidentState: 'Dismissed', message: 'Dismissed' })
        : Promise.reject(new ApiError('Conflict', 409, 'incident is already closed (Resolved)')),
    )
    renderPage()
    await screen.findByText('payments-api')

    fireEvent.click(screen.getByLabelText('Select incident payments-api'))
    fireEvent.click(screen.getByLabelText('Select incident billing-cron'))
    fireEvent.click(await screen.findByRole('button', { name: /^Dismiss…$/ }))

    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText(/Why are these being dismissed/i), {
      target: { value: 'testing partial failure' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /^Dismiss 2$/ }))

    expect(await screen.findByText('1 of 2 succeeded, 1 failed.')).toBeTruthy()
    expect(within(dialog).getByText('Succeeded')).toBeTruthy()
    expect(within(dialog).getByText(/Failed — Conflict/)).toBeTruthy()
  })
})

describe('IncidentsPage — the resolution route column', () => {
  const ROUTED_PR = incident({
    id: 'inc_pr',
    fingerprint: 'fp_pr',
    objectName: 'api-gateway',
    objectGvk: 'apps/v1/Deployment',
    objectNamespace: 'edge',
    openingReason: 'OOMKilled',
    route: 'pullRequest',
  })
  const ROUTED_GUIDANCE = incident({
    id: 'inc_guidance',
    fingerprint: 'fp_guidance',
    objectName: 'legacy-batch',
    objectGvk: 'batch/v1/CronJob',
    objectNamespace: 'ops',
    openingReason: 'FailedMount',
    route: 'guidance',
  })
  const UNROUTED = incident({
    id: 'inc_unrouted',
    fingerprint: 'fp_unrouted',
    objectName: 'never-investigated',
    objectGvk: 'v1/Pod',
    objectNamespace: 'default',
    openingReason: 'CrashLoopBackOff',
  })

  function rowFor(name: string) {
    const cell = screen.getByText(name)
    const row = cell.closest('tr')
    if (!row) throw new Error(`no row for ${name}`)
    return row
  }

  it('renders the route as readable words, never the raw wire value', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([ROUTED_PR, ROUTED_GUIDANCE]))
    renderPage()
    await screen.findByText('api-gateway')

    expect(within(rowFor('api-gateway')).getByText('Pull request')).toBeTruthy()
    // The guidance route is the whole reason this cannot be derived from a
    // plan's actionType: there is no plan.
    expect(within(rowFor('legacy-batch')).getByText('Guidance only')).toBeTruthy()
    // The wire values themselves must never reach the screen.
    expect(screen.queryByText('pullRequest')).toBeNull()
    expect(screen.queryByText('guidance')).toBeNull()
  })

  it('renders an em dash for an incident nothing has routed yet, never a guessed route', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([UNROUTED]))
    renderPage()
    await screen.findByText('never-investigated')

    const row = rowFor('never-investigated')
    expect(within(row).getByText('—')).toBeTruthy()
    for (const label of ['Pull request', 'In place', 'Both routes', 'Guidance only']) {
      expect(within(row).queryByText(label)).toBeNull()
    }
    // "Absence is stated, not implied": the dash carries the sentence.
    expect(within(row).getByTitle(/Not routed yet/i)).toBeTruthy()
  })
})

// --- The two counts that were both "occurrences" (review item 8) ---
describe('IncidentsPage — detection count naming', () => {
  it('calls the per-incident detector count "Detections", and says what it counts', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([CRITICAL]))
    renderPage()
    await screen.findByText('payments-api')

    expect(screen.getByRole('button', { name: /Detections/i })).toBeTruthy()
    // The old header. It collided with the incident detail page's "Prior
    // occurrences on this object", which counts prior CLOSED INCIDENTS — a
    // different number over a different set.
    expect(screen.queryByRole('button', { name: /^Occurrences$/i })).toBeNull()
    expect(
      screen.getByTitle(/Reported 5 times by a detector since this incident opened/i),
    ).toBeTruthy()
  })
})

// --- The owning workload leads the row (B174) ---
//
// Driving a real OOMKill end to end on 2026-09-19 showed the defect this
// covers: the fix targeted the Deployment, the rollout replaced the Pod, and
// the resolved incident still named `checkout-oom-6d99b45595-fw7v8` — an
// object the operator could no longer inspect. Both incidents are still in
// the development database. No backend change was needed: `workload_key` was
// already populated and already on the wire as `workloadKey`.
describe('IncidentsPage — the owning workload leads the identity cell', () => {
  const OOM_POD = incident({
    id: 'inc_oom',
    fingerprint: 'fp_oom',
    state: 'Resolved',
    objectGvk: 'v1/Pod',
    objectNamespace: 'argus-e2e-rke2',
    objectName: 'checkout-oom-6d99b45595-fw7v8',
    workloadKey: 'apps/v1/Deployment|argus-e2e-rke2|checkout-oom',
    openingReason: 'OOMKilled',
  })

  // A real NULL-workload_key row from the same database — the majority case.
  const NO_OWNER = incident({
    id: 'inc_cert',
    fingerprint: 'fp_cert',
    objectGvk: 'cert-manager.io/v1/Certificate',
    objectNamespace: 'cattle-system',
    objectName: 'rancher-ingress',
    openingReason: 'CertificateExpiryImminent',
  })

  it('leads with the Deployment and keeps the Pod as supporting detail on the fault line', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([OOM_POD]))
    const { container } = renderPage()
    await screen.findByText('checkout-oom')

    const cell = container.querySelector('.incident-identity')!
    expect(cell.querySelector('.identity-block-name')?.textContent).toBe('checkout-oom')
    expect(cell.querySelector('.identity-block-kind')?.textContent).toBe('Deployment · argus-e2e-rke2')
    // The Pod is still on screen — it is real evidence — but below the
    // workload, not as the headline.
    expect(cell.querySelector('.identity-block-fault')?.textContent).toBe('OOMKilled · Pod checkout-oom-6d99b45595-fw7v8')
    // ...and it does not imply the Pod still exists.
    expect(cell.querySelector('.identity-block-fault')?.getAttribute('title')).toMatch(/may be gone/)
  })

  it('shows the object itself, plainly, when there is no owner to show', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([NO_OWNER]))
    const { container } = renderPage()
    await screen.findByText('rancher-ingress')

    const cell = container.querySelector('.incident-identity')!
    expect(cell.querySelector('.identity-block-name')?.textContent).toBe('rancher-ingress')
    expect(cell.querySelector('.identity-block-kind')?.textContent).toBe('Certificate · cattle-system')
    // No invented owner, and no dash standing where a name belongs: the fault
    // line is the bare reason, exactly as it was before B174.
    expect(cell.querySelector('.identity-block-fault')?.textContent).toBe('CertificateExpiryImminent')
    // The title now carries the line's OWN text, because the cell truncates to
    // one line per fact (B178) and hiding text without making it reachable is
    // hiding it. What must still be absent is the caveat: there is no observed
    // object here, so nothing may-no-longer-exist about it.
    expect(cell.querySelector('.identity-block-fault')?.getAttribute('title')).toBe('CertificateExpiryImminent')
    expect(cell.querySelector('.identity-block-fault')?.getAttribute('title')).not.toMatch(/no longer exist/i)
  })

  it('keeps every row checkbox distinguishable once siblings share one name', async () => {
    mockGetIncidents.mockResolvedValue(
      resolveIncidents([
        incident({ id: 'a', fingerprint: 'fp_a', objectGvk: 'v1/Pod', objectName: 'checkout-1', workloadKey: 'apps/v1/Deployment|default|checkout' }),
        incident({ id: 'b', fingerprint: 'fp_b', objectGvk: 'v1/Pod', objectName: 'checkout-2', workloadKey: 'apps/v1/Deployment|default|checkout' }),
      ]),
    )
    renderPage()
    await screen.findAllByText('checkout')

    expect(screen.getByRole('checkbox', { name: 'Select incident checkout (Pod checkout-1)' })).toBeTruthy()
    expect(screen.getByRole('checkbox', { name: 'Select incident checkout (Pod checkout-2)' })).toBeTruthy()
  })

  it('names the subject in the quick view, which previously showed only a fingerprint', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([OOM_POD]))
    renderPage()
    await screen.findByText('checkout-oom')

    fireEvent.click(screen.getByRole('button', { name: /Actions for incident/ }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Quick view' }))

    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText('Workload')).toBeTruthy()
    expect(within(dialog).getByText('Observed on')).toBeTruthy()
    expect(within(dialog).getByText('Pod checkout-oom-6d99b45595-fw7v8')).toBeTruthy()
  })

  it('calls the subject an Object, not a Workload, when nothing owns it', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([NO_OWNER]))
    renderPage()
    await screen.findByText('rancher-ingress')

    fireEvent.click(screen.getByRole('button', { name: /Actions for incident/ }))
    fireEvent.click(screen.getByRole('menuitem', { name: 'Quick view' }))

    const dialog = screen.getByRole('dialog')
    expect(within(dialog).getByText('Object')).toBeTruthy()
    expect(within(dialog).queryByText('Workload')).toBeNull()
    expect(within(dialog).queryByText('Observed on')).toBeNull()
  })
})

// --- Workload sibling collapse (review item 15) ---
//
// internal/replicagroup gives every open incident on one cluster sharing
// (workload_key, opening_reason) the same workload_group_id. On the
// development database that is 52 of 225 incidents in four groups of
// thirteen: thirteen pods of one Deployment, thirteen consecutive rows.
describe('IncidentsPage — workload sibling collapse', () => {
  const sibling = (n: number, over: Partial<Incident> = {}) =>
    incident({
      id: `inc_sib_${n}`,
      fingerprint: `fp_sib_${n}`,
      severity: 'high',
      state: 'Detected',
      occurrenceCount: 2,
      objectGvk: 'v1/Pod',
      objectNamespace: 'default',
      objectName: `checkout-${n}`,
      openingReason: 'CrashLoopBackOff',
      workloadGroupId: 'wgrp_1',
      workloadKey: 'apps/v1/Deployment|default|checkout',
      ...over,
    })

  const LONE = incident({
    id: 'inc_lone',
    fingerprint: 'fp_lone',
    objectGvk: 'apps/v1/Deployment',
    objectNamespace: 'payments',
    objectName: 'payments-api',
    openingReason: 'OOMKilled',
  })

  it('collapses siblings into one row naming the workload and the sibling count, and expands inline', async () => {
    const siblings = [sibling(1), sibling(2), sibling(3)]
    mockGetIncidents.mockResolvedValue(resolveIncidents([...siblings, LONE]))
    renderPage()
    await screen.findByText('payments-api')

    // The parent names the WORKLOAD, not one of its pods, and says how many
    // incidents it stands for.
    expect(screen.getByText('checkout')).toBeTruthy()
    expect(screen.getByText(/3 incidents/)).toBeTruthy()
    // Collapsed: no pod is on screen. Since B174 a member row leads with the
    // same workload name as its parent and carries its own Pod on the fault
    // line, so "is a member rendered" is a question about the Pod text, not
    // about a bare object name.
    expect(screen.queryByText(/Pod checkout-1/)).toBeNull()
    expect(screen.queryByText(/Pod checkout-3/)).toBeNull()
    // Two rows for four incidents.
    expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(3) // header + 2

    // The control's accessible name carries the count, not just the workload
    // name — a screen reader must be told the row stands for three.
    fireEvent.click(screen.getByRole('button', { name: /checkout.*3 incidents/i }))
    // Expanded, the members are told apart by the Pod each one was observed
    // on — the only thing that differs between them now that the workload
    // leads. If this ever stops being rendered, three rows become
    // indistinguishable.
    expect(screen.getByText(/CrashLoopBackOff · Pod checkout-1/)).toBeTruthy()
    expect(screen.getByText(/CrashLoopBackOff · Pod checkout-3/)).toBeTruthy()
    expect(within(screen.getByRole('table')).getAllByRole('row')).toHaveLength(6) // header + 2 + 3 members
  })

  it('keeps the header count on INCIDENTS and states the collapsing rather than letting rows pass for incidents', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([sibling(1), sibling(2), sibling(3), LONE]))
    const { container } = renderPage()
    await screen.findByText('payments-api')

    // The page's most prominent number is the true incident count — this is
    // the safety-critical half of the feature. 4 incidents, 2 rows.
    expect(container.querySelector('.list-live-status')?.textContent).toContain('4 incidents')
    const resultCount = container.querySelector('.list-result-count')
    expect(resultCount?.textContent).toContain('4 matching incidents')
    expect(resultCount?.textContent).toContain('3 collapsed into 1 workload row')
  })

  it('does not collapse a group with only one member on this page', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([sibling(1), LONE]))
    renderPage()
    await screen.findByText('payments-api')

    // The incident renders as itself, not as a parent row standing in for one
    // thing: its owning workload leads and its own Pod is on the fault line.
    expect(screen.getByText('checkout')).toBeTruthy()
    expect(screen.getByText(/CrashLoopBackOff · Pod checkout-1/)).toBeTruthy()
    expect(screen.queryByText(/1 incidents/)).toBeNull()
    // Its scope badge still says siblings exist somewhere.
    expect(screen.getAllByTitle(/Also occurring on other pods of the same workload/i).length).toBeGreaterThan(0)
  })

  it('never asserts one state or one route for members that disagree', async () => {
    mockGetIncidents.mockResolvedValue(
      resolveIncidents([
        sibling(1, { state: 'Detected', route: 'inPlace', severity: 'critical' }),
        sibling(2, { state: 'AwaitingApproval', severity: 'high' }),
      ]),
    )
    renderPage()
    await screen.findByText('checkout')

    const row = screen.getByText('checkout').closest('tr')!
    // Two states, so the row says so instead of picking one.
    expect(within(row).getByText('2 states')).toBeTruthy()
    expect(within(row).queryByText('Not investigated')).toBeNull()
    expect(within(row).queryByText('Waiting on a decision')).toBeNull()
    // One member routed, one not — that is not a shared route.
    expect(within(row).getByText('Mixed')).toBeTruthy()
    expect(within(row).queryByText('In place')).toBeNull()
    // Severity IS aggregated, to the worst, and says that it is the worst.
    expect(within(row).getByText('Critical')).toBeTruthy()
    expect(within(row).getByText(/\(worst\)/)).toBeTruthy()
  })

  it('sums the members detection counts rather than showing one member\'s', async () => {
    mockGetIncidents.mockResolvedValue(
      resolveIncidents([sibling(1, { occurrenceCount: 4 }), sibling(2, { occurrenceCount: 7 })]),
    )
    renderPage()
    await screen.findByText('checkout')

    const row = screen.getByText('checkout').closest('tr')!
    expect(within(row).getByText('11')).toBeTruthy()
    expect(within(row).getByTitle(/11 detector reports across these 2 incidents/i)).toBeTruthy()
  })

  it('selecting a collapsed row selects every eligible incident it stands for', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([sibling(1), sibling(2), sibling(3)]))
    const { container } = renderPage()
    await screen.findByText('checkout')

    fireEvent.click(screen.getByLabelText(/Select the 3 incidents on checkout/i))
    // BulkActionBar counts INCIDENTS — a row-shaped count here would say 1.
    expect(container.textContent).toContain('3 incidents selected')
  })
})

function Loc() {
  const l = useLocation()
  return <p data-testid="loc">{l.pathname + l.search}</p>
}

function renderAt(url: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[url]}>
        <KeyboardShortcutProvider mac={false}>
          <IncidentsPage />
          <Loc />
        </KeyboardShortcutProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

// Live QA 2026-10-11.
describe('IncidentsPage — live QA fixes', () => {
  it('offers Diagnosed and Expired as states, and honours ?state=Diagnosed instead of falling back to All', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([CRITICAL]))
    renderAt('/incidents?state=Diagnosed')
    await screen.findByText('payments-api')
    await waitFor(() => {
      const call = mockGetIncidents.mock.calls[mockGetIncidents.mock.calls.length - 1]
      expect(call[2]).toBe('Diagnosed')
    })
    const stateSelect = screen.getByLabelText(/Filter by state/i) as HTMLSelectElement
    expect(stateSelect.value).toBe('Diagnosed')
    expect(Array.from(stateSelect.options).map((o) => o.value)).toContain('Diagnosed')
    // Under All, every state the hub can hold except the unreachable
    // RecommendationReady, Expired included.
    fireEvent.click(statusTab(/^All/))
    await waitFor(() => {
      const values = Array.from((screen.getByLabelText(/Filter by state/i) as HTMLSelectElement).options).map((o) => o.value)
      expect(values).toContain('Expired')
      expect(values).not.toContain('RecommendationReady')
    })
  })

  it('on a phone, each row states severity and state in words beside the name, not only as the row colour', async () => {
    const original = window.matchMedia
    window.matchMedia = ((query: string) => ({
      matches: query.includes('max-width: 720px'),
      media: query,
      addEventListener: () => {},
      removeEventListener: () => {},
    })) as unknown as typeof window.matchMedia
    try {
      mockGetIncidents.mockResolvedValue(resolveIncidents([CRITICAL]))
      renderPage()
      const name = await screen.findByText('payments-api')
      const facts = name.closest('.identity-block')?.querySelector('.incident-narrow-facts') as HTMLElement
      expect(facts.textContent).toMatch(/Critical/)
      expect(facts.textContent).toMatch(/Not investigated/)
    } finally {
      window.matchMedia = original
    }
  })

  it('shows an em dash, not "0 incidents", before the first answer arrives', async () => {
    mockGetIncidents.mockReturnValue(new Promise(() => {}))
    renderPage()
    const status = document.querySelector('.list-live-status') as HTMLElement
    expect(status.textContent).toMatch(/— incidents/)
    expect(status.textContent).not.toMatch(/\b0 incidents/)
  })

  it('cancelling bulk dismiss keeps the selection; finishing drops only what was dismissed', async () => {
    mockGetIncidents.mockImplementation(fakeServerIncidents([CRITICAL, RESOLVED, AWAITING, RUNNING]))
    mockDismissIncident.mockImplementation((id: string) =>
      id === 'inc_1'
        ? Promise.resolve({ incidentId: id, verdict: 'dismissed', incidentState: 'Dismissed', message: 'Dismissed' })
        : Promise.reject(new ApiError('Conflict', 409, 'already closed')),
    )
    renderPage()
    await screen.findByText('payments-api')
    fireEvent.click(screen.getByLabelText('Select incident payments-api'))
    fireEvent.click(screen.getByLabelText('Select incident billing-cron'))
    expect(await screen.findByText('2 incidents selected')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: /^Dismiss…$/ }))
    fireEvent.click(await screen.findByRole('button', { name: 'Cancel' }))
    expect(screen.getByText('2 incidents selected')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: /^Dismiss…$/ }))
    fireEvent.change(await screen.findByLabelText(/Why are these being dismissed/), { target: { value: 'known noise' } })
    fireEvent.click(screen.getByRole('button', { name: 'Dismiss 2' }))
    fireEvent.click(await screen.findByRole('button', { name: 'Done' }))
    // inc_1 was dismissed and leaves the selection; the one that failed stays
    // selected for a retry.
    expect(await screen.findByText('1 incident selected')).toBeTruthy()
  })
})

describe('IncidentsPage — shareable URLs and keyboard navigation (CI-U5, CI-U6)', () => {
  it('restores every filter and the sort from the URL and sends the server ones as parameters', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([CRITICAL, REJECTED]))
    renderAt('/incidents?state=PlanRejected&status=requiresAction&severity=high&sort=severity&dir=asc&q=auth')
    await screen.findByText('auth-gateway')
    await waitFor(() => {
      const call = lastCall()
      expect(call[2]).toBe('PlanRejected')
      expect(call[5]).toBe('auth')
      expect(call[6]).toBe('severity')
      expect(call[7]).toBe('asc')
      expect(call[9]).toBe('high')
      expect(call[10]).toBe('requiresAction')
    })
    expect(statusTab(/^Needs action/).getAttribute('aria-pressed')).toBe('true')
    expect((screen.getByLabelText('Filter by severity') as HTMLSelectElement).value).toBe('high')
  })

  it('rewrites an old ?view= link to the status and severity it meant', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([CRITICAL, REJECTED]))
    renderAt('/incidents?view=high')
    await screen.findByText('auth-gateway')
    await waitFor(() => {
      const loc = screen.getByTestId('loc').textContent ?? ''
      expect(loc).not.toContain('view=')
      expect(loc).toContain('status=all')
      expect(loc).toContain('severity=high')
    })
    await waitFor(() => expect(lastCall()[9]).toBe('high'))
  })

  it('writes a filter change into the URL', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([CRITICAL, REJECTED]))
    renderAt('/incidents')
    await screen.findByText('auth-gateway')
    fireEvent.click(statusTab(/^Closed/))
    expect(screen.getByTestId('loc').textContent).toContain('status=closed')
    fireEvent.change(screen.getByLabelText('Filter by severity'), { target: { value: 'critical' } })
    expect(screen.getByTestId('loc').textContent).toContain('severity=critical')
  })

  it('moves a focus row with j/k and opens the incident on Enter', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([CRITICAL, REJECTED]))
    renderAt('/incidents')
    await screen.findByText('auth-gateway')
    fireEvent.keyDown(document.body, { key: 'j' })
    const first = document.activeElement as HTMLElement
    expect(first.tagName).toBe('TR')
    fireEvent.keyDown(document.body, { key: 'j' })
    const second = document.activeElement as HTMLElement
    expect(second).not.toBe(first)
    fireEvent.keyDown(document.body, { key: 'k' })
    expect(document.activeElement).toBe(first)
    fireEvent.keyDown(first, { key: 'Enter' })
    expect(screen.getByTestId('loc').textContent).toMatch(/^\/incidents\/inc_/)
  })
})

describe('IncidentsPage — cluster filter', () => {
  it('lists the clusters, writes the choice into the URL and sends it to the server', async () => {
    capabilities.add(CAP_CLUSTER_READ)
    mockGetIncidents.mockResolvedValue(resolveIncidents([CRITICAL, REJECTED]))
    renderAt('/incidents')
    await screen.findByText('auth-gateway')
    const select = screen.getByLabelText('Filter by cluster') as HTMLSelectElement
    await within(select).findByRole('option', { name: 'lab-dev' })
    fireEvent.change(select, { target: { value: 'cl_b' } })
    await waitFor(() => expect(screen.getByTestId('loc').textContent).toContain('clusterId=cl_b'))
    await waitFor(() => {
      const call = mockGetIncidents.mock.calls[mockGetIncidents.mock.calls.length - 1]
      expect(call[1]).toBe('cl_b')
    })
  })

  it('keeps an unlisted ?clusterId= visible as the selected value, not as All clusters', async () => {
    capabilities.add(CAP_CLUSTER_READ)
    mockGetIncidents.mockResolvedValue(resolveIncidents([CRITICAL]))
    renderAt('/incidents?clusterId=cl_gone')
    await screen.findByText('payments-api')
    expect((screen.getByLabelText('Filter by cluster') as HTMLSelectElement).value).toBe('cl_gone')
  })

  it('is disabled with the missing capability named, never hidden', async () => {
    mockGetIncidents.mockResolvedValue(resolveIncidents([CRITICAL]))
    renderAt('/incidents')
    await screen.findByText('payments-api')
    const select = screen.getByLabelText('Filter by cluster') as HTMLSelectElement
    expect(select.disabled).toBe(true)
    expect(select.title).toContain(CAP_CLUSTER_READ)
    expect(mockGetClusters).not.toHaveBeenCalled()
  })
})
