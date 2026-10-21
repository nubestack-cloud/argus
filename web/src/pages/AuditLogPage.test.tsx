import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { AuditEventFilters, AuditEventSummary, AuditEventsResponse } from '../api/types'
import { CAP_AUDIT_READ, CAP_CLUSTER_READ } from '../api/capabilities'

// BACKLOG P3. AuditLogPage is keyset-paged (no total, no offset — see
// utils/pagination.ts's own comment on why this list can't be page-numbered
// like the others), gated on a real 403 rather than a client-guessed
// capability check, and — after D7b/D7c/D7i — deliberately never claims a
// count or an empty/filtered state it hasn't earned. These tests drive the
// actual mocked round trip (page tokens, filter submission, the "more
// available" caveat) rather than re-deriving any of that logic directly.

const mockGetAuditEvents = vi.fn()
const mockGetAuditEvent = vi.fn()
const mockGetClusters = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    getAuditEvents: (...args: unknown[]) => mockGetAuditEvents(...args),
    getAuditEvent: (...args: unknown[]) => mockGetAuditEvent(...args),
    getClusters: (...args: unknown[]) => mockGetClusters(...args),
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ accessToken: 'test-token' }),
}))

// Defaults to holding cluster:read (the ordinary case — audit:read is
// super-admin-only and cluster:read is held far more broadly); the one test
// on the missing-capability path below removes it for the duration of that
// test only.
const capabilities = new Set<string>([CAP_CLUSTER_READ])
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (capability: string) => capabilities.has(capability),
}))

import { AuditLogPage } from './AuditLogPage'
import { ApiError } from '../api/client'

function event(over: Partial<AuditEventSummary>): AuditEventSummary {
  return {
    id: 'evt_default',
    occurredAt: '2026-08-25T09:00:00Z',
    actorId: 'usr_admin',
    actorEmail: 'admin@example.com',
    actorDisplayName: null,
    actorAuthMethod: 'password',
    sourceIp: '10.0.0.1',
    capability: 'cluster:accept',
    clusterId: 'cl_1',
    clusterDisplayName: 'prod-eu',
    outcome: 'success',
    action: 'Cluster accepted',
    detailsSummary: '',
    ...over,
  }
}

const ACCEPT_EVENT = event({
  id: 'evt_accept',
  action: 'Cluster accepted',
  actorEmail: 'admin@example.com',
  outcome: 'success',
})

const DENIED_EVENT = event({
  id: 'evt_denied',
  action: 'Login failed',
  actorEmail: null,
  actorDisplayName: null,
  actorId: null,
  actorAuthMethod: 'password',
  outcome: 'denied',
  capability: null,
  clusterId: null,
  clusterDisplayName: null,
})

function auditResponse(events: AuditEventSummary[], nextCursor?: string): AuditEventsResponse {
  return { auditEvents: events, nextCursor }
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <AuditLogPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  mockGetAuditEvents.mockReset()
  mockGetAuditEvent.mockReset()
  mockGetClusters.mockReset()
  mockGetClusters.mockResolvedValue({ clusters: [{ id: 'cl_1', displayName: 'prod-eu' }] })
  capabilities.clear()
  capabilities.add(CAP_CLUSTER_READ)
})

describe('AuditLogPage — capability gating on a real 403', () => {
  it('shows the missing-capability banner rather than a generic error on a 403', async () => {
    mockGetAuditEvents.mockRejectedValue(new ApiError('Forbidden', 403, ''))
    renderPage()
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/don't have access to view the audit log/i)
    expect(alert.textContent).toMatch(new RegExp(CAP_AUDIT_READ))
  })

  it('shows the hub\'s own error message for a non-403 failure, not the capability banner', async () => {
    mockGetAuditEvents.mockRejectedValue(new ApiError('Request failed', 500, 'the audit table is unreachable'))
    renderPage()
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/Request failed/)
    expect(alert.textContent).toMatch(/the audit table is unreachable/)
    expect(screen.queryByText(new RegExp(CAP_AUDIT_READ))).toBeNull()
  })
})

describe('AuditLogPage — honesty about what a keyset page actually holds (D7b/D7c)', () => {
  it('states the count on THIS page and says nothing about a total it never fetched', async () => {
    mockGetAuditEvents.mockResolvedValue(auditResponse([ACCEPT_EVENT, DENIED_EVENT]))
    renderPage()
    expect(await screen.findByText(/2 events on this page/i)).toBeTruthy()
    // Never a fabricated "of N" style total for a cursor-paged list.
    expect(screen.queryByText(/of \d+ events/i)).toBeNull()
  })

  it('appends "more available" only when the server actually reports a nextCursor', async () => {
    mockGetAuditEvents.mockResolvedValue(auditResponse([ACCEPT_EVENT], 'cursor_2'))
    renderPage()
    expect(await screen.findByText(/1 event on this page/i)).toBeTruthy()
    expect(screen.getByText(/more available/i)).toBeTruthy()
  })

  it('says nothing about more being available when this is genuinely the last page', async () => {
    mockGetAuditEvents.mockResolvedValue(auditResponse([ACCEPT_EVENT]))
    renderPage()
    await screen.findByText(/1 event on this page/i)
    expect(screen.queryByText(/more available/i)).toBeNull()
  })
})

describe('AuditLogPage — keyset pagination', () => {
  it('disables "Previous" on the first page and enables "Next" only when a nextCursor exists', async () => {
    mockGetAuditEvents.mockResolvedValue(auditResponse([ACCEPT_EVENT], 'cursor_2'))
    renderPage()
    await screen.findByText('admin@example.com')

    expect(screen.getByRole('button', { name: /Previous/i })).toHaveProperty('disabled', true)
    expect(screen.getByRole('button', { name: /Next/i })).toHaveProperty('disabled', false)
  })

  it('clicking Next requests the next cursor, and Previous walks back to page 1 by reusing its cursor (undefined), not a new one', async () => {
    // A stable implementation (rather than chained mockResolvedValueOnce
    // calls) because TanStack Query's default staleTime is 0 — returning to
    // an already-fetched page legitimately triggers a background revalidation
    // fetch, which is real cache behavior, not something these assertions
    // should have to pin an exact call count against.
    mockGetAuditEvents.mockImplementation((_token: string, filters?: AuditEventFilters) =>
      Promise.resolve(
        filters?.cursor === 'cursor_2' ? auditResponse([DENIED_EVENT]) : auditResponse([ACCEPT_EVENT], 'cursor_2'),
      ),
    )
    renderPage()
    await screen.findByText('admin@example.com')

    fireEvent.click(screen.getByRole('button', { name: /Next/i }))

    await waitFor(() =>
      expect(mockGetAuditEvents).toHaveBeenLastCalledWith('test-token', expect.objectContaining({ cursor: 'cursor_2' })),
    )
    expect(await screen.findByText('Page 2')).toBeTruthy()
    expect(screen.getByRole('button', { name: /Next/i })).toHaveProperty('disabled', true)

    fireEvent.click(screen.getByRole('button', { name: /Previous/i }))
    expect(await screen.findByText('Page 1')).toBeTruthy()
    await waitFor(() => expect(screen.getByText('admin@example.com')).toBeTruthy())
    // Page 1's cursor is always undefined (cursorHistory[0]) — never the
    // page-2 cursor it just came back from.
    expect(mockGetAuditEvents).toHaveBeenLastCalledWith('test-token', expect.objectContaining({ cursor: undefined }))
  })
})

describe('AuditLogPage — filters', () => {
  it('applying a filter commits it to the query and resets to page 1', async () => {
    mockGetAuditEvents.mockResolvedValue(auditResponse([ACCEPT_EVENT]))
    renderPage()
    await screen.findByText('admin@example.com')

    fireEvent.change(screen.getByLabelText(/Actor \(email or ID\)/i), { target: { value: 'admin@example.com' } })
    fireEvent.change(screen.getByLabelText(/^Outcome$/i), { target: { value: 'success' } })
    fireEvent.click(screen.getByRole('button', { name: /Apply filters/i }))

    await waitFor(() =>
      expect(mockGetAuditEvents).toHaveBeenLastCalledWith(
        'test-token',
        expect.objectContaining({ actor: 'admin@example.com', outcome: 'success' }),
      ),
    )
    expect(screen.getByText(/actor: admin@example.com/i)).toBeTruthy()
  })

  it('clearing filters removes the applied-filter chips and refetches with none', async () => {
    mockGetAuditEvents.mockResolvedValue(auditResponse([ACCEPT_EVENT]))
    renderPage()
    await screen.findByText('admin@example.com')

    fireEvent.change(screen.getByLabelText(/Actor \(email or ID\)/i), { target: { value: 'admin@example.com' } })
    fireEvent.click(screen.getByRole('button', { name: /Apply filters/i }))
    await waitFor(() => expect(screen.getByText(/actor: admin@example.com/i)).toBeTruthy())

    fireEvent.click(screen.getByRole('button', { name: /Clear filters/i }))
    await waitFor(() => expect(screen.queryByText(/actor: admin@example.com/i)).toBeNull())
    const lastCallFilters = mockGetAuditEvents.mock.calls.at(-1)?.[1] as AuditEventFilters
    expect(lastCallFilters.actor).toBeUndefined()
  })

  it('distinguishes "no events match these filters" from "nothing recorded yet"', async () => {
    mockGetAuditEvents.mockResolvedValueOnce(auditResponse([ACCEPT_EVENT]))
    renderPage()
    await screen.findByText('admin@example.com')

    mockGetAuditEvents.mockResolvedValueOnce(auditResponse([]))
    fireEvent.change(screen.getByLabelText(/Actor \(email or ID\)/i), { target: { value: 'nobody@example.com' } })
    fireEvent.click(screen.getByRole('button', { name: /Apply filters/i }))

    expect(await screen.findByText(/No audit events match these filters/i)).toBeTruthy()
    expect(screen.queryByText(/No audit events recorded yet/i)).toBeNull()
  })

  it('shows the true empty state when the log has nothing at all and no filters are applied', async () => {
    mockGetAuditEvents.mockResolvedValue(auditResponse([]))
    renderPage()
    expect(await screen.findByText(/No audit events recorded yet/i)).toBeTruthy()
  })
})

describe('AuditLogPage — cluster and resource filters', () => {
  it('applying cluster and resource filters sends both to the API and composes with an existing filter', async () => {
    mockGetAuditEvents.mockResolvedValue(auditResponse([ACCEPT_EVENT]))
    renderPage()
    await screen.findByText('admin@example.com')
    // Cluster options loaded -- scoped to the select itself, since
    // ACCEPT_EVENT's own Target column already renders "prod-eu" as text.
    await waitFor(() => expect(within(screen.getByLabelText(/^Cluster$/i)).getByText('prod-eu')).toBeTruthy())

    fireEvent.change(screen.getByLabelText(/^Outcome$/i), { target: { value: 'success' } })
    fireEvent.change(screen.getByLabelText(/^Cluster$/i), { target: { value: 'cl_1' } })
    fireEvent.change(screen.getByPlaceholderText('e.g. checkout-worker'), { target: { value: 'checkout-worker' } })
    fireEvent.click(screen.getByRole('button', { name: /Apply filters/i }))

    await waitFor(() =>
      expect(mockGetAuditEvents).toHaveBeenLastCalledWith(
        'test-token',
        expect.objectContaining({ outcome: 'success', cluster: 'cl_1', resource: 'checkout-worker' }),
      ),
    )
    // Composes with the existing outcome filter (all three chips present),
    // not silently replaced by the new ones.
    expect(screen.getByText(/outcome: success/i)).toBeTruthy()
    expect(screen.getByText(/cluster: cl_1/i)).toBeTruthy()
    expect(screen.getByText(/resource: checkout-worker/i)).toBeTruthy()
  })

  it('clearing filters resets cluster and resource along with the rest', async () => {
    mockGetAuditEvents.mockResolvedValue(auditResponse([ACCEPT_EVENT]))
    renderPage()
    await screen.findByText('admin@example.com')
    await waitFor(() => expect(within(screen.getByLabelText(/^Cluster$/i)).getByText('prod-eu')).toBeTruthy())

    fireEvent.change(screen.getByLabelText(/^Cluster$/i), { target: { value: 'cl_1' } })
    fireEvent.change(screen.getByPlaceholderText('e.g. checkout-worker'), { target: { value: 'checkout-worker' } })
    fireEvent.click(screen.getByRole('button', { name: /Apply filters/i }))
    await waitFor(() => expect(screen.getByText(/cluster: cl_1/i)).toBeTruthy())

    fireEvent.click(screen.getByRole('button', { name: /Clear filters/i }))
    await waitFor(() => expect(screen.queryByText(/cluster: cl_1/i)).toBeNull())
    const lastCallFilters = mockGetAuditEvents.mock.calls.at(-1)?.[1] as AuditEventFilters
    expect(lastCallFilters.cluster).toBeUndefined()
    expect(lastCallFilters.resource).toBeUndefined()
  })

  it('disables the cluster select, naming the missing capability, when the viewer lacks cluster:read', async () => {
    capabilities.delete(CAP_CLUSTER_READ)
    mockGetAuditEvents.mockResolvedValue(auditResponse([ACCEPT_EVENT]))
    renderPage()
    await screen.findByText('admin@example.com')

    const select = screen.getByLabelText(/^Cluster$/i)
    expect(select).toHaveProperty('disabled', true)
    expect(select).toHaveProperty('title', expect.stringContaining(CAP_CLUSTER_READ))
    // Disabled, never hidden -- and the query behind it never even fires.
    expect(mockGetClusters).not.toHaveBeenCalled()
  })
})

describe('AuditLogPage — actor identity distinguishes a failed login from a system action', () => {
  it('an unresolved actor on a denied event reads "Unauthenticated", not "system"', async () => {
    mockGetAuditEvents.mockResolvedValue(auditResponse([DENIED_EVENT]))
    renderPage()
    expect(await screen.findByText('Unauthenticated')).toBeTruthy()
  })

  it('an unresolved actor on a successful, system-raised event reads "system"', async () => {
    mockGetAuditEvents.mockResolvedValue(
      auditResponse([
        event({
          id: 'evt_system',
          actorEmail: null,
          actorDisplayName: null,
          actorId: null,
          actorAuthMethod: 'mtls_tunnel',
          outcome: 'success',
          action: 'Cluster heartbeat',
        }),
      ]),
    )
    renderPage()
    expect(await screen.findByText('system')).toBeTruthy()
  })
})

describe('AuditLogPage — D7k split the actor back into its own column', () => {
  it('renders Event, Actor, Outcome, When, Details as five columns, with the actor out of the identity block', async () => {
    mockGetAuditEvents.mockResolvedValue(auditResponse([ACCEPT_EVENT]))
    renderPage()
    await screen.findByText('admin@example.com')

    const table = screen.getByRole('table')
    const headers = within(table).getAllByRole('columnheader').map((h) => h.textContent)
    expect(headers).toEqual(['Event', 'Actor', 'Outcome', 'When', 'Details'])

    // The Event cell still pairs the action with the target (D7h's
    // identity-block, kept), but no longer also carries the actor — that's
    // the D7k complaint: three stacked lines in one cell.
    const dataRow = within(table).getAllByRole('row')[1]
    const cells = within(dataRow).getAllByRole('cell')
    expect(cells[0].textContent).toContain('Cluster accepted')
    expect(cells[0].textContent).toContain('prod-eu')
    expect(cells[0].textContent).not.toContain('admin@example.com')
    expect(cells[1].textContent).toBe('admin@example.com')
  })
})

describe('AuditLogPage — the detail modal', () => {
  it('opening Details fetches the full record and renders the hash-chain fields', async () => {
    mockGetAuditEvents.mockResolvedValue(auditResponse([ACCEPT_EVENT]))
    mockGetAuditEvent.mockResolvedValue({
      ...ACCEPT_EVENT,
      scope: { clusterId: 'cl_1' },
      details: { reason: 'manual accept' },
      prevHash: 'aaa111',
      hash: 'bbb222',
    })

    renderPage()
    await screen.findByText('admin@example.com')
    fireEvent.click(screen.getByRole('button', { name: /Details/i }))

    const dialog = await screen.findByRole('dialog')
    expect(mockGetAuditEvent).toHaveBeenCalledWith('evt_accept', 'test-token')
    expect(await screen.findByText('bbb222')).toBeTruthy()
    expect(within(dialog).getByText('aaa111')).toBeTruthy()
  })
})
