import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { Toleration, TolerationDetail } from '../api/types'
import { CAP_INCIDENT_SILENCE } from '../api/capabilities'

// BACKLOG P3. TolerationsPage had a real, fixed-today bug: the header's
// "active rules" count included rules whose expiresAt had already passed,
// even though the actual suppressor (internal/gateway/toleration.go) stops
// applying a rule at expires_at <= now() — so the count overstated what was
// actually in force. These tests exercise the fixed active/expired split
// directly through the rendered header, plus the incident:silence capability
// gate (including the D7h "Restricted" value slot, muted/italic rather than
// a plain string in the same position a real number occupies) and the
// row-expand detail fetch.

const mockListTolerations = vi.fn()
const mockGetToleration = vi.fn()
const mockRemoveToleration = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    listTolerations: (...args: unknown[]) => mockListTolerations(...args),
    getToleration: (...args: unknown[]) => mockGetToleration(...args),
    removeToleration: (...args: unknown[]) => mockRemoveToleration(...args),
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ accessToken: 'test-token' }),
}))

const capabilities = new Set<string>([CAP_INCIDENT_SILENCE])
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (capability: string) => capabilities.has(capability),
  useMissingCapabilities: (caps: string[]) => ({ resolved: true, missing: caps.filter((c) => !capabilities.has(c)) }),
}))

import { TolerationsPage } from './TolerationsPage'
import { ApiError } from '../api/client'

function toleration(over: Partial<Toleration>): Toleration {
  return {
    id: 'tol_default',
    clusterId: 'cl_1',
    clusterDisplayName: 'prod-eu',
    objectKey: 'apps/v1/Deployment|payments|payments-api',
    // Required since the API began distinguishing a rule ARGUS created for
    // itself (no human author) from one a person created.
    autoCreated: false,
    objectGvk: 'apps/v1/Deployment',
    objectNamespace: 'payments',
    objectName: 'payments-api',
    allReasons: false,
    reasons: ['OOMKilled'],
    note: 'Known memory spike during batch jobs, safe to ignore.',
    createdBy: 'usr_admin',
    createdByEmail: 'admin@example.com',
    createdAt: '2026-08-01T00:00:00Z',
    suppressedCount: 0,
    ...over,
  }
}

// Far in the past/future so the active/expired split is correct regardless
// of when this test actually runs — no need to mock the clock.
const NEVER_EXPIRES = toleration({ id: 'tol_never', expiresAt: undefined, suppressedCount: 3, lastSuppressed: '2026-08-24T00:00:00Z' })
const ACTIVE_FUTURE = toleration({ id: 'tol_future', expiresAt: '2030-01-01T00:00:00Z', suppressedCount: 1 })
const EXPIRED_PAST = toleration({ id: 'tol_expired', expiresAt: '2020-01-01T00:00:00Z', suppressedCount: 5, objectName: 'checkout-worker' })

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <TolerationsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  mockListTolerations.mockReset()
  mockGetToleration.mockReset()
  mockRemoveToleration.mockReset()
  capabilities.clear()
  capabilities.add(CAP_INCIDENT_SILENCE)
})

describe('TolerationsPage — the active/expired split (the fixed bug)', () => {
  it('an expired rule is excluded from the active count, even though it is still listed', async () => {
    mockListTolerations.mockResolvedValue([NEVER_EXPIRES, ACTIVE_FUTURE, EXPIRED_PAST])
    renderPage()

    // Real logic, not a guessed number: 2 active (never-expires + not-yet-
    // expired), 1 expired — NOT "3 active" the way it read before the fix.
    expect(await screen.findByText('2 active, 1 expired')).toBeTruthy()

    // The expired rule is still a row in the table (removal is a human
    // action, not automatic) — only the summary count changes.
    expect(screen.getByText(/checkout-worker/)).toBeTruthy()
  })

  it('a rule with no expiresAt counts as active, never as expired', async () => {
    mockListTolerations.mockResolvedValue([NEVER_EXPIRES])
    renderPage()
    expect(await screen.findByText('1 active, 0 expired')).toBeTruthy()
  })

  it('all rules expired reads "0 active", not a stale positive count', async () => {
    mockListTolerations.mockResolvedValue([EXPIRED_PAST])
    renderPage()
    expect(await screen.findByText('0 active, 1 expired')).toBeTruthy()
  })
})

describe('TolerationsPage — capability gating on incident:silence', () => {
  it('shows the Restricted value slot instead of a plain count when the actor lacks incident:silence', async () => {
    capabilities.delete(CAP_INCIDENT_SILENCE)
    renderPage()

    const restricted = await screen.findByText(new RegExp(`Requires ${CAP_INCIDENT_SILENCE}`))
    expect(restricted.className).toMatch(/value-restricted/)
    // The query never fires at all — deny-by-default, not "fetch then hide".
    expect(mockListTolerations).not.toHaveBeenCalled()
    expect(screen.getByText(`Missing capability: ${CAP_INCIDENT_SILENCE}`)).toBeTruthy()
  })

  it('renders the real table once the actor holds incident:silence', async () => {
    mockListTolerations.mockResolvedValue([NEVER_EXPIRES])
    renderPage()
    expect(await screen.findByText(/payments-api/)).toBeTruthy()
    expect(screen.queryByText(/Requires incident:silence/)).toBeNull()
  })
})

describe('TolerationsPage — row expand fetches and renders the origin/suppressed detail', () => {
  it('shows the two distinct "no origin" reasons rather than one vague message', async () => {
    mockListTolerations.mockResolvedValue([
      toleration({ id: 'tol_aged_out', incidentId: 'inc_gone' }),
    ])
    const detail: TolerationDetail = {
      toleration: toleration({ id: 'tol_aged_out', incidentId: 'inc_gone' }),
      origin: null,
      suppressed: [],
    }
    mockGetToleration.mockResolvedValue(detail)

    renderPage()
    await screen.findByText(/payments-api/)
    fireEvent.click(screen.getByRole('button', { name: /payments-api/i }))

    await waitFor(() => expect(mockGetToleration).toHaveBeenCalledWith('tol_aged_out', 'test-token'))
    expect(await screen.findByText(/is no longer stored/i)).toBeTruthy()
    expect(screen.getByText(/Nothing suppressed yet/i)).toBeTruthy()
  })

  it('a rule with no recorded incident id at all gets the other, different explanation', async () => {
    mockListTolerations.mockResolvedValue([toleration({ id: 'tol_no_incident', incidentId: undefined })])
    mockGetToleration.mockResolvedValue({
      toleration: toleration({ id: 'tol_no_incident', incidentId: undefined }),
      origin: null,
      suppressed: [],
    } as TolerationDetail)

    renderPage()
    await screen.findByText(/payments-api/)
    fireEvent.click(screen.getByRole('button', { name: /payments-api/i }))

    expect(await screen.findByText(/No originating incident is recorded for this rule/i)).toBeTruthy()
  })

  it('renders suppressed-finding groups with their counts when the rule has actually suppressed something', async () => {
    mockListTolerations.mockResolvedValue([toleration({ id: 'tol_active_rule' })])
    mockGetToleration.mockResolvedValue({
      toleration: toleration({ id: 'tol_active_rule' }),
      origin: null,
      suppressed: [
        {
          reason: 'OOMKilled',
          count: 12,
          firstSeen: '2026-08-01T00:00:00Z',
          lastSeen: '2026-08-20T00:00:00Z',
          sampleMessage: 'Container payments-api was OOMKilled',
          severity: 'medium',
        },
      ],
    } as TolerationDetail)

    renderPage()
    await screen.findByText(/payments-api/)
    fireEvent.click(screen.getByRole('button', { name: /payments-api/i }))

    expect(await screen.findByText('×12')).toBeTruthy()
    expect(screen.getByText('Container payments-api was OOMKilled')).toBeTruthy()
  })
})

describe('TolerationsPage — removing a rule is a real, confirmed mutation', () => {
  it('requires a Confirm click, then calls the API and the row disappears once it refetches', async () => {
    mockListTolerations
      .mockResolvedValueOnce([NEVER_EXPIRES])
      .mockResolvedValueOnce([])
    mockRemoveToleration.mockResolvedValue(undefined)

    renderPage()
    await screen.findByText(/payments-api/)

    fireEvent.click(screen.getByRole('button', { name: /Remove…/i }))
    const confirmButton = screen.getByRole('button', { name: /^Confirm$/i })
    fireEvent.click(confirmButton)

    await waitFor(() => expect(mockRemoveToleration).toHaveBeenCalledWith('tol_never', 'test-token'))
    await waitFor(() => expect(screen.queryByText(/payments-api/)).toBeNull())
  })

  it('clicking Cancel after Remove… does not call the API', async () => {
    mockListTolerations.mockResolvedValue([NEVER_EXPIRES])
    renderPage()
    await screen.findByText(/payments-api/)

    fireEvent.click(screen.getByRole('button', { name: /Remove…/i }))
    fireEvent.click(screen.getByRole('button', { name: /^Cancel$/i }))

    expect(mockRemoveToleration).not.toHaveBeenCalled()
    expect(screen.getByText(/payments-api/)).toBeTruthy()
  })
})

describe('TolerationsPage — loading, empty, and error states', () => {
  it('shows the empty state when there are no tolerations at all', async () => {
    mockListTolerations.mockResolvedValue([])
    renderPage()
    expect(await screen.findByText(/No active tolerations/i)).toBeTruthy()
  })

  it('renders the hub error message rather than swallowing the failure', async () => {
    mockListTolerations.mockRejectedValue(new ApiError('Request failed', 500, 'the tolerations table is unreachable'))
    renderPage()
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/Request failed/)
    expect(alert.textContent).toMatch(/the tolerations table is unreachable/)
  })
})
