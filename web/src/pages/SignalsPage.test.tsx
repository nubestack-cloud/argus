import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { FindingListItem, FindingsResponse } from '../api/client'
import { CAP_AUDIT_READ, CAP_CLUSTER_READ, CAP_INCIDENT_READ } from '../api/capabilities'

// PROJECT.md F31. SignalsPage's whole reason to exist is that it answers
// "what did ARGUS notice and choose not to raise" — so the things worth
// testing are not that a table renders, but the four claims a dishonest
// version of this screen would quietly get wrong:
//
//   1. the counts come from the server's exact aggregate, never from the page
//      (and are an em dash, never 0, when there is no answer);
//   2. the window the counts are scoped to is stated, from the RESOLVED
//      window on the response rather than from the filter inputs;
//   3. `notRecorded` — the findings that are in no table and appear at no
//      filter setting — is rendered rather than silently omitted;
//   4. `suppressed` names the toleration-vs-storm-protection split when the
//      row carries `suppressionReason` (migration 000124, PROJECT.md F31),
//      and says plainly that it is unrecorded — never a guess — on a row
//      that predates that migration and so has neither value.
//
// Plus the two structural rules every list here follows: filters are query
// parameters the server applies, and a capability-gated control is disabled
// with the capability named rather than removed.

const mockGetFindings = vi.fn()
const mockGetClusters = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    getFindings: (...args: unknown[]) => mockGetFindings(...args),
    getClusters: (...args: unknown[]) => mockGetClusters(...args),
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ accessToken: 'test-token' }),
}))

const capabilities = new Set<string>([CAP_INCIDENT_READ, CAP_CLUSTER_READ, CAP_AUDIT_READ])
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (capability: string) => capabilities.has(capability),
  useMissingCapabilities: (caps: string[]) => ({ resolved: true, missing: caps.filter((c) => !capabilities.has(c)) }),
}))

import { SignalsPage } from './SignalsPage'
import { ApiError } from '../api/client'

const PROMOTION_RULE: FindingsResponse['promotionRule'] = {
  summary:
    'Only an active fault, on better than explicitly unverified evidence, carrying observed degradation or unavailability, opens an incident.',
  criteria: [
    { dimension: 'class', accepted: ['fault'], statement: 'class must be fault' },
    {
      dimension: 'confidence',
      accepted: ['verified', 'inferred'],
      statement: 'confidence must be verified or inferred',
    },
    {
      dimension: 'impact',
      accepted: ['unavailable', 'degraded'],
      statement: 'impact must be unavailable or degraded',
    },
  ],
  notRecorded:
    'Findings dropped before storage — a disabled detector, a disabled rule, or a condition the polarity gate resolved as healthy — are never written to the findings table and cannot appear in any findings list.',
  source: 'internal/gateway/promotion.go',
}

function finding(over: Partial<FindingListItem>): FindingListItem {
  return {
    id: 'fnd_default',
    clusterId: 'cl_1',
    clusterDisplayName: 'prod-eu-1',
    detectorId: 'k8s-events',
    gvk: 'v1/Pod',
    namespace: 'payments',
    objectName: 'checkout-7d9',
    reason: 'CrashLoopBackOff',
    message: 'back-off restarting failed container',
    severity: 'high',
    occurrenceCount: 4,
    occurredAt: '2026-09-23T09:00:00Z',
    fingerprint: 'fp-abc',
    class: 'fault',
    confidence: 'verified',
    impact: 'unavailable',
    disposition: 'correlated',
    incidentId: 'inc_1',
    promotion: { promotable: true, class: 'fault', confidence: 'verified', impact: 'unavailable' },
    ...over,
  }
}

const RAISED = finding({ id: 'fnd_raised' })

const RETAINED = finding({
  id: 'fnd_retained',
  objectName: 'ingress-nginx-controller',
  reason: 'CertificateExpiringSoon',
  severity: 'medium',
  class: 'risk',
  confidence: 'inferred',
  impact: 'potential',
  disposition: 'retained_unpromoted',
  incidentId: undefined,
  promotion: {
    promotable: false,
    class: 'risk',
    confidence: 'inferred',
    impact: 'potential',
    unmet: ['class', 'impact'],
  },
})

const SUPPRESSED = finding({
  id: 'fnd_suppressed',
  objectName: 'billing-worker',
  reason: 'OOMKilled',
  severity: 'critical',
  disposition: 'suppressed',
  incidentId: undefined,
  promotion: { promotable: true, class: 'fault', confidence: 'verified', impact: 'unavailable' },
})

// A suppressed row written after migration 000124 — carries the reason
// directly, unlike SUPPRESSED above which models a pre-migration row.
const SUPPRESSED_WITH_REASON = finding({
  id: 'fnd_suppressed_toleration',
  objectName: 'reporting-worker',
  reason: 'CrashLoopBackOff',
  severity: 'high',
  disposition: 'suppressed',
  incidentId: undefined,
  suppressionReason: 'toleration',
  promotion: { promotable: true, class: 'fault', confidence: 'verified', impact: 'unavailable' },
})

function findingsResponse(over: Partial<FindingsResponse> = {}): FindingsResponse {
  return {
    findings: [RAISED, RETAINED, SUPPRESSED],
    counts: { all: 1284, correlated: 402, retainedUnpromoted: 806, suppressed: 76 },
    window: { since: '2026-09-16T09:00:00Z' },
    promotionRule: PROMOTION_RULE,
    ...over,
  }
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <SignalsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

function lastFindingFilters() {
  return mockGetFindings.mock.calls[mockGetFindings.mock.calls.length - 1][1]
}

beforeEach(() => {
  vi.clearAllMocks()
  capabilities.clear()
  capabilities.add(CAP_INCIDENT_READ)
  capabilities.add(CAP_CLUSTER_READ)
  capabilities.add(CAP_AUDIT_READ)
  mockGetClusters.mockResolvedValue({
    clusters: [{ id: 'cl_1', displayName: 'prod-eu-1' }, { id: 'cl_2', displayName: 'staging' }],
  })
  mockGetFindings.mockResolvedValue(findingsResponse())
})

describe('SignalsPage — the promotion boundary', () => {
  // The enforcing source file is provenance for maintainers, not operator
  // text (live QA 2026-10-11: "Enforced in internal/gateway/promotion.go").
  it('renders the rule and every criterion, and never the hub source path', async () => {
    renderPage()
    const boundary = await screen.findByRole('region', { name: /promotion boundary/i })
    expect(within(boundary).getByText(/only an active fault/i)).toBeTruthy()
    expect(within(boundary).getByText('class must be fault')).toBeTruthy()
    expect(within(boundary).getByText('confidence must be verified or inferred')).toBeTruthy()
    expect(within(boundary).getByText('impact must be unavailable or degraded')).toBeTruthy()
    expect(within(boundary).queryByText(/internal\/gateway\/promotion\.go/)).toBeNull()
  })

  // The honesty clause. Three drop dispositions return before any row is
  // inserted, so those findings are in no table and appear at no filter
  // setting — a screen that answers "what did you see and not tell me" while
  // omitting them overstates its own coverage.
  it('renders notRecorded, labelled, at the same weight as the criteria', async () => {
    renderPage()
    const boundary = await screen.findByRole('region', { name: /promotion boundary/i })
    expect(within(boundary).getByText('Not recorded at all')).toBeTruthy()
    expect(within(boundary).getByText(/cannot appear in any findings list/i)).toBeTruthy()
    // Same primitive as the three criteria, not a footnote.
    expect(within(boundary).getByText('Not recorded at all').className).toContain('verification-chip')
  })
})

describe('SignalsPage — counts and the window they are scoped to', () => {
  it('shows the server aggregate on each tab, not the length of the page', async () => {
    renderPage()
    // Three rows arrived; the tabs must still read the whole-scope figures.
    expect(await screen.findByRole('button', { name: /^All\s*1284$/ })).toBeTruthy()
    expect(screen.getByRole('button', { name: /^Raised\s*402$/ })).toBeTruthy()
    expect(screen.getByRole('button', { name: /^Recorded, not raised\s*806$/ })).toBeTruthy()
    expect(screen.getByRole('button', { name: /^Suppressed\s*76$/ })).toBeTruthy()
  })

  it('never renders a fabricated zero for a count it does not have', async () => {
    mockGetFindings.mockRejectedValue(new ApiError('Could not list findings', 500, ''))
    renderPage()
    await screen.findByRole('alert')
    const all = screen.getByRole('button', { name: /^All/ })
    expect(within(all).getByText('—')).toBeTruthy()
    expect(within(all).queryByText('0')).toBeNull()
  })

  // ?since= DEFAULTS rather than meaning "everything", so the counts above
  // are a week's worth and saying nothing would let them read as all time.
  // The sentence comes from the response's resolved window, which on a
  // default load is the only place that fact exists at all.
  it('states the resolved window from the response, not from the empty filter inputs', async () => {
    renderPage()
    expect(await screen.findByText(/recorded since/i)).toBeTruthy()
    expect(lastFindingFilters().since).toBeUndefined()
  })
})

describe('SignalsPage — dispositions', () => {
  it('labels each disposition readably and keeps the wire word reachable', async () => {
    renderPage()
    const raised = within(await screen.findByRole('row', { name: /checkout-7d9/ }))
    expect(raised.getByText('Raised').getAttribute('title')).toContain('correlated')
    const retained = within(screen.getByRole('row', { name: /ingress-nginx-controller/ }))
    expect(retained.getByText('Recorded, not raised').getAttribute('title')).toContain('retained_unpromoted')
  })

  it('names the criteria a retained finding missed, from promotion.unmet', async () => {
    renderPage()
    const retained = within(await screen.findByRole('row', { name: /ingress-nginx-controller/ }))
    expect(retained.getByText('Missed on class and impact')).toBeTruthy()
  })

  it('links a raised finding to the incident it became', async () => {
    renderPage()
    const raised = within(await screen.findByRole('row', { name: /checkout-7d9/ }))
    expect(raised.getByRole('link', { name: /open the incident/i }).getAttribute('href')).toBe('/incidents/inc_1')
  })

  // A suppressed row cleared the boundary and still has no incident, which
  // exactly two things cause — a toleration, or storm protection. A row from
  // before migration 000124 carries neither value, so it must not imply it
  // can tell them apart, and must point at where the answer actually is.
  it('does not guess why a pre-migration suppressed finding was suppressed', async () => {
    renderPage()
    const suppressed = within(await screen.findByRole('row', { name: /billing-worker/ }))
    expect(suppressed.getByText(/cause not recorded for this row/i)).toBeTruthy()
    expect(suppressed.queryByText(/toleration/i)).toBeNull()
    expect(suppressed.queryByText(/storm/i)).toBeNull()
    expect(suppressed.getByRole('link', { name: /look in the audit log/i }).getAttribute('href')).toBe(
      '/audit-log?resource=billing-worker',
    )
  })

  // PROJECT.md F31: a row written after migration 000124 carries the reason
  // directly and must show it rather than falling back to the "not
  // recorded" copy or offering the audit-log workaround it no longer needs.
  it('names the suppression reason when the row carries one', async () => {
    mockGetFindings.mockResolvedValue(
      findingsResponse({ findings: [RAISED, RETAINED, SUPPRESSED, SUPPRESSED_WITH_REASON] }),
    )
    renderPage()
    // RAISED and this row share detector + reason, so they collapse into one
    // look-alike group (CI-U4); expanding it shows each member.
    fireEvent.click(await screen.findByRole('button', { name: /CrashLoopBackOff/, expanded: false }))
    const suppressed = within(await screen.findByRole('row', { name: /reporting-worker/ }))
    expect(suppressed.getByText(/suppressed by a toleration/i)).toBeTruthy()
    expect(suppressed.queryByText(/cause not recorded/i)).toBeNull()
    expect(suppressed.queryByRole('link', { name: /look in the audit log/i })).toBeNull()
  })

  it('shows the stored tuple as well as the judged one when the evidence was corrected', async () => {
    mockGetFindings.mockResolvedValue(
      findingsResponse({
        findings: [
          finding({
            id: 'fnd_legacy',
            objectName: 'legacy-generic',
            disposition: 'retained_unpromoted',
            incidentId: undefined,
            class: 'fault',
            confidence: 'verified',
            impact: 'degraded',
            promotion: {
              promotable: false,
              class: 'anomaly',
              confidence: 'unverified',
              impact: 'none',
              evidenceCorrected: true,
              unmet: ['class', 'confidence', 'impact'],
            },
          }),
        ],
      }),
    )
    renderPage()
    const row = within(await screen.findByRole('row', { name: /legacy-generic/ }))
    expect(row.getByText('anomaly · unverified · none')).toBeTruthy()
    expect(row.getByText(/stored as fault · verified · degraded \(corrected\)/i)).toBeTruthy()
  })
})

// Live QA 2026-10-11: "0 findings · Updating…" on first load and on every
// filter change — a zero taken from the empty array the page falls back to
// while it waits, and the table emptied while the narrowed answer loaded.
describe('SignalsPage — no fabricated zero while loading', () => {
  it('shows an em dash, not 0, before the first answer arrives', async () => {
    mockGetFindings.mockReturnValue(new Promise(() => {}))
    renderPage()
    const status = document.querySelector('.list-live-status') as HTMLElement
    expect(status.textContent).toMatch(/— findings/)
    expect(status.textContent).not.toMatch(/\b0 findings/)
  })

  it('states the counting window as relative time with the exact instant on hover, like every other time', async () => {
    renderPage()
    await screen.findByText(/recorded since/i)
    const time = document.querySelector('.signals-window time') as HTMLTimeElement
    expect(time.getAttribute('datetime')).toBe('2026-09-16T09:00:00Z')
    expect(time.textContent).toMatch(/ago$/)
    expect(time.title).not.toBe('')
  })

  it('keeps the previous rows and count on screen while a filter change refetches', async () => {
    renderPage()
    await screen.findByRole('button', { name: /^Suppressed\s*76$/ })
    mockGetFindings.mockReturnValue(new Promise(() => {}))
    fireEvent.click(screen.getByRole('button', { name: /^Suppressed\s*76$/ }))
    await waitFor(() => expect(lastFindingFilters().disposition).toBe('suppressed'))
    const status = document.querySelector('.list-live-status') as HTMLElement
    // The header holds the exact window total from the last response, not the
    // rows on screen, and keeps it while the narrowed answer loads.
    expect(status.textContent).toMatch(/1284 findings/)
    expect(status.textContent).toMatch(/Updating/)
    expect(screen.getAllByText('checkout-7d9').length).toBeGreaterThan(0)
  })
})

describe('SignalsPage — filters are the server’s, not the page’s', () => {
  it('sends the disposition as a query parameter when a tab is chosen', async () => {
    renderPage()
    await screen.findByRole('button', { name: /^Suppressed\s*76$/ })
    fireEvent.click(screen.getByRole('button', { name: /^Suppressed\s*76$/ }))
    await waitFor(() => expect(lastFindingFilters().disposition).toBe('suppressed'))
  })

  it('sends the evidence filters to the server as they change, rather than narrowing the fetched page', async () => {
    renderPage()
    await screen.findByLabelText('Class')
    fireEvent.change(screen.getByLabelText('Class'), { target: { value: 'risk' } })
    fireEvent.change(screen.getByLabelText('Confidence'), { target: { value: 'unverified' } })
    fireEvent.change(screen.getByLabelText('Impact'), { target: { value: 'none' } })
    // No Apply button: the selects apply on change, the typed reason after a
    // short pause.
    fireEvent.change(screen.getByPlaceholderText('Reason, e.g. CrashLoopBackOff'), { target: { value: 'OOMKilled' } })
    await waitFor(() => {
      const filters = lastFindingFilters()
      expect(filters.class).toBe('risk')
      expect(filters.confidence).toBe('unverified')
      expect(filters.impact).toBe('none')
      expect(filters.reason).toBe('OOMKilled')
    })
  })

  it('shows each applied filter as a readable chip that removes it', async () => {
    renderAt('/signals?reason=OOMKilled')
    const chip = (await screen.findByText(/Reason: OOMKilled/)).closest('.list-active-filter') as HTMLElement
    expect(chip).toBeTruthy()
    fireEvent.click(within(chip).getByRole('button', { name: /Remove the reason filter/i }))
    await waitFor(() => expect(lastFindingFilters().reason).toBeUndefined())
    expect(screen.queryByText(/Reason: OOMKilled/)).toBeNull()
  })

  it('turns a time-range preset into a since the server applies, and the default into none', async () => {
    renderPage()
    await screen.findByRole('button', { name: /^All\s*1284$/ })
    expect(lastFindingFilters().since).toBeUndefined()
    fireEvent.change(screen.getByLabelText('Time range'), { target: { value: '24h' } })
    await waitFor(() => expect(lastFindingFilters().since).toBeDefined())
    const ageHours = (Date.now() - new Date(lastFindingFilters().since!).getTime()) / 3600_000
    expect(ageHours).toBeGreaterThan(23.9)
    expect(ageHours).toBeLessThan(24.1)
    fireEvent.change(screen.getByLabelText('Time range'), { target: { value: '' } })
    await waitFor(() => expect(lastFindingFilters().since).toBeUndefined())
  })

  it('pages with the server cursor and steps back without a second kind of request', async () => {
    mockGetFindings.mockResolvedValue(findingsResponse({ nextCursor: 'cur-2' }))
    renderPage()
    // Wait for the first page to actually land: Next is disabled until the
    // server has handed back a cursor, and fireEvent on a disabled button is
    // a no-op that would make this test pass for the wrong reason.
    await screen.findByRole('row', { name: /checkout-7d9/ })
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(lastFindingFilters().cursor).toBe('cur-2'))
    expect(screen.getByText('Page 2')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Previous' }))
    await waitFor(() => expect(lastFindingFilters().cursor).toBeUndefined())
  })
})

describe('SignalsPage — capability-gated controls are disabled, never hidden', () => {
  it('disables the cluster filter and names cluster:read', async () => {
    capabilities.delete(CAP_CLUSTER_READ)
    renderPage()
    const select = await screen.findByLabelText('Cluster')
    expect(select).toHaveProperty('disabled', true)
    expect(select.getAttribute('title')).toContain(CAP_CLUSTER_READ)
  })

  it('keeps the audit-log pointer in the DOM, disabled, when audit:read is missing', async () => {
    capabilities.delete(CAP_AUDIT_READ)
    renderPage()
    const suppressed = within(await screen.findByRole('row', { name: /billing-worker/ }))
    const control = suppressed.getByRole('button', { name: /look in the audit log/i })
    expect(control).toHaveProperty('disabled', true)
    expect(control.getAttribute('title')).toContain(CAP_AUDIT_READ)
  })
})

describe('SignalsPage — the four states', () => {
  it('distinguishes "no match for these filters" from "nothing in this window"', async () => {
    mockGetFindings.mockResolvedValue(findingsResponse({ findings: [] }))
    const { unmount } = renderPage()
    expect(await screen.findByText(/nothing has been recorded in this window/i)).toBeTruthy()
    unmount()

    renderPage()
    await screen.findByRole('button', { name: /^Suppressed\s*76$/ })
    fireEvent.click(screen.getByRole('button', { name: /^Suppressed\s*76$/ }))
    expect(await screen.findByText(/no findings match these filters/i)).toBeTruthy()
  })

  it('renders the RFC 9457 title and detail on a failure', async () => {
    mockGetFindings.mockRejectedValue(new ApiError('Invalid filter', 400, 'class must be one of: fault, risk, anomaly'))
    renderPage()
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/Invalid filter/)
    expect(alert.textContent).toMatch(/class must be one of: fault, risk, anomaly/)
  })

  it('renders a scope denial naming the capability the hub actually requires', async () => {
    mockGetFindings.mockRejectedValue(new ApiError('Forbidden', 403, 'missing capability'))
    renderPage()
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(new RegExp(CAP_INCIDENT_READ))
  })
})

function Loc() {
  return <p data-testid="loc">{useLocation().search}</p>
}

function renderAt(url: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[url]}>
        <SignalsPage />
        <Loc />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('SignalsPage — look-alike rows, the inspector and the URL (CI-U4/U5/U7)', () => {
  const posture = (id: string, name: string) =>
    finding({
      id,
      objectName: name,
      gvk: 'apps/v1/Deployment',
      detectorId: 'k8s-posture',
      reason: 'PosturePrivileged',
      ruleId: 'privileged',
      message: 'Privileged container (Security): container app runs privileged',
      disposition: 'retained_unpromoted',
      incidentId: undefined,
    })

  it('collapses look-alike posture signals under the check title, counting a partial page as a lower bound', async () => {
    mockGetFindings.mockResolvedValue(findingsResponse({ findings: [posture('p1', 'a'), posture('p2', 'b')], nextCursor: 'c2' }))
    renderAt('/signals')
    const toggle = await screen.findByRole('button', { name: /Privileged container/, expanded: false })
    expect(screen.getByLabelText('at least 2')).toBeTruthy()
    expect(screen.getByText(/on this page/)).toBeTruthy()
    fireEvent.click(toggle)
    expect(screen.getByTestId('loc').textContent).toContain('group=k8s-posture%7CPosturePrivileged%7Cprivileged')
    expect(screen.getAllByText('Privileged container').length).toBeGreaterThan(1)
  })

  it('narrows to the group reason on the server for an exact count', async () => {
    mockGetFindings.mockResolvedValue(findingsResponse({ findings: [posture('p1', 'a'), posture('p2', 'b')], nextCursor: 'c2' }))
    renderAt('/signals')
    fireEvent.click(await screen.findByRole('button', { name: /Only this reason/ }))
    await waitFor(() => expect(lastFindingFilters().reason).toBe('PosturePrivileged'))
  })

  it('opens a row in the inspector without leaving the list, keeping the filters', async () => {
    renderAt('/signals?class=fault')
    fireEvent.click(await screen.findByRole('button', { name: 'billing-worker' }))
    const search = screen.getByTestId('loc').textContent!
    expect(search).toContain('class=fault')
    expect(search).toContain('panel=obj%3Acl_1%3A%2FPod%3Apayments%2Fbilling-worker')
  })

  it('keeps the page in the URL and walks back with Previous', async () => {
    mockGetFindings.mockResolvedValue(findingsResponse({ nextCursor: 'cur-2' }))
    renderAt('/signals')
    await screen.findByRole('button', { name: 'billing-worker' })
    fireEvent.click(screen.getByRole('button', { name: 'Next' }))
    await waitFor(() => expect(screen.getByTestId('loc').textContent).toBe('?cursor=cur-2'))
    expect(screen.getByText('Page 2')).toBeTruthy()
    await waitFor(() => expect(lastFindingFilters().cursor).toBe('cur-2'))
    fireEvent.click(screen.getByRole('button', { name: 'Previous' }))
    await waitFor(() => expect(screen.getByTestId('loc').textContent).toBe(''))
  })

  it('opens a link straight onto page 2', async () => {
    renderAt('/signals?cursor=cur-2')
    await screen.findByText('Page 2')
    expect(lastFindingFilters().cursor).toBe('cur-2')
  })
})
