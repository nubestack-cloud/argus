import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ApprovalFilters } from '../api/client'
import type { ApprovalQueueItem, ApprovalsResponse, ApprovalDecisionResponse } from '../api/types'
import { CAP_REMEDIATION_APPROVE, CAP_REMEDIATION_REJECT } from '../api/capabilities'

// BACKLOG P3. ApprovalsPage itself is a thin queue (fetch, split pending vs.
// already-decided, 403-vs-generic error, the capability note) — but that
// queue renders ApprovalDecisionCard per row, and approving/rejecting is a
// real mutation with a real consequence (the incident actually moves off
// this queue). Rendering the page with real queue data — rather than
// stubbing ApprovalDecisionCard out — is what lets these tests cover the
// approve/reject flow the BACKLOG item actually asks for, not just the
// page's own loading/error/split logic.

const mockGetApprovals = vi.fn()
const mockApproveIncident = vi.fn()
const mockRejectIncident = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    getApprovals: (...args: unknown[]) => mockGetApprovals(...args),
    approveIncident: (...args: unknown[]) => mockApproveIncident(...args),
    rejectIncident: (...args: unknown[]) => mockRejectIncident(...args),
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ accessToken: 'test-token' }),
}))

const capabilities = new Set<string>([CAP_REMEDIATION_APPROVE, CAP_REMEDIATION_REJECT])
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (capability: string) => capabilities.has(capability),
}))

import { ApprovalsPage } from './ApprovalsPage'
import { ApiError } from '../api/client'

function scaleItem(over: Partial<ApprovalQueueItem> = {}): ApprovalQueueItem {
  return {
    incidentId: 'inc_scale',
    clusterId: 'cl_1',
    clusterDisplayName: 'prod-eu',
    fingerprint: 'fp_scale',
    severity: 'high',
    firstSeen: '2026-08-25T09:00:00Z',
    lastSeen: '2026-08-25T09:30:00Z',
    occurrenceCount: 4,
    plan: {
      id: 'plan_scale',
      actionType: 'ScaleDeployment',
      targetGvk: 'apps/v1/Deployment',
      targetNamespace: 'payments',
      targetName: 'payments-api',
      params: { replicas: 3 },
      reversible: true,
      riskLevel: 'low',
      effectiveRiskLevel: 'low',
      summary: 'Scale payments-api to 3 replicas',
      gateOutcome: 'NeedsApproval',
      gateReason: 'Confidence below the auto-approve threshold',
      createdAt: '2026-08-25T09:00:00Z',
    },
    confidence: 0.8,
    rootCauseStatement: 'OOMKilled',
    causalChain: [],
    ruledOut: [],
    alreadyApproved: false,
    ...over,
  }
}

function openPrItem(over: Partial<ApprovalQueueItem> = {}): ApprovalQueueItem {
  return scaleItem({
    incidentId: 'inc_pr',
    fingerprint: 'fp_pr',
    plan: {
      ...scaleItem().plan,
      id: 'plan_pr',
      actionType: 'OpenPR',
      summary: 'Open a pull request against the manifest',
    },
    alreadyApproved: true,
    ...over,
  })
}

// PROJECT.md B167: GET /api/v1/approvals now does the filtering, sorting and
// counting these tests exercise — ApprovalsPage only sends the request and
// renders what comes back. This fake stands in for that endpoint: given the
// FULL fixture set a test wants "on the server", it answers exactly the
// query shape ApprovalsPage sends (clusterId/actionType/riskLevel/
// alreadyApproved/sort), the same way internal/api/approvals_query_db_test.go
// proves the real handler does. Tests below assert against WHAT THE PAGE
// SHOWS, driven through this fake request/response boundary, rather than
// reaching into the page's state directly.
const RISK_ORDER: Record<string, number> = { high: 0, medium: 1, low: 2 }
const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }

function serverBackedApprovals(items: ApprovalQueueItem[]) {
  return async (_accessToken: string, filters: ApprovalFilters = {}): Promise<ApprovalsResponse> => {
    const alreadyApproved = filters.alreadyApproved ?? false
    const matchesClusterAction = (i: ApprovalQueueItem) =>
      (!filters.clusterId || i.clusterId === filters.clusterId) &&
      (!filters.actionType || i.plan.actionType === filters.actionType)
    const matchesAll = (i: ApprovalQueueItem) =>
      i.alreadyApproved === alreadyApproved &&
      matchesClusterAction(i) &&
      (!filters.riskLevel || i.plan.effectiveRiskLevel === filters.riskLevel)

    const rows = items.filter(matchesAll).sort((a, b) => {
      if (filters.sort === 'risk') return (RISK_ORDER[a.plan.effectiveRiskLevel] ?? 9) - (RISK_ORDER[b.plan.effectiveRiskLevel] ?? 9)
      if (filters.sort === 'severity') return (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9)
      return new Date(a.firstSeen).getTime() - new Date(b.firstSeen).getTime()
    })

    // pending/approved: scoped by clusterId/actionType/riskLevel, exactly
    // like the returned rows — internal/api/approvals.go's approvalCounts
    // doc comment. high/medium/low: scoped by clusterId/actionType but NOT
    // riskLevel — the pending set's own breakdown.
    const pendingScope = items.filter((i) => !i.alreadyApproved && matchesClusterAction(i) && (!filters.riskLevel || i.plan.effectiveRiskLevel === filters.riskLevel))
    const approvedScope = items.filter((i) => i.alreadyApproved && matchesClusterAction(i) && (!filters.riskLevel || i.plan.effectiveRiskLevel === filters.riskLevel))
    const breakdownScope = items.filter((i) => !i.alreadyApproved && matchesClusterAction(i))

    return {
      approvals: rows,
      counts: {
        pending: pendingScope.length,
        approved: approvedScope.length,
        high: breakdownScope.filter((i) => i.plan.effectiveRiskLevel === 'high').length,
        medium: breakdownScope.filter((i) => i.plan.effectiveRiskLevel === 'medium').length,
        low: breakdownScope.filter((i) => i.plan.effectiveRiskLevel === 'low').length,
      },
    }
  }
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <ApprovalsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  mockGetApprovals.mockReset()
  mockApproveIncident.mockReset()
  mockRejectIncident.mockReset()
  capabilities.clear()
  capabilities.add(CAP_REMEDIATION_APPROVE)
  capabilities.add(CAP_REMEDIATION_REJECT)
})

describe('ApprovalsPage — loading, empty, and error states', () => {
  it('shows the empty state once loaded with nothing pending', async () => {
    mockGetApprovals.mockImplementation(serverBackedApprovals([]))
    renderPage()
    expect(await screen.findByText(/Nothing is currently awaiting approval/i)).toBeTruthy()
  })

  it('shows the missing-capability banner on a 403, never the generic error line', async () => {
    mockGetApprovals.mockRejectedValue(new ApiError('Forbidden', 403, ''))
    renderPage()
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/don't have access to the approval queue/i)
    expect(alert.textContent).toMatch(new RegExp(CAP_REMEDIATION_APPROVE))
  })

  it('shows the hub\'s own error message for a non-403 failure', async () => {
    mockGetApprovals.mockRejectedValue(new ApiError('Request failed', 500, 'timed out reaching the database'))
    renderPage()
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/Request failed/)
    expect(alert.textContent).toMatch(/timed out reaching the database/)
  })
})

describe('ApprovalsPage — splits the queue into needs-decision vs. already-decided', () => {
  it('a pending plan renders under "Needs decision" with its target and risk', async () => {
    mockGetApprovals.mockImplementation(serverBackedApprovals([scaleItem()]))
    renderPage()
    expect(await screen.findByText('payments-api')).toBeTruthy()
    expect(screen.getByText(/1 need a decision/i)).toBeTruthy()
    expect(screen.getByText('low risk')).toBeTruthy()
  })

  it('an already-approved OpenPR plan is collapsed under the approved-count summary, not under "Needs decision"', async () => {
    mockGetApprovals.mockImplementation(serverBackedApprovals([openPrItem()]))
    renderPage()
    const summary = await screen.findByText(/1 approved, awaiting execution capability/i)
    expect(summary).toBeTruthy()
    expect(screen.getByText(/0 need a decision/i)).toBeTruthy()
    expect(screen.queryByText('Needs decision')).toBeNull()
  })

  it('without remediation:approve, shows the note that Approve/Reject render disabled', async () => {
    capabilities.delete(CAP_REMEDIATION_APPROVE)
    mockGetApprovals.mockImplementation(serverBackedApprovals([scaleItem()]))
    renderPage()
    expect(await screen.findByText(/without remediation:approve/i)).toBeTruthy()
  })
})

// BACKLOG D11 #6: "three orphaned-pod deletions is one judgement about a
// policy, not three about pods." podDeleteItem's three instances share a
// shape (same actionType, same target Kind, same gateReason) by construction
// — shapeKey/groupAndOrderApprovals never look at targetName, which is the
// only thing that differs between them.
function podDeleteItem(over: Partial<ApprovalQueueItem> = {}): ApprovalQueueItem {
  return scaleItem({
    incidentId: 'inc_pod',
    fingerprint: 'fp_pod',
    severity: 'low',
    firstSeen: '2026-08-25T09:00:00Z',
    plan: {
      id: 'plan_pod',
      actionType: 'DeleteResource' as unknown as ApprovalQueueItem['plan']['actionType'],
      targetGvk: 'v1/Pod',
      targetNamespace: 'kube-system',
      targetName: 'orphaned-pod',
      params: {},
      reversible: false,
      riskLevel: 'high',
      effectiveRiskLevel: 'high',
      summary: 'Delete kube-system/orphaned-pod',
      gateOutcome: 'NeedsApproval',
      gateReason:
        'DeleteResource is approval-only by construction: it is never auto-approved at any confidence, under any policy',
      createdAt: '2026-08-25T09:00:00Z',
    },
    ...over,
  })
}

describe('ApprovalsPage — BACKLOG D11 #6: orders by consequence and collapses identical shapes', () => {
  it('collapses three same-shape decisions into one card, and still counts three needing a decision', async () => {
    const podA = podDeleteItem({ incidentId: 'inc_pod_a', fingerprint: 'fp_pod_a', plan: { ...podDeleteItem().plan, id: 'plan_pod_a', targetName: 'orphaned-pod-a' } })
    const podB = podDeleteItem({ incidentId: 'inc_pod_b', fingerprint: 'fp_pod_b', plan: { ...podDeleteItem().plan, id: 'plan_pod_b', targetName: 'orphaned-pod-b' } })
    const podC = podDeleteItem({ incidentId: 'inc_pod_c', fingerprint: 'fp_pod_c', plan: { ...podDeleteItem().plan, id: 'plan_pod_c', targetName: 'orphaned-pod-c' } })
    mockGetApprovals.mockImplementation(serverBackedApprovals([podA, podB, podC]))

    renderPage()

    expect(await screen.findByText('3 matching decisions')).toBeTruthy()
    // The header count is still the real number of decisions, not the number
    // of cards — collapsing into one card must never understate the queue.
    expect(screen.getByText(/3 need a decision/i)).toBeTruthy()
    expect(screen.getByText('orphaned-pod-a')).toBeTruthy()
    expect(screen.getByText('orphaned-pod-b')).toBeTruthy()
    expect(screen.getByText('orphaned-pod-c')).toBeTruthy()
    expect(screen.getAllByRole('button', { name: /^Approve$/i }).length).toBe(3)
  })

  it('does not group decisions of a different shape, even when the target Kind matches', async () => {
    const podDelete = podDeleteItem()
    // Same target Kind (Pod), different action type — must not collapse with
    // podDeleteItem's DeleteResource shape.
    const podRestart = scaleItem({
      incidentId: 'inc_pod_restart',
      fingerprint: 'fp_pod_restart',
      plan: { ...scaleItem().plan, id: 'plan_pod_restart', actionType: 'RestartPod', targetGvk: 'v1/Pod', targetName: 'crashlooping-pod', summary: 'Restart crashlooping-pod' },
    })
    mockGetApprovals.mockImplementation(serverBackedApprovals([podDelete, podRestart]))

    renderPage()

    await screen.findByText('orphaned-pod')
    expect(screen.getByText('crashlooping-pod')).toBeTruthy()
    expect(screen.queryByText(/matching decisions/i)).toBeNull()
    expect(screen.getAllByRole('button', { name: /^Approve$/i }).length).toBe(2)
  })

  it('ranks a same-severity, higher-enforced-risk decision ahead of a lower-risk one', async () => {
    // Both critical severity (so severity alone cannot explain the order);
    // the DeleteResource plan's gate-enforced risk (high) must sort it
    // ahead of the ScaleDeployment plan's (low) — BACKLOG D11 #6's "order by
    // consequence", using the risk the gate actually enforced, not arrival.
    const lowRiskFirst = scaleItem({
      incidentId: 'inc_low_risk',
      fingerprint: 'fp_low_risk',
      severity: 'critical',
      firstSeen: '2026-08-25T01:00:00Z',
      plan: { ...scaleItem().plan, id: 'plan_low_risk', targetName: 'low-risk-target' },
    })
    const highRiskSecond = podDeleteItem({
      incidentId: 'inc_high_risk',
      fingerprint: 'fp_high_risk',
      severity: 'critical',
      firstSeen: '2026-08-25T02:00:00Z',
      plan: { ...podDeleteItem().plan, id: 'plan_high_risk', targetName: 'high-risk-target' },
    })
    // Arrival order deliberately puts the lower-risk one first.
    mockGetApprovals.mockImplementation(serverBackedApprovals([lowRiskFirst, highRiskSecond]))

    renderPage()
    await screen.findByText('low-risk-target')

    const names = screen.getAllByText(/-target$/).map((el) => el.textContent)
    expect(names).toEqual(['high-risk-target', 'low-risk-target'])
  })
})

describe('ApprovalsPage — approve/reject are real mutations with a real consequence', () => {
  it('approving calls the API for that exact incident, and shows the hub\'s own outcome message', async () => {
    mockGetApprovals.mockImplementation(serverBackedApprovals([scaleItem()]))
    const decision: ApprovalDecisionResponse = {
      incidentId: 'inc_scale',
      planId: 'plan_scale',
      verdict: 'approved',
      incidentState: 'Validating',
      message: 'Scaled payments-api to 3 replicas; the cluster accepted the change.',
    }
    mockApproveIncident.mockResolvedValue(decision)

    renderPage()
    await screen.findByText('payments-api')
    fireEvent.click(screen.getByRole('button', { name: /^Approve$/i }))

    await waitFor(() => expect(mockApproveIncident).toHaveBeenCalledWith('inc_scale', 'test-token', {}))
    expect(await screen.findByText(/Scaled payments-api to 3 replicas/i)).toBeTruthy()
  })

  it('the Approve button is disabled with the missing-capability reason when the actor lacks remediation:approve', async () => {
    capabilities.delete(CAP_REMEDIATION_APPROVE)
    mockGetApprovals.mockImplementation(serverBackedApprovals([scaleItem()]))
    renderPage()
    const approveButton = await screen.findByRole('button', { name: /^Approve$/i })
    expect(approveButton).toHaveProperty('disabled', true)
    expect(approveButton.title).toMatch(new RegExp(CAP_REMEDIATION_APPROVE))
  })

  it('rejecting requires a reason: the confirm button stays disabled until one is typed, then submits it', async () => {
    mockGetApprovals.mockImplementation(serverBackedApprovals([scaleItem()]))
    mockRejectIncident.mockResolvedValue({
      incidentId: 'inc_scale',
      planId: 'plan_scale',
      verdict: 'rejected',
      incidentState: 'Dismissed',
      message: 'Rejected.',
    } as ApprovalDecisionResponse)

    renderPage()
    await screen.findByText('payments-api')
    fireEvent.click(screen.getByRole('button', { name: /^Reject$/i }))

    const confirmButton = screen.getByRole('button', { name: /Confirm reject/i })
    expect(confirmButton).toHaveProperty('disabled', true)

    const reasonInput = screen.getByPlaceholderText(/Reason for rejecting/i)
    fireEvent.change(reasonInput, { target: { value: 'False positive — cluster was intentionally scaled down' } })
    expect(confirmButton).toHaveProperty('disabled', false)

    fireEvent.click(confirmButton)
    await waitFor(() =>
      expect(mockRejectIncident).toHaveBeenCalledWith(
        'inc_scale',
        'False positive — cluster was intentionally scaled down',
        'test-token',
      ),
    )
  })
})

// PROJECT.md D16 / B167 — the queue was a stack of cards with no page around
// it: no summary of what was waiting, no filters, no sort, no pagination.
// B167 moved the filtering/sorting/counting themselves onto the server
// (GET /api/v1/approvals now takes clusterId/actionType/riskLevel/sort as
// query params — see internal/api/approvals_query_db_test.go for the API-side
// proof); these tests drive the SAME page controls and assert what they
// render, now via serverBackedApprovals answering the request the page
// actually sends rather than a client-side re-derivation of one static
// response. The one distinction that is still easy to get wrong: "your
// filter hid everything" must never render as "the fleet is quiet".
describe('ApprovalsPage — page structure (PROJECT.md D16, B167)', () => {
  const queue = () => [
    scaleItem({ incidentId: 'inc_a', clusterId: 'cl_1', clusterDisplayName: 'prod-eu', firstSeen: '2026-08-01T09:00:00Z' }),
    scaleItem({
      incidentId: 'inc_b',
      clusterId: 'cl_2',
      clusterDisplayName: 'staging-eu',
      firstSeen: '2026-08-20T09:00:00Z',
      plan: { ...scaleItem().plan, id: 'plan_b', riskLevel: 'high', effectiveRiskLevel: 'high' },
    }),
  ]

  // The distinction that matters, and the one the first version of this page got
  // wrong: `riskLevel` is the model's DECLARED risk, `effectiveRiskLevel` is what
  // the deterministic floor actually enforced at gate time. They can disagree, and
  // RemediationPlan's own doc comment says the effective value is what any risk
  // badge must show. Counting, filtering or ranking by the declared value would
  // present a plan differently from the way ARGUS treated it — now enforced
  // server-side (approvalRiskRankExpr), exercised here through the fake's own use
  // of effectiveRiskLevel.
  it('counts, filters and ranks on the gate-enforced risk, not the declared one', async () => {
    const declaredLowEnforcedHigh = scaleItem({
      incidentId: 'inc_floor',
      plan: { ...scaleItem().plan, id: 'plan_floor', riskLevel: 'low', effectiveRiskLevel: 'high' },
    })
    mockGetApprovals.mockImplementation(serverBackedApprovals([declaredLowEnforcedHigh]))
    renderPage()

    // The summary must report the enforced value.
    expect(await screen.findByText(/1 high risk/)).toBeTruthy()
    expect(screen.queryByText(/1 low risk/)).toBeNull()

    // And filtering must agree with it: "high" keeps the row, "low" hides it.
    fireEvent.change(screen.getByLabelText(/Filter by risk/i), { target: { value: 'high' } })
    await waitFor(() => expect(screen.getByText(/Showing 1–1 of 1/)).toBeTruthy())
    fireEvent.change(screen.getByLabelText(/Filter by risk/i), { target: { value: 'low' } })
    expect(await screen.findByText(/1 are waiting in total/)).toBeTruthy()
  })

  it('says what is waiting, with risk as words rather than colour alone', async () => {
    mockGetApprovals.mockImplementation(serverBackedApprovals(queue()))
    renderPage()
    expect(await screen.findByText(/2 need a decision/)).toBeTruthy()
    expect(screen.getByText(/1 high risk/)).toBeTruthy()
    expect(screen.getByText(/1 low risk/)).toBeTruthy()
  })

  it('offers only filter options that actually match a row', async () => {
    mockGetApprovals.mockImplementation(serverBackedApprovals(queue()))
    renderPage()
    const cluster = await screen.findByLabelText(/Filter by cluster/i)
    const values = Array.from(cluster.querySelectorAll('option')).map((o) => o.textContent)
    // Derived from the rows present: a filter that could match nothing is
    // never offered.
    expect(values).toEqual(['All clusters', 'prod-eu', 'staging-eu'])
  })

  it('narrows the queue by cluster', async () => {
    mockGetApprovals.mockImplementation(serverBackedApprovals(queue()))
    renderPage()
    await screen.findByText(/2 need a decision/)
    fireEvent.change(screen.getByLabelText(/Filter by cluster/i), { target: { value: 'cl_2' } })
    // A filter keyed on the wrong field (display name instead of id) would
    // either match nothing or match both, since this endpoint's own
    // ?clusterId= is an id, never a display string — "exactly one row left"
    // is what proves it matched by id.
    await waitFor(() => expect(screen.getByText(/Showing 1–1 of 1/)).toBeTruthy())
  })

  it('distinguishes "filtered to nothing" from "nothing is waiting"', async () => {
    mockGetApprovals.mockImplementation(serverBackedApprovals(queue()))
    renderPage()
    await screen.findByText(/2 need a decision/)
    fireEvent.change(screen.getByLabelText(/Filter by risk/i), { target: { value: 'medium' } })
    // The honest message names the real total, and the page-level empty state
    // must NOT appear — telling an approver the fleet is quiet because their
    // own filter hid the work would be a lie about the cluster.
    expect(await screen.findByText(/2 are waiting in total/)).toBeTruthy()
    expect(screen.queryByText(/Nothing is currently awaiting approval/)).toBeNull()
  })

  it('pages the queue rather than scrolling without bound', async () => {
    mockGetApprovals.mockImplementation(serverBackedApprovals(queue()))
    renderPage()
    expect(await screen.findByText(/Showing 1–2 of 2/)).toBeTruthy()
  })

  it('leads with the longest-waiting decision, not the newest arrival', async () => {
    mockGetApprovals.mockImplementation(serverBackedApprovals(queue()))
    renderPage()
    const sort = await screen.findByLabelText(/^Sort$/i)
    expect((sort as HTMLSelectElement).value).toBe('waiting')
    // An item sitting unnoticed is this screen's real failure mode — one waited
    // 278 hours before the escalation sweep caught it.
    expect(Array.from(sort.querySelectorAll('option'))[0].textContent).toMatch(/Longest waiting/i)
  })

  it('a cluster/action/risk filter change is a fresh request, not a client-side re-derivation', async () => {
    mockGetApprovals.mockImplementation(serverBackedApprovals(queue()))
    renderPage()
    await screen.findByText(/2 need a decision/)
    const callsBefore = mockGetApprovals.mock.calls.length
    fireEvent.change(screen.getByLabelText(/Filter by action/i), { target: { value: 'ScaleDeployment' } })
    await waitFor(() => expect(mockGetApprovals.mock.calls.length).toBeGreaterThan(callsBefore))
    // And the request that follows actually carries the filter as a
    // parameter — the whole point of B167, not merely a re-render.
    const lastCall = mockGetApprovals.mock.calls[mockGetApprovals.mock.calls.length - 1]
    expect(lastCall[1]).toMatchObject({ actionType: 'ScaleDeployment' })
  })
})
