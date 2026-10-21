import { describe, expect, it, vi, beforeEach } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type {
  AutomationCandidateSummary,
  InsightsResponse,
  IssueClassSummary,
  NewNoisyNamespaceSummary,
  RejectedRecommendationSummary,
  RemediationQualityResponse,
  SpendToday,
  UnstableClusterSummary,
} from '../api/types'
import { CAP_REMEDIATION_APPROVE, CAP_SPEND_READ } from '../api/capabilities'

// BACKLOG.md L4 — "unstable clusters" (GET /api/v1/insights) and
// "recommendations frequently rejected"/"automation candidates" (GET
// /api/v1/insights/remediation-quality, gated on a DIFFERENT, narrower
// capability than the rest of the page). These tests cover: the new table
// renders real counts (not a fabricated figure), the remediation-quality
// pair is entirely OMITTED without remediation:approve (never disabled —
// there's no control here, only data a capability-less viewer must not
// see), and the roadmap section's copy stays in sync with however many
// notBuilt entries the backend actually sends.

const mockGetClusters = vi.fn()
const mockGetInsights = vi.fn()
const mockGetInsightsRemediationQuality = vi.fn()
const mockGetSpendToday = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    getClusters: (...args: unknown[]) => mockGetClusters(...args),
    getInsights: (...args: unknown[]) => mockGetInsights(...args),
    getInsightsRemediationQuality: (...args: unknown[]) => mockGetInsightsRemediationQuality(...args),
    getSpendToday: (...args: unknown[]) => mockGetSpendToday(...args),
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ accessToken: 'test-token' }),
}))

const capabilities = new Set<string>()
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (capability: string) => capabilities.has(capability),
}))

import { InsightsPage } from './InsightsPage'

function baseInsights(over: Partial<InsightsResponse> = {}): InsightsResponse {
  return {
    generatedAt: '2026-08-25T12:00:00Z',
    issueClasses: [],
    noisyNamespaces: [],
    newIssueClasses: [],
    newNoisyNamespaces: [],
    newSignalWindowDays: 7,
    unstableClusters: [],
    investigationOutcomes: {
      totalAnalyses: 0,
      completeCount: 0,
      partialCount: 0,
      completeRate: null,
      avgIterations: null,
    },
    costAndTokens: {
      totalInvestigations: 0,
      avgTokensBilledIn: 0,
      avgTokensCacheRead: 0,
      avgTokensOut: 0,
      totalCostUsd: 0,
      unmeasuredCostCount: 0,
      costTrackingNote: 'test cost tracking note',
      dailyTrend: [],
    },
    notBuilt: [
      { id: 'calibrationCurve', label: 'Confidence calibration curve', reason: 'needs shadow-mode history' },
      { id: 'autonomyReadiness', label: 'Autonomy readiness per class', reason: 'needs decision history' },
      { id: 'estimatedToilSaved', label: 'Estimated toil saved', reason: 'needs a human-fix-time baseline' },
      { id: 'spendVsValue', label: 'Spend vs. value', reason: 'needs a value-avoided methodology' },
    ],
    ...over,
  }
}

function unstableCluster(over: Partial<UnstableClusterSummary> = {}): UnstableClusterSummary {
  return {
    clusterId: 'cl_flaky',
    clusterDisplayName: 'prod-flaky',
    totalIncidents: 12,
    reopenedOrFailedCount: 5,
    openCount: 8,
    ...over,
  }
}

function issueClass(over: Partial<IssueClassSummary> = {}): IssueClassSummary {
  return {
    fingerprint: 'fp_new_signal',
    sampleGvk: 'apps/v1/Deployment',
    sampleNamespace: 'checkout',
    sampleObjectName: 'checkout-worker',
    sampleReason: 'CrashLoopBackOff',
    incidentCount: 2,
    clusterCount: 1,
    totalOccurrences: 2,
    firstSeen: '2026-08-24T09:00:00Z',
    lastSeen: '2026-08-25T09:00:00Z',
    ...over,
  }
}

function newNoisyNamespace(over: Partial<NewNoisyNamespaceSummary> = {}): NewNoisyNamespaceSummary {
  return {
    namespace: 'checkout',
    findingCount: 3,
    incidentCount: 2,
    clusterCount: 1,
    firstSeen: '2026-08-24T09:00:00Z',
    ...over,
  }
}

function rejectedRecommendation(over: Partial<RejectedRecommendationSummary> = {}): RejectedRecommendationSummary {
  return {
    actionType: 'ScaleDeployment',
    targetGvk: 'apps/v1/Deployment',
    recommendedCount: 4,
    decidedCount: 5,
    rejectedCount: 3,
    rejectionRate: 0.6,
    sampleRejectionReason: 'would breach maxReplicas policy',
    lastRejectedAt: '2026-08-24T10:00:00Z',
    ...over,
  }
}

function automationCandidate(over: Partial<AutomationCandidateSummary> = {}): AutomationCandidateSummary {
  return {
    actionType: 'RestartPod',
    targetGvk: 'v1/Pod',
    riskLevel: 'medium',
    decidedCount: 3,
    approvedCount: 3,
    rejectedCount: 0,
    approvalRate: 1,
    lastDecidedAt: '2026-08-24T11:00:00Z',
    ...over,
  }
}

function baseRemediationQuality(over: Partial<RemediationQualityResponse> = {}): RemediationQualityResponse {
  return {
    generatedAt: '2026-08-25T12:00:00Z',
    frequentlyRejected: [],
    automationCandidates: [],
    ...over,
  }
}

function renderPage(initialEntries: string[] = ['/']) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={initialEntries}>
        <InsightsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  mockGetClusters.mockReset()
  mockGetInsights.mockReset()
  mockGetInsightsRemediationQuality.mockReset()
  mockGetSpendToday.mockReset()
  capabilities.clear()

  mockGetClusters.mockResolvedValue({ clusters: [] })
  mockGetInsightsRemediationQuality.mockResolvedValue(baseRemediationQuality())
  mockGetSpendToday.mockRejectedValue(new Error('spend:read not held'))
})

describe('InsightsPage — unstable clusters', () => {
  it('renders the real reopened/failed and open counts, ranked, without a fabricated figure', async () => {
    mockGetInsights.mockResolvedValue(
      baseInsights({ unstableClusters: [unstableCluster()] }),
    )
    renderPage()

    // "Unstable clusters" (the <h2>) also exists in the loading skeleton, so
    // waiting on it alone would resolve before real data ever renders — wait
    // on the cluster's own name instead, which only exists once loaded.
    expect(await screen.findByText('prod-flaky')).toBeTruthy()
    expect(screen.getByText('Incidents by cluster')).toBeTruthy()
    // The three real counts, as words beside the bar: reopened/failed (5), open (8), total (12).
    const row = screen.getByText('prod-flaky').closest('li') as HTMLElement
    expect(row.textContent).toMatch(/5 reopened\/failed · 8 open · 12 total/)
  })

  it('shows a scope-aware empty message, distinct for an "All clusters" vs. a narrowed cluster', async () => {
    mockGetInsights.mockResolvedValue(
      baseInsights({ issueClasses: [], noisyNamespaces: [], unstableClusters: [] }),
    )
    renderPage()
    // hasAnyData is false with everything empty, so the page-level EmptyState
    // renders instead of the per-section one — that itself is the honest
    // "nothing exists yet" state, not a per-section empty message.
    expect(await screen.findByText(/No incidents or analyses recorded yet/i)).toBeTruthy()
  })
})

describe('InsightsPage — new in this window (BUGS.md 121 part b)', () => {
  it('renders a new issue class with its real counts and "First seen" rather than "Last seen"', async () => {
    mockGetInsights.mockResolvedValue(
      baseInsights({ newIssueClasses: [issueClass()], unstableClusters: [unstableCluster()] }),
    )
    renderPage()

    await screen.findByText('What keeps happening')
    fireEvent.click(screen.getByRole('button', { name: /^New in 7d/ }))
    // The fingerprint is the link's title, not printed under every object.
    expect(screen.getByTitle(/^Fingerprint fp_new_signal/)).toBeTruthy()
    expect(screen.getByText('checkout/checkout-worker')).toBeTruthy()
    expect(screen.getByText('CrashLoopBackOff')).toBeTruthy()
    // This table's own "First seen" column header, distinct from the
    // all-time table's "Last seen" — the fact that actually answers "how
    // new is this," per NewIssueClassRow's own doc comment.
    expect(screen.getByText('First seen')).toBeTruthy()
  })

  it('renders a new noisy namespace with a "since" marker, alongside the all-time list', async () => {
    mockGetInsights.mockResolvedValue(
      baseInsights({
        newNoisyNamespaces: [newNoisyNamespace()],
        noisyNamespaces: [{ namespace: 'checkout', findingCount: 40, incidentCount: 12, clusterCount: 3 }],
        unstableClusters: [unstableCluster()],
      }),
    )
    renderPage()

    // "New noisy namespaces" (the <h2>) also exists in the loading
    // skeleton, so waiting on it alone would resolve before real data ever
    // renders (same trap as the "Unstable clusters" test above) — wait on
    // the "since" marker itself, which only exists once real data has
    // loaded.
    // Noisiest first; the new-signal list is one toggle away, with its since marker.
    expect(await screen.findByText('checkout')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: /^New · 1/ }))
    expect(screen.getByText(/since/)).toBeTruthy()
    expect(screen.getByText('checkout')).toBeTruthy()
  })

  it('shows a scope-aware empty message that does not claim the date-range selector helps (this list ignores it)', async () => {
    mockGetInsights.mockResolvedValue(baseInsights({ unstableClusters: [unstableCluster()] }))
    renderPage()

    await screen.findByText('What keeps happening')
    fireEvent.click(screen.getByRole('button', { name: /^New in 7d/ }))
    fireEvent.click(screen.getByRole('button', { name: /^New · 0/ }))
    expect(screen.getByText(/No new issue classes in the last 7 days/)).toBeTruthy()
    expect(screen.getByText(/No new noisy namespaces in the last 7 days\./)).toBeTruthy()
  })

  it('names the cluster-scoped remedy without suggesting a wider date range', async () => {
    mockGetClusters.mockResolvedValue({ clusters: [{ id: 'cl_1', displayName: 'prod-1' }] })
    mockGetInsights.mockResolvedValue(baseInsights({ unstableClusters: [unstableCluster()] }))
    renderPage(['/?clusterId=cl_1'])

    await screen.findByText('What keeps happening')
    fireEvent.click(screen.getByRole('button', { name: /^New in 7d/ }))
    fireEvent.click(screen.getByRole('button', { name: /^New · 0/ }))
    expect(screen.getByText(/No new issue classes for this cluster in the last 7 days\. Try All clusters\./)).toBeTruthy()
    expect(screen.getByText(/No new noisy namespaces for this cluster in the last 7 days\. Try All clusters\./)).toBeTruthy()
  })
})

describe('InsightsPage — remediation quality is a capability-gated, separate query', () => {
  it('renders both section headings with a "Restricted" body (never absent) without remediation:approve, and never calls the endpoint', async () => {
    mockGetInsights.mockResolvedValue(baseInsights({ unstableClusters: [unstableCluster()] }))
    renderPage()

    await screen.findByText('prod-flaky')
    expect(screen.getByText('Fixes people reject')).toBeTruthy()
    expect(screen.getByText('Automation candidates')).toBeTruthy()
    expect(screen.getAllByText(/Restricted — viewing this needs the remediation:approve capability\./)).toHaveLength(2)
    expect(mockGetInsightsRemediationQuality).not.toHaveBeenCalled()
  })

  it('renders frequently-rejected recommendations with a real rejection rate, and a sample reason', async () => {
    capabilities.add(CAP_REMEDIATION_APPROVE)
    mockGetInsights.mockResolvedValue(baseInsights({ unstableClusters: [unstableCluster()] }))
    mockGetInsightsRemediationQuality.mockResolvedValue(
      baseRemediationQuality({ frequentlyRejected: [rejectedRecommendation()] }),
    )
    renderPage()

    // The section heading also exists in this capability's loading skeleton
    // (rendered as soon as the main insights query is loading), so wait on
    // the row's own content, which only exists once real data has landed.
    expect(await screen.findByText('Scale deployment')).toBeTruthy()
    expect(screen.getByText('Fixes people reject')).toBeTruthy()
    expect(screen.getByText('Deployment')).toBeTruthy()
    expect(screen.getByText(/rejected \(60%\)/)).toBeTruthy()
    expect(screen.getByText('“would breach maxReplicas policy”')).toBeTruthy()
  })

  it('renders automation candidates with a 100% approval rate and its real sample size, not a bare percentage', async () => {
    capabilities.add(CAP_REMEDIATION_APPROVE)
    mockGetInsights.mockResolvedValue(baseInsights({ unstableClusters: [unstableCluster()] }))
    mockGetInsightsRemediationQuality.mockResolvedValue(
      baseRemediationQuality({ automationCandidates: [automationCandidate()] }),
    )
    renderPage()

    expect(await screen.findByText('Restart pod')).toBeTruthy()
    expect(screen.getByText('Automation candidates')).toBeTruthy()
    // A rate is never shown without its real sample size.
    expect(screen.getByText(/3 of 3 approved \(100%\)/)).toBeTruthy()
  })

  it('shows a scope-aware empty message per section when the capability is held but nothing qualifies', async () => {
    capabilities.add(CAP_REMEDIATION_APPROVE)
    mockGetInsights.mockResolvedValue(baseInsights({ unstableClusters: [unstableCluster()] }))
    mockGetInsightsRemediationQuality.mockResolvedValue(baseRemediationQuality())
    renderPage()

    await screen.findByText(/No rejected recommendations in the last 14 days\./)
    expect(screen.getByText(/No decided approvals in the last 14 days\./)).toBeTruthy()
  })
})

describe('InsightsPage — the roadmap section stays in sync with notBuilt', () => {
  it('states how many pieces are missing rather than a hardcoded number, and lists every one', async () => {
    mockGetInsights.mockResolvedValue(baseInsights({ unstableClusters: [unstableCluster()] }))
    renderPage()

    // The property under test is that the number is DERIVED from notBuilt,
    // not hardcoded — not the surrounding wording, which was rewritten when
    // internal document references (§15.1, BACKLOG.md) were removed from
    // customer-facing copy.
    expect(await screen.findByText(/Not measured yet · 4/)).toBeTruthy()
    expect(screen.getByText('Confidence calibration curve')).toBeTruthy()
    expect(screen.getByText('Autonomy readiness per class')).toBeTruthy()
    expect(screen.getByText('Estimated toil saved')).toBeTruthy()
    expect(screen.getByText('Spend vs. value')).toBeTruthy()
  })
})

// PROJECT.md T8. The second place org spend is displayed, and the one that
// rendered `$0.0000` with a green accent regardless of whether that zero meant
// anything. It is the same fabricated zero the Total cost tile beside it was
// already fixed for.
describe('InsightsPage — the org spend tile never renders an unmeasurable cost as a dollar figure', () => {
  function spend(over: Partial<SpendToday> = {}): SpendToday {
    return {
      generatedAt: '2026-09-17T10:00:00Z',
      date: '2026-09-17',
      todaySpendUsd: 0,
      pricingConfigured: true,
      spendCountable: true,
      dailySpendCeilingUsd: null,
      ceilingBreached: false,
      ceilingEnforceable: false,
      ...over,
    }
  }

  it('says "not measured" and names the subscription provider instead of $0.0000', async () => {
    capabilities.add(CAP_SPEND_READ)
    mockGetInsights.mockResolvedValue(baseInsights({ unstableClusters: [unstableCluster()] }))
    mockGetSpendToday.mockResolvedValue(spend({ spendCountable: false, dailySpendCeilingUsd: 10 }))
    renderPage()

    expect(
      await screen.findByText(/not measured, subscription provider/),
    ).toBeTruthy()
    expect(screen.queryByText('$0.0000')).toBeNull()
    // And the ceiling is not described as one that applies.
    expect(screen.getByText(/\$10\.00 ceiling not enforced/)).toBeTruthy()
  })

  it('names the missing price table when that is the reason, not the provider', async () => {
    capabilities.add(CAP_SPEND_READ)
    mockGetInsights.mockResolvedValue(baseInsights({ unstableClusters: [unstableCluster()] }))
    mockGetSpendToday.mockResolvedValue(spend({ pricingConfigured: false }))
    renderPage()

    expect(await screen.findByText(/not measured, no price table/)).toBeTruthy()
    expect(screen.queryByText('$0.0000')).toBeNull()
  })

  it('renders the real figure and the ceiling where spend genuinely is measured', async () => {
    capabilities.add(CAP_SPEND_READ)
    mockGetInsights.mockResolvedValue(baseInsights({ unstableClusters: [unstableCluster()] }))
    mockGetSpendToday.mockResolvedValue(
      spend({ todaySpendUsd: 1.2345, dailySpendCeilingUsd: 10, ceilingEnforceable: true }),
    )
    renderPage()

    expect(await screen.findByText('$1.2345')).toBeTruthy()
    expect(screen.getByText('Org spend today')).toBeTruthy()
    expect(screen.getByText(/of \$10\.00 ceiling/)).toBeTruthy()
  })
})
