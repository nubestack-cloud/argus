import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type {
  AgentCompatibility,
  AutomationWindowsResponse,
  AutonomySettings,
  CircuitBreakerResponse,
  Cluster,
  CreateEnrollmentTokenResponse,
} from '../api/types'

// T16: every Cluster now carries a server-computed compatibility verdict.
// This suite doesn't exercise it, so a fixed 'unknown' default (honest for
// a cluster that has never reported a version, which is exactly this file's
// PendingApproval/no-agentVersion default below) is enough.
const UNREPORTED_COMPATIBILITY: AgentCompatibility = {
  verdict: 'unknown',
  label: 'Unknown',
  agentVersion: null,
  minSupportedVersion: '0.1.0-mvp',
  recommendedVersion: '0.1.0-mvp',
  reason: 'This cluster has not reported an agent version yet, so no compatibility verdict can be given.',
}
import { CAP_CLUSTER_ACCEPT, CAP_CLUSTER_ONBOARD } from '../api/capabilities'

// BACKLOG P3. OverviewPage itself wires together seven queries (clusters,
// incidents, approvals, spend, settings, breaker, windows) that would all
// need mocking to render the whole page — but the actual first-run logic
// worth pinning down lives entirely inside OnboardingWizard, which takes
// plain props and owns nothing but its own three mutations. Same boundary
// ClusterDetailPage.test.tsx already draws for DetectionCard/
// RemediationAuthorityCard: test the exported subcomponent directly rather
// than the whole page.
//
// The four steps are re-derived from live data every render (this file's own
// doc comment: "not a client-side illusion of progress that could drift from
// what's actually true"), which is exactly the kind of derivation a rename or
// a reordered condition can quietly break — these tests pin each of the four
// stepIndex outcomes and the capability-gated button in each one.

const mockCreateEnrollmentToken = vi.fn()
const mockAcceptCluster = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    createEnrollmentToken: (...args: unknown[]) => mockCreateEnrollmentToken(...args),
    acceptCluster: (...args: unknown[]) => mockAcceptCluster(...args),
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ accessToken: 'test-token' }),
}))

import { AIProviderSetupCard, AutomationStatusCard, OnboardingWizard } from './OverviewPage'
import { IncidentActivity } from '../overview/NowBand'
import type { IncidentOverviewDay } from '../api/types'

function cluster(over: Partial<Cluster>): Cluster {
  return {
    id: 'cl_default',
    displayName: 'prod-eu',
    state: 'PendingApproval',
    agentVersion: null,
    lastHeartbeatAt: null,
    createdAt: '2026-08-20T00:00:00Z',
    archivedAt: null,
    compatibility: UNREPORTED_COMPATIBILITY,
    ...over,
  }
}

function renderWizard(props: { clusters: Cluster[]; canOnboard?: boolean; canAccept?: boolean }) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter>
        <OnboardingWizard
          clusters={props.clusters}
          canOnboard={props.canOnboard ?? true}
          canAccept={props.canAccept ?? true}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  mockCreateEnrollmentToken.mockReset()
  mockAcceptCluster.mockReset()
})

describe('OnboardingWizard — the four steps track real state, not a remembered click count', () => {
  it('step 1 is current with no clusters and no token yet', () => {
    renderWizard({ clusters: [] })
    const steps = screen.getAllByRole('listitem')
    expect(steps[0].className).toBe('onboarding-step-current')
    expect(steps[1].className).toBe('onboarding-step-pending')
    expect(screen.getByRole('button', { name: /Generate token/i })).toBeTruthy()
  })

  it('generating a token advances to step 2 and shows the install snippet with that exact token', async () => {
    const response: CreateEnrollmentTokenResponse = {
      token: 'tok_abc123',
      expiresAt: '2026-08-25T01:00:00Z',
      agentInstall: { chartRef: 'oci://registry-1.docker.io/nubestack/argus-agent-chart', chartVersion: '0.2.0', hubApiUrl: 'https://argus.example.com' },
    }
    mockCreateEnrollmentToken.mockResolvedValue(response)
    renderWizard({ clusters: [] })

    fireEvent.click(screen.getByRole('button', { name: /Generate token/i }))

    await waitFor(() => {
      const steps = screen.getAllByRole('listitem')
      expect(steps[0].className).toBe('onboarding-step-done')
      expect(steps[1].className).toBe('onboarding-step-current')
    })
    expect(screen.getByText(/tok_abc123/)).toBeTruthy()
  })

  it('a cluster stuck at PendingApproval puts step 3 in the current, actionable state', () => {
    renderWizard({ clusters: [cluster({ id: 'cl_1', displayName: 'my-cluster', state: 'PendingApproval' })] })
    const steps = screen.getAllByRole('listitem')
    expect(steps[0].className).toBe('onboarding-step-done')
    expect(steps[1].className).toBe('onboarding-step-done')
    expect(steps[2].className).toBe('onboarding-step-current')
    expect(screen.getByText('my-cluster')).toBeTruthy()
    expect(screen.getByRole('button', { name: /Accept cluster/i })).toBeTruthy()
  })

  it('accepting the pending cluster calls the API with that cluster\'s id', async () => {
    mockAcceptCluster.mockResolvedValue({})
    renderWizard({ clusters: [cluster({ id: 'cl_specific', state: 'PendingApproval' })] })

    fireEvent.click(screen.getByRole('button', { name: /Accept cluster/i }))
    await waitFor(() => expect(mockAcceptCluster).toHaveBeenCalledWith('cl_specific', 'test-token'))
  })

  it('a Provisioning cluster (accepted, no heartbeat yet) puts step 4 in the current state', () => {
    renderWizard({ clusters: [cluster({ state: 'Provisioning' })] })
    const steps = screen.getAllByRole('listitem')
    expect(steps[2].className).toBe('onboarding-step-done')
    expect(steps[3].className).toBe('onboarding-step-current')
    expect(screen.getByText(/waiting for the agent's tunnel to report in/i)).toBeTruthy()
    // Step 4 is the last step and is never rendered as "done" by this
    // component — the parent unmounts the whole card once a cluster reaches
    // Active (OverviewPage's own fleetOnboarded check), so there is no
    // "done" state for this file to own.
    expect(steps[3].className).not.toBe('onboarding-step-done')
  })
})

describe('OnboardingWizard — capability-gated actions are disabled, not hidden', () => {
  it('"Generate token" is disabled with the missing-capability reason when the actor lacks cluster:onboard', () => {
    renderWizard({ clusters: [], canOnboard: false })
    const button = screen.getByRole('button', { name: /Generate token/i })
    expect(button).toHaveProperty('disabled', true)
    expect(button.title).toMatch(new RegExp(CAP_CLUSTER_ONBOARD))
  })

  it('"Accept cluster" is disabled with the missing-capability reason when the actor lacks cluster:accept', () => {
    renderWizard({ clusters: [cluster({ state: 'PendingApproval' })], canAccept: false })
    const button = screen.getByRole('button', { name: /Accept cluster/i })
    expect(button).toHaveProperty('disabled', true)
    expect(button.title).toMatch(new RegExp(CAP_CLUSTER_ACCEPT))
  })

  // PROJECT.md D14: the onboarding wizard used to offer "Load sample data
  // instead" here. Sample data is gone from the product — the honest answer
  // to an empty install is to enrol a cluster, including a test one.
  it('offers no sample-data shortcut out of the empty state', async () => {
    renderWizard({ clusters: [] })
    expect(screen.queryByRole('button', { name: /sample data/i })).toBeNull()
    expect(screen.getByRole('link', { name: /Open Clusters page/i })).toBeTruthy()
  })
})

// BACKLOG P3 (second round). The rest of OverviewPage outside the onboarding
// wizard: AutomationStatusCard, AIProviderSetupCard and IncidentActivity are
// all presentational-plus-derivation components fed by props the page's own
// queries produce — same OnboardingWizard/DetectionCard precedent, tested
// directly with plain props rather than through the whole page's seven
// queries.

function autonomy(over: Partial<AutonomySettings> = {}): AutonomySettings {
  return {
    autoApproveMaxRisk: 'low',
    minConfidenceForAutoApprove: 0.5,
    requireReversibleForAutoApprove: true,
    effectiveAutoApproveMaxRisk: 'low',
    effectiveMinConfidenceForAutoApprove: 0.5,
    effectiveRequireReversibleForAutoApprove: true,
    unattendedExecutionEnabled: true,
    maxUnattendedPerCluster: null,
    maxUnattendedFleetWide: null,
    unattendedWindowSeconds: null,
    effectiveMaxUnattendedPerCluster: 5,
    effectiveMaxUnattendedFleetWide: 20,
    effectiveUnattendedWindowSeconds: 3600,
    unattendedNamespaces: ['payments'],
    ...over,
  }
}

function breaker(over: Partial<CircuitBreakerResponse> = {}): CircuitBreakerResponse {
  return {
    enabled: true,
    maxPerCluster: 3,
    maxFleetWide: 10,
    windowSeconds: 3600,
    open: [],
    history: [],
    ...over,
  }
}

function windows(over: Partial<AutomationWindowsResponse> = {}): AutomationWindowsResponse {
  return {
    windows: [],
    automationOpenNow: true,
    decisionReason: 'No freeze window scheduled',
    ...over,
  }
}

function renderAutomationCard(props: Partial<Parameters<typeof AutomationStatusCard>[0]> = {}) {
  return render(
    <MemoryRouter>
      <AutomationStatusCard
        canManageSettings={props.canManageSettings ?? true}
        unattendedEnabled={props.unattendedEnabled ?? true}
        autonomy={props.autonomy}
        breaker={props.breaker}
        windows={props.windows}
      />
    </MemoryRouter>,
  )
}

describe('AutomationStatusCard — the one card that says whether automation is actually running', () => {
  it('without org:settings:write, shows the access-denied message and no bound chips at all', () => {
    renderAutomationCard({ canManageSettings: false })
    expect(screen.getByText(/your role cannot read/i)).toBeTruthy()
    expect(screen.queryByText(/Blast radius/i)).toBeNull()
  })

  it('unattended execution off reads "off", with "nothing runs without a person" on the pill, not held-back language', () => {
    renderAutomationCard({ unattendedEnabled: false, autonomy: autonomy(), breaker: breaker(), windows: windows() })
    expect(screen.getByText('Unattended execution off').getAttribute('title')).toBe('Nothing runs without a person, by configuration.')
    expect(screen.queryByText(/held back/i)).toBeNull()
  })

  it('unattended execution on with an empty namespace allowlist is "held back" even with a closed breaker and no freeze', () => {
    renderAutomationCard({
      unattendedEnabled: true,
      autonomy: autonomy({ unattendedNamespaces: [] }),
      breaker: breaker(),
      windows: windows(),
    })
    expect(screen.getByText('Unattended execution on · held back')).toBeTruthy()
    expect(screen.getByText('No namespace allowlisted').closest('.ov-g')?.getAttribute('title')).toMatch(/denies/)
  })

  it('a tripped breaker is held-back and names the trip reason, with a "Reset the breaker" link', () => {
    renderAutomationCard({
      autonomy: autonomy(),
      breaker: breaker({
        open: [{
          id: 't1',
          fleetWide: true,
          trippedAt: '2026-08-25T00:00:00Z',
          reason: 'too many failed patches',
          badOutcomes: 5,
          threshold: 3,
        }],
      }),
      windows: windows(),
    })
    expect(screen.getByText('Unattended execution on · held back')).toBeTruthy()
    expect(screen.getByText(/Circuit breaker open — too many failed patches/i)).toBeTruthy()
    expect(screen.getByRole('link', { name: /Reset the breaker/i })).toBeTruthy()
  })

  it('a disabled breaker reads as neutral-and-held-back, not as a closed/permitting one', () => {
    renderAutomationCard({ autonomy: autonomy(), breaker: breaker({ enabled: false }), windows: windows() })
    expect(screen.getByText(/Circuit breaker disabled — failing changes stop nothing/i)).toBeTruthy()
  })

  it('an active freeze window names its own reason and holds the card back', () => {
    renderAutomationCard({
      autonomy: autonomy(),
      breaker: breaker(),
      windows: windows({ automationOpenNow: false, decisionReason: 'Scheduled maintenance freeze' }),
    })
    expect(screen.getByText(/Change freeze in force — Scheduled maintenance freeze/i)).toBeTruthy()
    expect(screen.getByText('Unattended execution on · held back')).toBeTruthy()
  })

  it('fully unblocked (namespaces set, breaker closed, no freeze) reads plain "on", with no held-back mark and no "Reset the breaker" link', () => {
    renderAutomationCard({ autonomy: autonomy(), breaker: breaker(), windows: windows() })
    expect(screen.getByText('Unattended execution on').getAttribute('title')).toBe('Unattended execution is running and unblocked.')
    expect(screen.queryByText(/held back/i)).toBeNull()
    expect(screen.queryByText(/Reset the breaker/i)).toBeNull()
  })

  it('missing breaker/windows data reads as unavailable, not as a false permitting state', () => {
    renderAutomationCard({ autonomy: autonomy(), breaker: undefined, windows: undefined })
    expect(screen.getByText(/Circuit breaker state unavailable/i)).toBeTruthy()
    expect(screen.getByText(/Freeze window state unavailable/i)).toBeTruthy()
  })
})

describe('AIProviderSetupCard — the setup-needed card OverviewPage shows only while unconfigured', () => {
  it('renders the setup message and a link into the AI providers settings section', () => {
    render(
      <MemoryRouter>
        <AIProviderSetupCard />
      </MemoryRouter>,
    )
    expect(screen.getByText('Configure your AI provider')).toBeTruthy()
    expect(screen.getByText(/never investigated/i)).toBeTruthy()
    const link = screen.getByRole('link', { name: /Go to AI provider settings/i })
    expect(link.getAttribute('href')).toBe('/settings?section=providers')
  })
})

function day(date: string, opened: Partial<IncidentOverviewDay['opened']> = {}): IncidentOverviewDay {
  return { date, opened: { critical: 0, high: 0, medium: 0, low: 0, ...opened }, resolved: 0, openAtEnd: 0 }
}

// The chart now draws the hub's whole-set per-day series, so there is no
// truncation caveat left to test: what remains is that every count stays
// reachable without colour (owner's decision, 2026-09-19, to keep severity
// segments in the bars).
describe('IncidentActivity — incidents opened per day, from the hub series', () => {
  it('describes each day and the window by severity in its accessible name', () => {
    render(<IncidentActivity daily={[day('2026-10-11'), day('2026-10-12', { critical: 1, high: 2 })]} />)
    const chart = screen.getByRole('img', { name: /3 incidents opened during the last 2 days/i })
    expect(chart.getAttribute('aria-label')).toMatch(/1 critical, 2 high, 0 medium, 0 low/)
    expect(chart.getAttribute('aria-label')).toMatch(/none/)
  })

  it('draws one segment per severity present, sized by its share, critical first', () => {
    render(<IncidentActivity daily={[day('2026-10-12', { critical: 1, low: 2 })]} />)
    const segments = Array.from(document.querySelectorAll('.ov-activity-seg')) as HTMLElement[]
    expect(segments.map((s) => s.className)).toEqual(['ov-activity-seg sev-critical', 'ov-activity-seg sev-low'])
    expect(segments[0].style.height).toBe('33.33333333333333%')
  })

  it('keeps every count readable without colour: the bar total, the per-day title and the window legend', () => {
    render(<IncidentActivity daily={[day('2026-10-12', { high: 2, medium: 1 })]} />)
    expect(document.querySelector('.ov-activity-total')?.textContent).toBe('3')
    expect(document.querySelector('.ov-activity-bar')?.getAttribute('title')).toMatch(/3 opened — 2 high, 1 medium/)
    const legend = Array.from(document.querySelectorAll('.ov-legend li')).map((li) => li.textContent)
    expect(legend).toEqual(['Critical 0', 'High 2', 'Medium 1', 'Low 0'])
  })

  it('draws nothing for a day with nothing opened rather than a sliver standing for zero', () => {
    render(<IncidentActivity daily={[day('2026-10-12')]} />)
    expect(document.querySelector('.ov-activity-bar')).toBeNull()
    expect(screen.getByRole('img', { name: /0 incidents opened/i })).toBeTruthy()
  })
})
