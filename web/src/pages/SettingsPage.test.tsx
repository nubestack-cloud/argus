import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type {
  AIProvider,
  AIProvidersResponse,
  AutomationWindow,
  AutomationWindowsResponse,
  CircuitBreakerResponse,
  ClusterGroup,
  ClusterGroupsResponse,
  ClustersResponse,
  CustomRole,
  CustomRolesResponse,
  DetectionDryRunResponse,
  RepositoriesResponse,
  RolesResponse,
  Settings,
} from '../api/types'
import {
  CAP_CLUSTER_GROUP_MANAGE,
  CAP_ORG_SETTINGS_WRITE,
  CAP_REPO_READ,
  CAP_REPO_WRITE,
  CAP_ROLE_MANAGE,
} from '../api/capabilities'

// BACKLOG P3 — the last of the ten big pages. SettingsPage is one component
// fronting eight navigable sections (General, Detectors, Investigation,
// AI providers, Model pricing, Git repositories, Notifications, Roles &
// access) sharing one GET/PUT pair, plus four real child components
// (AIProvidersCard, RepositoriesCard, AutomationWindowsCard,
// CircuitBreakerCard) that fetch their own data. These tests render the real
// children rather than stubs, mocking every api/client function any of them
// call, and drive the page through the real router/query client per this
// session's established convention (ClustersPage/AuditLogPage/TolerationsPage).

const mockGetSettings = vi.fn()
const mockUpdateSettings = vi.fn()
const mockGetRoles = vi.fn()
const mockDryRunDetectionSettings = vi.fn()
const mockGetDiagnosticsBundle = vi.fn()
const mockGetAIProviders = vi.fn()
const mockActivateAIProvider = vi.fn()
const mockCreateAIProvider = vi.fn()
const mockUpdateAIProvider = vi.fn()
const mockDeleteAIProvider = vi.fn()
const mockTestAIProvider = vi.fn()
const mockGetRepositories = vi.fn()
const mockCreateRepository = vi.fn()
const mockDeleteRepository = vi.fn()
const mockCheckRepository = vi.fn()
const mockGetAutomationWindows = vi.fn()
const mockCreateAutomationWindow = vi.fn()
const mockDeleteAutomationWindow = vi.fn()
const mockGetCircuitBreaker = vi.fn()
const mockResetCircuitBreaker = vi.fn()
const mockGetCustomRoles = vi.fn()
const mockCreateCustomRole = vi.fn()
const mockUpdateCustomRole = vi.fn()
const mockDeleteCustomRole = vi.fn()
const mockGetClusterGroups = vi.fn()
const mockGetNotificationRouting = vi.fn()
const mockCreateClusterGroup = vi.fn()
const mockDeleteClusterGroup = vi.fn()
const mockAddClusterToGroup = vi.fn()
const mockRemoveClusterFromGroup = vi.fn()
const mockGetClusters = vi.fn()
const mockListPersonalTokens = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    getSettings: (...args: unknown[]) => mockGetSettings(...args),
    updateSettings: (...args: unknown[]) => mockUpdateSettings(...args),
    getRoles: (...args: unknown[]) => mockGetRoles(...args),
    dryRunDetectionSettings: (...args: unknown[]) => mockDryRunDetectionSettings(...args),
    getDiagnosticsBundle: (...args: unknown[]) => mockGetDiagnosticsBundle(...args),
    getAIProviders: (...args: unknown[]) => mockGetAIProviders(...args),
    activateAIProvider: (...args: unknown[]) => mockActivateAIProvider(...args),
    createAIProvider: (...args: unknown[]) => mockCreateAIProvider(...args),
    updateAIProvider: (...args: unknown[]) => mockUpdateAIProvider(...args),
    deleteAIProvider: (...args: unknown[]) => mockDeleteAIProvider(...args),
    testAIProvider: (...args: unknown[]) => mockTestAIProvider(...args),
    getRepositories: (...args: unknown[]) => mockGetRepositories(...args),
    createRepository: (...args: unknown[]) => mockCreateRepository(...args),
    deleteRepository: (...args: unknown[]) => mockDeleteRepository(...args),
    checkRepository: (...args: unknown[]) => mockCheckRepository(...args),
    getAutomationWindows: (...args: unknown[]) => mockGetAutomationWindows(...args),
    createAutomationWindow: (...args: unknown[]) => mockCreateAutomationWindow(...args),
    deleteAutomationWindow: (...args: unknown[]) => mockDeleteAutomationWindow(...args),
    getCircuitBreaker: (...args: unknown[]) => mockGetCircuitBreaker(...args),
    resetCircuitBreaker: (...args: unknown[]) => mockResetCircuitBreaker(...args),
    getCustomRoles: (...args: unknown[]) => mockGetCustomRoles(...args),
    createCustomRole: (...args: unknown[]) => mockCreateCustomRole(...args),
    updateCustomRole: (...args: unknown[]) => mockUpdateCustomRole(...args),
    deleteCustomRole: (...args: unknown[]) => mockDeleteCustomRole(...args),
    getClusterGroups: (...args: unknown[]) => mockGetClusterGroups(...args),
    createClusterGroup: (...args: unknown[]) => mockCreateClusterGroup(...args),
    deleteClusterGroup: (...args: unknown[]) => mockDeleteClusterGroup(...args),
    addClusterToGroup: (...args: unknown[]) => mockAddClusterToGroup(...args),
    removeClusterFromGroup: (...args: unknown[]) => mockRemoveClusterFromGroup(...args),
    getClusters: (...args: unknown[]) => mockGetClusters(...args),
    getNotificationRouting: (...args: unknown[]) => mockGetNotificationRouting(...args),
    listPersonalTokens: (...args: unknown[]) => mockListPersonalTokens(...args),
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ accessToken: 'test-token' }),
}))

const capabilities = new Set<string>([CAP_ORG_SETTINGS_WRITE, CAP_REPO_READ, CAP_REPO_WRITE])
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (capability: string) => capabilities.has(capability),
  useMissingCapabilities: (caps: string[]) => ({ resolved: true, missing: caps.filter((c) => !capabilities.has(c)) }),
}))

import { SettingsPage } from './SettingsPage'
import { ApiError } from '../api/client'

// A full, "nothing configured yet" Settings object — every test overrides
// only the section(s) it cares about, one level deep per section (matching
// how the real API always returns every section, never a partial object).
function baseSettings(): Settings {
  return {
    llm: {
      baseUrl: '',
      model: '',
      apiKeySet: false,
      providerKind: 'api',
      cliRunnerUrl: '',
      cliAgent: 'claude',
      cliRunnerTokenSet: false,
      cliBackendAvailable: true,
    },
    notify: { webhookConfigured: false },
    analysis: {
      maxIterations: null,
      timeLimitSeconds: null,
      effectiveMaxIterations: 20,
      effectiveTimeLimitSeconds: 600,
      retrievalEnabled: false,
    },
    automation: { autoAnalysisEnabled: false, autoAnalysisSeverities: [] },
    retention: { auditRetentionDays: null, incidentRetentionDays: null, findingRetentionDays: null },
    detection: {
      disabledDetectorIds: [],
      stormProtectionMaxNewIncidents: null,
      stormProtectionWindowSeconds: null,
      disabledRuleIds: [],
    },
    autonomy: {
      autoApproveMaxRisk: null,
      minConfidenceForAutoApprove: null,
      requireReversibleForAutoApprove: true,
      effectiveAutoApproveMaxRisk: 'low',
      effectiveMinConfidenceForAutoApprove: 0.9,
      effectiveRequireReversibleForAutoApprove: true,
      unattendedExecutionEnabled: false,
      maxUnattendedPerCluster: null,
      maxUnattendedFleetWide: null,
      unattendedWindowSeconds: null,
      effectiveMaxUnattendedPerCluster: 3,
      effectiveMaxUnattendedFleetWide: 10,
      effectiveUnattendedWindowSeconds: 3600,
      unattendedNamespaces: [],
    },
    cost: {
      pricePerMillionInputTokens: null,
      pricePerMillionCachedTokens: null,
      pricePerMillionOutputTokens: null,
      pricingConfigured: false,
      spendCountable: true,
      dailySpendCeilingUsd: null,
      ceilingEnforceable: false,
      todaySpendUsd: 0,
      ceilingBreached: false,
    },
    appearance: {
      loginStyle: 'aperture',
      styles: ['aperture', 'sentinel'],
      primaryColorId: 'teal',
      primaryColorOptions: ['teal', 'blue', 'violet', 'slate', 'forest'],
      overviewDefaultWindowDays: 14,
    },
    general: {
      minPasswordLength: 12,
      sessionIdleTimeoutMinutes: null,
    },
    outbound: { privateDestinations: [] },
    posture: { disabledChecks: [], ignoredNamespaces: [] },
  }
}

function settingsFixture(over: Partial<{ [K in keyof Settings]: Partial<Settings[K]> }>): Settings {
  const base = baseSettings()
  const merged = { ...base } as Settings
  for (const key of Object.keys(over) as Array<keyof Settings>) {
    ;(merged as any)[key] = { ...(base as any)[key], ...(over as any)[key] }
  }
  return merged
}

function rolesFixture(over: Partial<RolesResponse['roles']> = {}): RolesResponse {
  const empty = { capabilities: [] as string[] }
  return {
    roles: {
      'super-admin': empty,
      'tenant-admin': empty,
      resolver: empty,
      'pr-approver': empty,
      viewer: empty,
      ...over,
    },
  }
}

function aiProvider(over: Partial<AIProvider>): AIProvider {
  return {
    id: 'prov_default',
    name: 'Default provider',
    kind: 'api',
    active: false,
    baseUrl: 'https://api.example.com',
    model: 'claude',
    apiKeySet: true,
    runnerUrl: '',
    agent: '',
    runnerTokenSet: false,
    ...over,
  }
}

function providersResponse(providers: AIProvider[]): AIProvidersResponse {
  return { providers, activeProviderId: providers.find((p) => p.active)?.id ?? '' }
}

function repositoriesResponse(): RepositoriesResponse {
  return { repositories: [] }
}

function automationWindowsResponse(windows: AutomationWindow[] = []): AutomationWindowsResponse {
  return { windows, automationOpenNow: true, decisionReason: 'No freeze window is currently open.' }
}

function circuitBreakerResponse(): CircuitBreakerResponse {
  return { enabled: true, maxPerCluster: 3, maxFleetWide: 10, windowSeconds: 3600, open: [], history: [] }
}

function customRole(over: Partial<CustomRole> = {}): CustomRole {
  return {
    id: 'crole_1',
    name: 'on-call-viewer',
    capabilities: ['incident:read', 'analysis:read'],
    createdBy: 'usr_admin',
    createdAt: '2026-08-30T00:00:00Z',
    ...over,
  }
}

function customRolesResponse(roles: CustomRole[] = []): CustomRolesResponse {
  return { roles }
}

function clusterGroup(over: Partial<ClusterGroup> = {}): ClusterGroup {
  return { id: 'clg_1', name: 'payments-team', clusterIds: [], ...over }
}

function clusterGroupsResponse(groups: ClusterGroup[] = []): ClusterGroupsResponse {
  return { clusterGroups: groups }
}

function clustersResponse(): ClustersResponse {
  return {
    clusters: [
      {
        id: 'cl_a',
        displayName: 'rke2-prod',
        state: 'Active',
        agentVersion: '0.1.0',
        lastHeartbeatAt: '2026-08-30T00:00:00Z',
        createdAt: '2026-08-01T00:00:00Z',
        archivedAt: null,
        // T16: every Cluster now carries a server-computed verdict; this
        // suite doesn't exercise it, so a plain 'current' default is enough.
        compatibility: {
          verdict: 'current',
          label: 'Current',
          agentVersion: '0.1.0',
          minSupportedVersion: '0.1.0',
          recommendedVersion: '0.1.0',
          reason: 'Agent version 0.1.0 meets the recommended version 0.1.0.',
        },
      },
    ],
  }
}

function dryRunResponse(over: Partial<DetectionDryRunResponse> = {}): DetectionDryRunResponse {
  return {
    windowDays: 7,
    windowStart: '2026-08-18T00:00:00Z',
    generatedAt: '2026-08-25T00:00:00Z',
    totalFindingsInWindow: 200,
    disabledDetectorFilter: { filteredCount: 12, byClusterDetector: [] },
    stormProtection: {
      candidateConfigured: false,
      eligibleOpportunities: 0,
      actual: { createdCount: 0, suppressedCount: 0 },
      candidate: { createdCount: 0, suppressedCount: 0 },
      newlySuppressedCount: 0,
      newlyAllowedCount: 0,
      byClusterDetector: [],
    },
    ...over,
  }
}

function renderPage(initialSection?: string) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const entry = initialSection ? `/settings?section=${initialSection}` : '/settings'
  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[entry]}>
        <SettingsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  mockGetSettings.mockReset()
  mockUpdateSettings.mockReset()
  mockGetRoles.mockReset().mockResolvedValue(rolesFixture())
  mockDryRunDetectionSettings.mockReset()
  mockGetDiagnosticsBundle.mockReset()
  mockGetAIProviders.mockReset().mockResolvedValue(providersResponse([]))
  mockActivateAIProvider.mockReset()
  mockCreateAIProvider.mockReset()
  mockUpdateAIProvider.mockReset()
  mockDeleteAIProvider.mockReset()
  mockTestAIProvider.mockReset()
  mockGetRepositories.mockReset().mockResolvedValue(repositoriesResponse())
  mockCreateRepository.mockReset()
  mockDeleteRepository.mockReset()
  mockCheckRepository.mockReset()
  mockGetAutomationWindows.mockReset().mockResolvedValue(automationWindowsResponse())
  mockCreateAutomationWindow.mockReset()
  mockDeleteAutomationWindow.mockReset()
  mockGetCircuitBreaker.mockReset().mockResolvedValue(circuitBreakerResponse())
  mockResetCircuitBreaker.mockReset()
  mockGetCustomRoles.mockReset().mockResolvedValue(customRolesResponse())
  mockCreateCustomRole.mockReset()
  mockUpdateCustomRole.mockReset()
  mockDeleteCustomRole.mockReset()
  mockGetClusterGroups.mockReset().mockResolvedValue(clusterGroupsResponse())
  mockCreateClusterGroup.mockReset()
  mockDeleteClusterGroup.mockReset()
  mockAddClusterToGroup.mockReset()
  mockRemoveClusterFromGroup.mockReset()
  mockGetClusters.mockReset().mockResolvedValue(clustersResponse())
  capabilities.clear()
  capabilities.add(CAP_ORG_SETTINGS_WRITE)
  capabilities.add(CAP_REPO_READ)
  capabilities.add(CAP_REPO_WRITE)
  capabilities.add(CAP_ROLE_MANAGE)
  capabilities.add(CAP_CLUSTER_GROUP_MANAGE)
})

describe('SettingsPage — loading and error states', () => {
  it('shows the non-interactive nav and a shape-matched skeleton while loading the default (General) section', async () => {
    mockGetSettings.mockReturnValue(new Promise(() => {}))
    renderPage()
    expect(screen.getByText('General').closest('span')).toBeTruthy()
    expect(screen.queryByRole('tab', { name: 'General' })).toBeNull()
    const layout = document.querySelector('.settings-layout') as HTMLElement
    expect(within(layout).getAllByRole('generic').length).toBeGreaterThan(0)
    // Two: Data retention, then Account security (PROJECT.md, 2026-10-14) —
    // General held retention AND a demo-data panel until PROJECT.md D14
    // removed the latter, then just retention alone until Account security
    // joined it. The skeleton has to track the real shape or it reintroduces
    // the layout jump it exists to prevent.
    expect(document.querySelectorAll('.settings-panel').length).toBe(2)
  })

  it('matches the skeleton panel count to the section requested via ?section=', async () => {
    mockGetSettings.mockReturnValue(new Promise(() => {}))
    renderPage('general')
    expect(document.querySelectorAll('.settings-panel').length).toBe(2)
  })

  // Live QA 2026-10-11: a viewer opening Roles & access, Single sign-on or AI
  // tools & tokens was shown "You don't have access to view or change these
  // settings" — the answer to GET /admin/settings, which none of those
  // sections reads — after waiting through its retries.
  it('sections that do not read organisation settings never request them, and render despite a settings 403', async () => {
    mockGetSettings.mockRejectedValue(new ApiError('Forbidden', 403, 'missing org:settings:write'))
    mockGetRoles.mockResolvedValue(rolesFixture())
    renderPage('access')
    expect(await screen.findByText('Super-admin')).toBeTruthy()
    expect(mockGetSettings).not.toHaveBeenCalled()
    expect(screen.queryByText(/You don't have access to view or change these settings/)).toBeNull()
  })

  it('a 403 on GET settings shows the missing-capability banner but keeps the nav usable', async () => {
    mockGetSettings.mockRejectedValue(new ApiError('Forbidden', 403, 'missing org:settings:write'))
    renderPage()
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(new RegExp(CAP_ORG_SETTINGS_WRITE))
    expect(screen.getByRole('tab', { name: 'Detectors' })).toBeTruthy()
  })

  it('a non-403 error renders the hub error message directly, replacing the whole page', async () => {
    mockGetSettings.mockRejectedValue(new ApiError('Request failed', 500, 'the settings service is unreachable'))
    renderPage()
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/Request failed/)
    expect(alert.textContent).toMatch(/the settings service is unreachable/)
    expect(screen.queryByRole('tab', { name: 'Detectors' })).toBeNull()
  })

  it('D7d: on a 403, the Git repositories section still works via its own repo:read/repo:write gate', async () => {
    mockGetSettings.mockRejectedValue(new ApiError('Forbidden', 403, 'missing org:settings:write'))
    mockGetRepositories.mockResolvedValue(repositoriesResponse())
    renderPage('repositories')
    expect(await screen.findByRole('heading', { name: 'Git repositories' })).toBeTruthy()
    expect(screen.queryByText(new RegExp(CAP_ORG_SETTINGS_WRITE))).toBeNull()
  })

  it('D7d: on a 403 with no repo:read either, Git repositories shows its own distinct warning instead of the generic one', async () => {
    capabilities.delete(CAP_REPO_READ)
    mockGetSettings.mockRejectedValue(new ApiError('Forbidden', 403, 'missing org:settings:write'))
    renderPage('repositories')
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(new RegExp(CAP_REPO_READ))
    expect(mockGetRepositories).not.toHaveBeenCalled()
  })
})

describe('SettingsPage — every section is reachable by clicking', () => {
  // SETTINGS_GROUPS, not SETTINGS_SECTIONS, is what the nav renders. A section
  // added to the latter alone gets a label, a panel and a skeleton entry that
  // nothing can navigate to — the file says so in a comment, and it has now
  // happened twice: once for Appearance, once for Single sign-on. A comment
  // did not stop the second one, so this is a test.
  it('renders a nav entry for Single sign-on, not just a URL that works', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage()
    await screen.findByText('Data retention')
    expect(screen.getByRole('tab', { name: /Single sign-on/i })).toBeTruthy()
  })

  // PROJECT.md T18 — the same trap this describe block already guards
  // against for Single sign-on: SETTINGS_SECTIONS alone would give
  // Diagnostics a label, a panel and a skeleton entry with no nav link to
  // reach it. This clicks the tab, the same way a real user would, rather
  // than only asserting on ?section=diagnostics working.
  it('renders a nav entry for Diagnostics, and clicking it reaches the panel', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage()
    await screen.findByText('Data retention')
    const tab = screen.getByRole('tab', { name: /Diagnostics/i })
    expect(tab).toBeTruthy()
    fireEvent.click(tab)
    expect(await screen.findByRole('heading', { name: 'Diagnostics bundle' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Download diagnostics bundle' })).toBeTruthy()
  })

  // PROJECT.md AD3: personal, so reachable by clicking AND still there when
  // the viewer cannot read organisation settings at all — a person must always
  // be able to see and revoke their own tokens.
  it('AI tools & tokens is reachable from the nav, and survives a 403 on organisation settings', async () => {
    mockListPersonalTokens.mockResolvedValue({ tokens: [], defaultDays: 90, maxDays: 365, maxActive: 20 })
    mockGetSettings.mockResolvedValue(baseSettings())
    const { unmount } = renderPage()
    await screen.findByText('Data retention')
    fireEvent.click(screen.getByRole('tab', { name: /AI tools & tokens/i }))
    expect(await screen.findByRole('heading', { name: 'Personal access tokens' })).toBeTruthy()
    unmount()

    mockGetSettings.mockRejectedValue(new ApiError('Forbidden', 403, 'missing org:settings:write'))
    renderPage('ai-tools')
    expect(await screen.findByRole('heading', { name: 'Personal access tokens' })).toBeTruthy()
    expect(screen.queryByText(new RegExp(CAP_ORG_SETTINGS_WRITE))).toBeNull()
  })
})

describe('SettingsPage — legacy ?section= aliases and nav', () => {
  it('maps the old "ai" alias to the Investigation section', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('ai')
    expect(await screen.findByRole('tab', { name: 'Investigation', selected: true })).toBeTruthy()
    expect(screen.getByText('Investigation bounds')).toBeTruthy()
  })

  it('the Automation section holds unattended execution and the auto-approval policy, not Investigation', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('automation')
    expect(await screen.findByRole('tab', { name: 'Automation', selected: true })).toBeTruthy()
    expect(screen.getByText('Unattended execution')).toBeTruthy()
    expect(screen.getByText('Auto-approval policy')).toBeTruthy()
    expect(screen.queryByText('Investigation bounds')).toBeNull()
  })

  it('maps the old "operations" alias to the Detectors section', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('operations')
    expect(await screen.findByRole('tab', { name: 'Detectors', selected: true })).toBeTruthy()
    expect(screen.getByText('Storm protection')).toBeTruthy()
  })

  it('an unrecognized ?section= value falls back to General rather than erroring', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('nonsense')
    expect(await screen.findByRole('tab', { name: 'General', selected: true })).toBeTruthy()
  })

  it('clicking a nav tab switches the visible section', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage()
    await screen.findByText('Data retention')
    fireEvent.click(screen.getByRole('tab', { name: 'Notifications' }))
    expect(await screen.findByText('Notification webhook URL', { exact: false })).toBeTruthy()
    expect(screen.queryByText('Data retention')).toBeNull()
  })

  it('only sections backed by the page-level form show the Save bar', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('access')
    await screen.findByText('Builtin roles')
    expect(screen.queryByRole('button', { name: /Save settings/i })).toBeNull()
  })
})

describe('SettingsPage — General section', () => {
  it('retention fields default to "Keep forever", and General offers nothing else', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage()
    await screen.findByText('Data retention')
    expect(screen.getAllByPlaceholderText('Keep forever')).toHaveLength(3)
    // PROJECT.md D14: the "Demo data" panel that used to sit here is gone from
    // the product entirely, not merely relocated.
    expect(screen.queryByRole('button', { name: /sample data/i })).toBeNull()
    expect(screen.queryByText(/Demo data/i)).toBeNull()
  })

  it('disables retention inputs with the missing-capability reason when the actor lacks org:settings:write', async () => {
    capabilities.delete(CAP_ORG_SETTINGS_WRITE)
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage()
    await screen.findByText('Data retention')
    const auditInput = screen.getByLabelText(/Audit log/i, { selector: 'input' })
    expect(auditInput).toHaveProperty('disabled', true)
    expect(auditInput.title).toMatch(new RegExp(CAP_ORG_SETTINGS_WRITE))
  })

  it('a real save round trip: only the edited (retention) section is sent, and the saved state clears', async () => {
    mockGetSettings
      .mockResolvedValueOnce(baseSettings())
      .mockResolvedValueOnce(settingsFixture({ retention: { auditRetentionDays: 30 } }))
    mockUpdateSettings.mockResolvedValue(settingsFixture({ retention: { auditRetentionDays: 30 } }))
    renderPage()
    await screen.findByText('Data retention')

    fireEvent.change(screen.getByLabelText(/Audit log/i, { selector: 'input' }), { target: { value: '30' } })
    expect(await screen.findByText('Unsaved changes')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: /^Save settings$/i }))

    await waitFor(() =>
      expect(mockUpdateSettings).toHaveBeenCalledWith(
        { retention: { auditRetentionDays: 30, incidentRetentionDays: null, findingRetentionDays: null } },
        'test-token',
      ),
    )
    expect(await screen.findByText('Settings saved.')).toBeTruthy()
    await waitFor(() => expect(screen.getByLabelText(/Audit log/i, { selector: 'input' })).toHaveProperty('value', '30'))
  })

  // Segmented (web/src/components/SplitBar.tsx) renders <button onClick>, not
  // a form input — a button click never fires a native `change` event, so it
  // never bubbles to this page's <form onChange={() => markDirty(...)}>
  // convention the way every native <input>/<select> field does. Clicking
  // "30 days" here silently leaving Save disabled was a real, shipped bug
  // (PROJECT.md, 2026-10-14) until the Overview-window Segmented usage
  // started calling markDirty('appearance') explicitly in its own onChange.
  it('choosing a different Overview default window enables Save', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('appearance')
    await screen.findByText('Overview default window')

    fireEvent.click(screen.getByRole('button', { name: '30 days' }))

    expect(await screen.findByText('Unsaved changes')).toBeTruthy()
    expect((screen.getByRole('button', { name: /^Save settings$/i }) as HTMLButtonElement).disabled).toBe(false)
  })

})

describe('SettingsPage — Detectors section', () => {
  it('renders each detector checkbox unchecked (enabled) by default, with its description', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('detectors')
    await screen.findByText('Storm protection')
    expect(screen.getByText(/Every Warning-type Kubernetes Event, cluster-wide\./)).toBeTruthy()
    const sweepCheckbox = screen.getByLabelText(/Disable "Sweep detector/i) as HTMLInputElement
    expect(sweepCheckbox.checked).toBe(false)
  })

  it('a previously-disabled detector shows checked, with the "disabled" badge', async () => {
    mockGetSettings.mockResolvedValue(settingsFixture({ detection: { disabledDetectorIds: ['k8s-sweep'] } }))
    renderPage('detectors')
    const sweepCheckbox = (await screen.findByLabelText(/Disable "Sweep detector/i)) as HTMLInputElement
    expect(sweepCheckbox.checked).toBe(true)
    expect(within(sweepCheckbox.closest('.checkbox-row') as HTMLElement).getByText('disabled')).toBeTruthy()
  })

  it('disables every detector checkbox and the preview button with the missing-capability reason when read-only', async () => {
    capabilities.delete(CAP_ORG_SETTINGS_WRITE)
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('detectors')
    const sweepCheckbox = await screen.findByLabelText(/Disable "Sweep detector/i)
    expect(sweepCheckbox).toHaveProperty('disabled', true)
    const previewButton = screen.getByRole('button', { name: /Preview against history/i })
    expect(previewButton).toHaveProperty('disabled', true)
    expect(previewButton.title).toMatch(new RegExp(CAP_ORG_SETTINGS_WRITE))
  })

  it('"Preview against history" sends the currently-entered, unsaved form values and renders the real result', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockDryRunDetectionSettings.mockResolvedValue(
      dryRunResponse({
        stormProtection: {
          candidateConfigured: true,
          eligibleOpportunities: 40,
          actual: { createdCount: 30, suppressedCount: 10 },
          candidate: { createdCount: 25, suppressedCount: 15 },
          newlySuppressedCount: 3,
          newlyAllowedCount: 2,
          byClusterDetector: [],
        },
      }),
    )
    renderPage('detectors')
    await screen.findByText('Storm protection')

    fireEvent.click(screen.getByLabelText(/Disable "Sweep detector/i))
    fireEvent.change(screen.getByLabelText(/Max new incidents per cluster/i), { target: { value: '5' } })
    fireEvent.change(screen.getByLabelText(/Rolling window \(seconds\)/i, { selector: 'input' }), { target: { value: '300' } })

    fireEvent.click(screen.getByRole('button', { name: /Preview against history/i }))

    await waitFor(() =>
      expect(mockDryRunDetectionSettings).toHaveBeenCalledWith(
        {
          disabledDetectorIds: ['k8s-sweep'],
          stormProtectionMaxNewIncidents: 5,
          stormProtectionWindowSeconds: 300,
          // Always [] here — the dry-run replay doesn't simulate the
          // rule-level control (BUGS.md 111), so this request deliberately
          // never carries whatever is checked in the Rules list above; see
          // UpdateDetectionSettingsRequest's own doc comment.
          disabledRuleIds: [],
        },
        'test-token',
      ),
    )
    expect(await screen.findByText(/would have been suppressed instead/)).toBeTruthy()
    expect(screen.getByText(/that were actually suppressed would have/)).toBeTruthy()
  })

  it('a dry-run failure renders the hub error rather than a stale or blank result', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockDryRunDetectionSettings.mockRejectedValue(new ApiError('Dry run failed', 500, 'no history available'))
    renderPage('detectors')
    await screen.findByText('Storm protection')
    fireEvent.click(screen.getByRole('button', { name: /Preview against history/i }))
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/Dry run failed/)
    expect(alert.textContent).toMatch(/no history available/)
  })

  // BUGS.md 111: the rule-level control, alongside the detector-level tests
  // above — same shape, same assertions, just over RULE_IDS/disabledRuleIds
  // instead of DETECTOR_OPTIONS/disabledDetectorIds.
  it('renders each rule checkbox unchecked (enabled) by default', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('detectors')
    await screen.findByText('Storm protection')
    const pdbCheckbox = screen.getByLabelText(/Disable pdb-blocks-all-disruptions/i) as HTMLInputElement
    expect(pdbCheckbox.checked).toBe(false)
  })

  it('a previously-disabled rule shows checked, with the "disabled" badge', async () => {
    mockGetSettings.mockResolvedValue(settingsFixture({ detection: { disabledRuleIds: ['pdb-blocks-all-disruptions'] } }))
    renderPage('detectors')
    const pdbCheckbox = (await screen.findByLabelText(/Disable pdb-blocks-all-disruptions/i)) as HTMLInputElement
    expect(pdbCheckbox.checked).toBe(true)
    expect(within(pdbCheckbox.closest('.checkbox-row') as HTMLElement).getByText('disabled')).toBeTruthy()
  })

  it('disables every rule checkbox with the missing-capability reason when read-only, but leaves the filter usable', async () => {
    capabilities.delete(CAP_ORG_SETTINGS_WRITE)
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('detectors')
    const pdbCheckbox = await screen.findByLabelText(/Disable pdb-blocks-all-disruptions/i)
    expect(pdbCheckbox).toHaveProperty('disabled', true)
    // The filter is not a setting — a read-only viewer must still be able to
    // browse the full rule list, not just the three detectors.
    const filterInput = screen.getByPlaceholderText('Filter rules by id')
    expect(filterInput).toHaveProperty('disabled', false)
  })

  it('filtering narrows the rendered rule list by id substring, and a non-matching filter shows a distinct empty state', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('detectors')
    await screen.findByText('Storm protection')
    expect(screen.getByLabelText(/Disable pdb-blocks-all-disruptions/i)).toBeTruthy()
    expect(screen.getByLabelText(/Disable hpa-pegged-at-max-replicas/i)).toBeTruthy()

    fireEvent.change(screen.getByPlaceholderText('Filter rules by id'), { target: { value: 'hpa' } })

    expect(screen.queryByLabelText(/Disable pdb-blocks-all-disruptions/i)).toBeNull()
    expect(screen.getByLabelText(/Disable hpa-pegged-at-max-replicas/i)).toBeTruthy()

    fireEvent.change(screen.getByPlaceholderText('Filter rules by id'), { target: { value: 'not-a-real-rule' } })
    expect(screen.getByText(/No rules match .*not-a-real-rule.*\./)).toBeTruthy()
  })

  it('a real save round trip sends disabledRuleIds alongside disabledDetectorIds in the same "detection" section', async () => {
    mockGetSettings
      .mockResolvedValueOnce(baseSettings())
      .mockResolvedValueOnce(settingsFixture({ detection: { disabledRuleIds: ['pdb-blocks-all-disruptions'] } }))
    mockUpdateSettings.mockResolvedValue(settingsFixture({ detection: { disabledRuleIds: ['pdb-blocks-all-disruptions'] } }))
    renderPage('detectors')
    await screen.findByText('Storm protection')

    fireEvent.click(screen.getByLabelText(/Disable pdb-blocks-all-disruptions/i))
    fireEvent.click(screen.getByRole('button', { name: /^Save settings$/i }))

    await waitFor(() =>
      expect(mockUpdateSettings).toHaveBeenCalledWith(
        {
          detection: {
            disabledDetectorIds: [],
            stormProtectionMaxNewIncidents: null,
            stormProtectionWindowSeconds: null,
            disabledRuleIds: ['pdb-blocks-all-disruptions'],
          },
        },
        'test-token',
      ),
    )
    expect(await screen.findByText('Settings saved.')).toBeTruthy()
  })
})

describe('SettingsPage — Investigation section (bounds, automatic investigation, auto-approval)', () => {
  it('shows the effective iteration/time-limit values as placeholders and in the hint', async () => {
    mockGetSettings.mockResolvedValue(settingsFixture({ analysis: { effectiveMaxIterations: 15, effectiveTimeLimitSeconds: 300 } }))
    renderPage('analysis')
    await screen.findByText('Investigation bounds')
    expect(screen.getByPlaceholderText('Default: 15')).toBeTruthy()
    const effective = document.querySelector('.settings-effective') as HTMLElement
    expect(within(effective).getByText('15')).toBeTruthy()
    expect(within(effective).getByText('300s')).toBeTruthy()
  })

  it('toggling automatic investigation on reveals the severity checklist and its own hint text', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('analysis')
    await screen.findByText('Automatic investigation')
    expect(screen.getByText(/Turn on automatic investigation above to choose/)).toBeTruthy()

    fireEvent.click(screen.getByLabelText(/Automatically investigate new incidents/i))
    expect(screen.getByText(/No severities are checked, so no incident is investigated automatically yet/)).toBeTruthy()

    fireEvent.click(screen.getByLabelText('High'))
    fireEvent.click(screen.getByLabelText('Critical'))
    expect(
      screen.getByText(/Only incidents with severity "high" or "critical" are investigated automatically/),
    ).toBeTruthy()
  })

  it('shows the unbounded-cost warning only once automation is on, naming which caps are missing', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('analysis')
    await screen.findByText('Automatic investigation')
    expect(screen.queryByText(/its cost is not bounded/)).toBeNull()

    fireEvent.click(screen.getByLabelText(/Automatically investigate new incidents/i))
    expect(await screen.findByText(/its cost is not bounded/)).toBeTruthy()
    expect(screen.getByText(/No daily spend ceiling\./)).toBeTruthy()
    expect(screen.getByText(/Storm protection is off\./)).toBeTruthy()
  })

  it('the auto-approval risk dropdown and reversibility toggle reflect saved state and effective values', async () => {
    mockGetSettings.mockResolvedValue(
      settingsFixture({
        autonomy: {
          autoApproveMaxRisk: 'medium',
          requireReversibleForAutoApprove: false,
          effectiveAutoApproveMaxRisk: 'medium',
          effectiveMinConfidenceForAutoApprove: 0.8,
        },
      }),
    )
    renderPage('automation')
    await screen.findByText('Auto-approval policy')
    expect(screen.getByLabelText(/Maximum risk/i, { selector: 'select' })).toHaveProperty('value', 'medium')
    expect(screen.getByText('not required')).toBeTruthy()
    const effective = Array.from(document.querySelectorAll('.settings-effective')).find((el) => /Max risk/.test(el.textContent ?? '')) as HTMLElement
    expect(within(effective).getByText('medium')).toBeTruthy()
    expect(within(effective).getByText('0.8')).toBeTruthy()
  })

  it('unattended execution off shows the reassuring banner; on shows the unsupervised-change warning', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('automation')
    await screen.findByText('Auto-approval policy')
    expect(screen.getByText(/Nothing here executes anything\./)).toBeTruthy()

    fireEvent.click(screen.getByLabelText(/Execute auto-approved plans without waiting/i))
    expect(await screen.findByText(/ARGUS can change your clusters with nobody/)).toBeTruthy()
    expect(screen.queryByText(/Nothing here executes anything\./)).toBeNull()
  })

  it('a real save round trip sends the whole autonomy section, including the seconds-from-minutes conversion', async () => {
    mockGetSettings
      .mockResolvedValueOnce(settingsFixture({ autonomy: { unattendedWindowSeconds: 600 } }))
      .mockResolvedValueOnce(settingsFixture({ autonomy: { unattendedWindowSeconds: 600, requireReversibleForAutoApprove: false } }))
    mockUpdateSettings.mockResolvedValue(settingsFixture({ autonomy: { unattendedWindowSeconds: 600, requireReversibleForAutoApprove: false } }))
    renderPage('automation')
    await screen.findByText('Auto-approval policy')
    expect(screen.getByLabelText(/Window \(minutes\)/i, { selector: 'input' })).toHaveProperty('value', '10')

    fireEvent.click(screen.getByLabelText(/Require the plan to be reversible/i))
    fireEvent.click(screen.getByRole('button', { name: /^Save settings$/i }))

    await waitFor(() =>
      expect(mockUpdateSettings).toHaveBeenCalledWith(
        {
          autonomy: {
            autoApproveMaxRisk: null,
            minConfidenceForAutoApprove: null,
            requireReversibleForAutoApprove: false,
            unattendedExecutionEnabled: false,
            maxUnattendedPerCluster: null,
            maxUnattendedFleetWide: null,
            unattendedWindowSeconds: 600,
          },
        },
        'test-token',
      ),
    )
  })

  it('renders the real AutomationWindowsCard and CircuitBreakerCard beneath the autonomy form', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetAutomationWindows.mockResolvedValue(
      automationWindowsResponse([
        {
          id: 'win_1',
          kind: 'freeze',
          schedule: '0 0 25 12 *',
          durationSeconds: 86400,
          upcoming: [],
          timezone: 'UTC',
          reason: 'December change freeze',
          createdAt: '2026-01-01T00:00:00Z',
          openNow: false,
        },
      ]),
    )
    mockGetCircuitBreaker.mockResolvedValue(circuitBreakerResponse())
    renderPage('automation')
    expect(await screen.findByText('Maintenance and freeze windows')).toBeTruthy()
    expect(await screen.findByText('December change freeze')).toBeTruthy()
    expect(screen.getByText('Circuit breaker')).toBeTruthy()
  })

  it('disables the whole autonomy form, including AutomationWindowsCard/CircuitBreakerCard controls, when read-only', async () => {
    capabilities.delete(CAP_ORG_SETTINGS_WRITE)
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('automation')
    await screen.findByText('Maintenance and freeze windows')
    expect(screen.getByLabelText(/Maximum risk/i, { selector: 'select' })).toHaveProperty('disabled', true)
    const addWindowButton = screen.getAllByRole('button').find((b) => /add/i.test(b.textContent ?? ''))
    if (addWindowButton) expect(addWindowButton).toHaveProperty('disabled', true)
  })
})

describe('SettingsPage — AI providers section', () => {
  it('the AIProvidersCard fetch is disabled and a plain message shown when read-only', async () => {
    capabilities.delete(CAP_ORG_SETTINGS_WRITE)
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('providers')
    // The message is a sentence now (PROJECT.md item 13: human wording for a
    // missing capability), but it still NAMES the raw capability — that is what
    // a support request has to ask for, so the constant stays assertable.
    expect(await screen.findByText(new RegExp(`do not have permission[\\s\\S]*${CAP_ORG_SETTINGS_WRITE}`))).toBeTruthy()
    expect(mockGetAIProviders).not.toHaveBeenCalled()
  })

  it('shows the empty state when no provider is configured', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetAIProviders.mockResolvedValue(providersResponse([]))
    renderPage('providers')
    expect(await screen.findByText('No providers configured')).toBeTruthy()
  })

  it('renders a configured provider with its active/inactive badge', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetAIProviders.mockResolvedValue(providersResponse([aiProvider({ id: 'prov_1', name: 'prod-claude', active: true })]))
    renderPage('providers')
    await screen.findByText('prod-claude')
    expect(within(screen.getByText('prod-claude').closest('li') as HTMLElement).getByText('active')).toBeTruthy()
  })

  it('SettingsPage-specific wiring: warns when the active provider is a CLI kind but this hub has no CLI backend', async () => {
    mockGetSettings.mockResolvedValue(settingsFixture({ llm: { cliBackendAvailable: false } }))
    mockGetAIProviders.mockResolvedValue(
      providersResponse([aiProvider({ id: 'prov_cli', name: 'cli-runner', kind: 'cli', active: true })]),
    )
    renderPage('providers')
    expect(await screen.findByText(/The active provider cannot run on this hub\./)).toBeTruthy()
  })

  it('shows no such warning when the CLI backend is available', async () => {
    mockGetSettings.mockResolvedValue(settingsFixture({ llm: { cliBackendAvailable: true } }))
    mockGetAIProviders.mockResolvedValue(
      providersResponse([aiProvider({ id: 'prov_cli', name: 'cli-runner', kind: 'cli', active: true })]),
    )
    renderPage('providers')
    await screen.findByText('cli-runner')
    expect(screen.queryByText(/cannot run on this hub/)).toBeNull()
  })

  it('an AI providers fetch failure renders the card error, not a silent empty list', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetAIProviders.mockRejectedValue(new ApiError('Request failed', 500, ''))
    renderPage('providers')
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/Could not load AI providers\./)
    expect(screen.queryByText('No providers configured')).toBeNull()
  })
})

describe('SettingsPage — Model pricing section', () => {
  it('shows the unconfigured banner and an honest $0.0000 today figure with no ceiling', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('pricing')
    await screen.findByText('LLM pricing')
    expect(screen.getByText(/No pricing configured — this is the current, unconfigured state\./)).toBeTruthy()
    expect(screen.getByText(/not measured, no price table configured/)).toBeTruthy()
  })

  it('shows the configured banner, a real spend figure, and the ceiling badge', async () => {
    mockGetSettings.mockResolvedValue(
      settingsFixture({
        cost: {
          pricingConfigured: true,
          pricePerMillionInputTokens: 3,
          pricePerMillionCachedTokens: 0.3,
          pricePerMillionOutputTokens: 15,
          todaySpendUsd: 12.3456,
          dailySpendCeilingUsd: 50,
          // Both server-computed (internal/api/settings.go's costSettingsView):
          // an api-backed provider with pricing and a ceiling set is the one
          // combination in which the ceiling is a working control.
          ceilingEnforceable: true,
        },
      }),
    )
    renderPage('pricing')
    await screen.findByText('LLM pricing')
    expect(screen.getByText(/Pricing is configured\./)).toBeTruthy()
    expect(screen.getByText(/\$12\.3456/)).toBeTruthy()
    expect(screen.getByText('under ceiling')).toBeTruthy()
  })

  it('shows "ceiling reached" once today\'s spend meets the configured ceiling', async () => {
    mockGetSettings.mockResolvedValue(
      // ceilingBreached is the hub's own SpendCeilingBreached answer, not a
      // comparison this screen redoes — see CostSettings' doc comment.
      settingsFixture({
        cost: {
          pricingConfigured: true,
          todaySpendUsd: 50,
          dailySpendCeilingUsd: 50,
          ceilingEnforceable: true,
          ceilingBreached: true,
        },
      }),
    )
    renderPage('pricing')
    expect(await screen.findByText('ceiling reached')).toBeTruthy()
  })

  it('warns the ceiling cannot be reached under providerKind "cli" once a ceiling is set', async () => {
    mockGetSettings.mockResolvedValue(
      settingsFixture({
        llm: { providerKind: 'cli' },
        // spendCountable is what the hub actually sends for a cli provider,
        // and is now what gates the notice — see the notice's own comment.
        cost: { pricingConfigured: true, spendCountable: false, dailySpendCeilingUsd: 50 },
      }),
    )
    renderPage('pricing')
    await screen.findByText('LLM pricing')
    expect(screen.getByText(/This ceiling can't actually be reached right now\./)).toBeTruthy()
  })

  it('does not warn about providerKind "cli" when no ceiling is configured', async () => {
    mockGetSettings.mockResolvedValue(
      settingsFixture({
        llm: { providerKind: 'cli' },
        cost: { pricingConfigured: true, spendCountable: false, dailySpendCeilingUsd: null },
      }),
    )
    renderPage('pricing')
    await screen.findByText('LLM pricing')
    expect(screen.queryByText(/This ceiling can't actually be reached right now\./)).toBeNull()
  })

  it('does not warn about providerKind "cli" for an "api" provider even with a ceiling set', async () => {
    mockGetSettings.mockResolvedValue(
      settingsFixture({
        llm: { providerKind: 'api' },
        cost: { pricingConfigured: true, spendCountable: true, dailySpendCeilingUsd: 50, ceilingEnforceable: true },
      }),
    )
    renderPage('pricing')
    await screen.findByText('LLM pricing')
    expect(screen.queryByText(/This ceiling can't actually be reached right now\./)).toBeNull()
  })

  // PROJECT.md T8. The prose notice above has been right for a while; what was
  // wrong is everything around it. The ceiling input carried no state at all,
  // and the figure beside it wore a green "under ceiling" — a claim that a
  // guardrail is holding, made on a deployment where it cannot fire. Per
  // anti-patterns.md "One fact, one claim", the reader resolves that pair in
  // favour of the green, so the notice was being overruled by the badge
  // directly above it.
  it('does not badge a ceiling "under ceiling" when the ceiling cannot be enforced', async () => {
    mockGetSettings.mockResolvedValue(
      settingsFixture({
        llm: { providerKind: 'cli' },
        cost: {
          pricingConfigured: true,
          spendCountable: false,
          dailySpendCeilingUsd: 50,
          ceilingEnforceable: false,
        },
      }),
    )
    renderPage('pricing')
    await screen.findByText('LLM pricing')
    expect(screen.queryByText('under ceiling')).toBeNull()
    expect(screen.getByText('not enforced')).toBeTruthy()
  })

  it('reports the ceiling input as not enforced, and why, on the control itself', async () => {
    mockGetSettings.mockResolvedValue(
      settingsFixture({
        llm: { providerKind: 'cli' },
        cost: {
          pricingConfigured: true,
          spendCountable: false,
          dailySpendCeilingUsd: 50,
          ceilingEnforceable: false,
        },
      }),
    )
    renderPage('pricing')
    await screen.findByText('LLM pricing')
    expect(screen.getByText('not enforced — provider spend not measured')).toBeTruthy()
  })

  it('badges the ceiling input "enforced" only where it actually is', async () => {
    mockGetSettings.mockResolvedValue(
      settingsFixture({
        cost: {
          pricingConfigured: true,
          spendCountable: true,
          dailySpendCeilingUsd: 50,
          ceilingEnforceable: true,
        },
      }),
    )
    renderPage('pricing')
    await screen.findByText('LLM pricing')
    expect(screen.getByText('enforced')).toBeTruthy()
  })

  it('names the missing price table on the control when that is the reason', async () => {
    mockGetSettings.mockResolvedValue(
      settingsFixture({ cost: { pricingConfigured: false, spendCountable: true, dailySpendCeilingUsd: 50 } }),
    )
    renderPage('pricing')
    await screen.findByText('LLM pricing')
    expect(screen.getByText('not enforced — no price table')).toBeTruthy()
  })

  // Not '$0.0000'. todaySpendUsd is the sum of cost_basis='metered' rows, so
  // on a subscription provider it is zero while real investigations ran, and
  // the sentence it sits in calls it "real spend".
  it('reports today\'s figure as not measured on a subscription provider, never as a dollar amount', async () => {
    mockGetSettings.mockResolvedValue(
      settingsFixture({
        llm: { providerKind: 'cli' },
        cost: { pricingConfigured: true, spendCountable: false, todaySpendUsd: 0 },
      }),
    )
    renderPage('pricing')
    await screen.findByText('LLM pricing')
    expect(screen.getByText(/not measured, the active provider bills by subscription/)).toBeTruthy()
    expect(screen.queryByText(/\$0\.0000/)).toBeNull()
  })

  it('a real save round trip sends all three price fields together plus the ceiling', async () => {
    mockGetSettings
      .mockResolvedValueOnce(baseSettings())
      .mockResolvedValueOnce(settingsFixture({ cost: { pricingConfigured: true } }))
    mockUpdateSettings.mockResolvedValue(settingsFixture({ cost: { pricingConfigured: true } }))
    renderPage('pricing')
    await screen.findByText('LLM pricing')

    fireEvent.change(screen.getByLabelText(/^Input tokens/i, { selector: 'input' }), { target: { value: '3' } })
    fireEvent.change(screen.getByLabelText(/Cached-read input tokens/i, { selector: 'input' }), { target: { value: '0.3' } })
    fireEvent.change(screen.getByLabelText(/Output tokens/i, { selector: 'input' }), { target: { value: '15' } })
    fireEvent.change(screen.getByLabelText(/Daily spend ceiling/i, { selector: 'input' }), { target: { value: '25' } })
    fireEvent.click(screen.getByRole('button', { name: /^Save settings$/i }))

    await waitFor(() =>
      expect(mockUpdateSettings).toHaveBeenCalledWith(
        {
          cost: {
            pricePerMillionInputTokens: 3,
            pricePerMillionCachedTokens: 0.3,
            pricePerMillionOutputTokens: 15,
            dailySpendCeilingUsd: 25,
          },
        },
        'test-token',
      ),
    )
  })

  it('a save rejected by the hub (e.g. a partial price table) renders the real detail, not a generic fallback', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockUpdateSettings.mockRejectedValue(new ApiError('Invalid settings', 400, 'all three price fields must be set together'))
    renderPage('pricing')
    await screen.findByText('LLM pricing')
    fireEvent.change(screen.getByLabelText(/^Input tokens/i, { selector: 'input' }), { target: { value: '3' } })
    fireEvent.click(screen.getByRole('button', { name: /^Save settings$/i }))
    expect(await screen.findByText(/Invalid settings — all three price fields must be set together/)).toBeTruthy()
  })
})

describe('SettingsPage — Git repositories section (happy path)', () => {
  it('renders the real RepositoriesCard and its capability-gated Add button', async () => {
    capabilities.delete(CAP_REPO_WRITE)
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetRepositories.mockResolvedValue(repositoriesResponse())
    renderPage('repositories')
    await screen.findByRole('heading', { name: 'Git repositories' })
    const addButton = screen.getByRole('button', { name: /Add repository/i })
    expect(addButton).toHaveProperty('disabled', true)
    expect(addButton.title).toMatch(new RegExp(CAP_REPO_WRITE))
  })

  it('no Save bar is shown, since every change goes through the repository dialog', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('repositories')
    await screen.findByRole('heading', { name: 'Git repositories' })
    expect(screen.queryByRole('button', { name: /Save settings/i })).toBeNull()
  })
})

describe('SettingsPage — Notifications section', () => {
  it('offers "Clear the webhook URL" only when a webhook is set — there is nothing to clear otherwise', async () => {
    mockGetSettings.mockResolvedValue(settingsFixture({ notify: { webhookConfigured: false } }))
    renderPage('notifications')
    await screen.findByText('not configured')
    expect(screen.queryByLabelText(/Clear the webhook URL/i)).toBeNull()
    expect(screen.getByText(/No webhook is set/)).toBeTruthy()
  })

  it('the webhook input and the Clear checkbox are mutually exclusive', async () => {
    mockGetSettings.mockResolvedValue(settingsFixture({ notify: { webhookConfigured: true } }))
    renderPage('notifications')
    await screen.findByText('configured')

    fireEvent.change(screen.getByLabelText(/Notification webhook URL/i), { target: { value: 'https://hooks.example.com/x' } })
    expect(screen.getByLabelText(/Clear the webhook URL/i)).toHaveProperty('disabled', true)
  })

  it('a real save round trip sends the typed webhook URL, then resets the input on success', async () => {
    mockGetSettings
      .mockResolvedValueOnce(baseSettings())
      .mockResolvedValueOnce(settingsFixture({ notify: { webhookConfigured: true } }))
    mockUpdateSettings.mockResolvedValue(settingsFixture({ notify: { webhookConfigured: true } }))
    renderPage('notifications')
    await screen.findByRole('heading', { name: 'Notifications' })

    fireEvent.change(screen.getByLabelText(/Notification webhook URL/i), { target: { value: 'https://hooks.example.com/x' } })
    fireEvent.click(screen.getByRole('button', { name: /^Save settings$/i }))

    await waitFor(() =>
      expect(mockUpdateSettings).toHaveBeenCalledWith({ notify: { webhookUrl: 'https://hooks.example.com/x' } }, 'test-token'),
    )
    await waitFor(() => expect(screen.getByLabelText(/Notification webhook URL/i)).toHaveProperty('value', ''))
  })

  it('checking Clear sends an explicit empty webhookUrl, not an omitted one', async () => {
    mockGetSettings.mockResolvedValue(settingsFixture({ notify: { webhookConfigured: true } }))
    mockUpdateSettings.mockResolvedValue(settingsFixture({ notify: { webhookConfigured: false } }))
    renderPage('notifications')
    await screen.findByText('configured')

    fireEvent.click(screen.getByLabelText(/Clear the webhook URL/i))
    fireEvent.click(screen.getByRole('button', { name: /^Save settings$/i }))

    await waitFor(() => expect(mockUpdateSettings).toHaveBeenCalledWith({ notify: { webhookUrl: '' } }, 'test-token'))
  })
})

describe('SettingsPage — Notification routing section', () => {
  // SETTINGS_GROUPS, not SETTINGS_SECTIONS, is what the nav renders — the trap
  // this file already guards for Single sign-on, Diagnostics and Outbound
  // access. Clicked rather than reached by ?section=, for the same reason.
  it('renders a nav entry for Notification routing, and clicking it reaches the panel', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetNotificationRouting.mockResolvedValue({
      destinations: [],
      rules: [],
      defaultRule: { name: 'Default', urlConfigured: true, source: 'settings.notify.webhookUrl' },
      transitions: ['NewIncident'],
      severities: ['low', 'medium', 'high', 'critical'],
    })
    renderPage()
    await screen.findByText('Data retention')
    fireEvent.click(screen.getByRole('tab', { name: /Notification routing/i }))
    expect(await screen.findByRole('heading', { name: 'Notification routing' })).toBeTruthy()
  })

  // The section owns its own endpoint and its own Save, so the page-level
  // "Save settings" bar must stay off it — SETTINGS_SECTIONS marks it
  // form: false for exactly that reason, and two save buttons in one panel is
  // what that flag exists to prevent.
  it('does not show the page-level Save settings bar, which would have nothing to save', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetNotificationRouting.mockResolvedValue({
      destinations: [],
      rules: [],
      defaultRule: { name: 'Default', urlConfigured: true, source: 'settings.notify.webhookUrl' },
      transitions: ['NewIncident'],
      severities: ['low', 'medium', 'high', 'critical'],
    })
    renderPage('routing')
    // The loaded panel, not the skeleton — both carry the same <h2>.
    expect(await screen.findByRole('button', { name: /Save routing table/i })).toBeTruthy()
    expect(screen.queryByRole('button', { name: /^Save settings$/i })).toBeNull()
  })
})

describe('SettingsPage — Outbound access section', () => {
  // SETTINGS_GROUPS, not SETTINGS_SECTIONS, is what the nav renders — the same
  // trap this file already guards for Single sign-on and Diagnostics. Clicked,
  // not reached by ?section=, because that is the part that has broken twice.
  it('renders a nav entry for Outbound access, and clicking it reaches the panel', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage()
    await screen.findByText('Data retention')
    fireEvent.click(screen.getByRole('tab', { name: /Outbound access/i }))
    expect(await screen.findByRole('heading', { name: 'Private destinations' })).toBeTruthy()
  })

  it('an empty allowlist reads as the deliberate secure default, not as missing data', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('outbound')
    await screen.findByRole('heading', { name: 'Private destinations' })
    expect(screen.getByText(/Nothing is allowlisted, which is the default and the secure state/i)).toBeTruthy()
    // No table at all, rather than a table of zero rows claiming to be a list.
    expect(document.querySelector('.cluster-table')).toBeNull()
  })

  it('a destination cannot be added without a reason — the pair is the point', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('outbound')
    await screen.findByRole('heading', { name: 'Private destinations' })

    fireEvent.change(screen.getByLabelText(/Destination/i, { selector: 'input' }), {
      target: { value: '10.20.0.5' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Add destination/i }))

    expect((await screen.findByRole('alert')).textContent).toMatch(/does not accept a destination without one/i)
    // Nothing was staged, so there is nothing to save either.
    expect(document.querySelector('.cluster-table')).toBeNull()
    expect(screen.getByText('No unsaved changes')).toBeTruthy()
  })

  it('an added entry says it is not in effect until saved, then the whole list is sent verbatim', async () => {
    const saved = settingsFixture({
      outbound: { privateDestinations: [{ destination: '10.20.0.0/16', reason: 'self-hosted vLLM' }] },
    })
    mockGetSettings.mockResolvedValueOnce(baseSettings()).mockResolvedValueOnce(saved)
    mockUpdateSettings.mockResolvedValue(saved)
    renderPage('outbound')
    await screen.findByRole('heading', { name: 'Private destinations' })

    fireEvent.change(screen.getByLabelText(/Destination/i, { selector: 'input' }), {
      target: { value: '10.20.0.0/16' },
    })
    fireEvent.change(screen.getByLabelText(/Reason/i, { selector: 'input' }), {
      target: { value: 'self-hosted vLLM' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Add destination/i }))

    // Staged, and saying so — a security exception on screen that the hub has
    // not accepted must not read as one that is being enforced.
    expect(await screen.findByText('Not saved')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: /^Save settings$/i }))
    await waitFor(() =>
      expect(mockUpdateSettings).toHaveBeenCalledWith(
        { outbound: { privateDestinations: [{ destination: '10.20.0.0/16', reason: 'self-hosted vLLM' }] } },
        'test-token',
      ),
    )
    expect(await screen.findByText('In effect')).toBeTruthy()
  })

  it('removing the only entry keeps it visible as "Removed on save" and sends an explicit empty list', async () => {
    const withEntry = settingsFixture({
      outbound: { privateDestinations: [{ destination: '10.20.0.5', reason: 'internal registry' }] },
    })
    mockGetSettings.mockResolvedValueOnce(withEntry).mockResolvedValueOnce(baseSettings())
    mockUpdateSettings.mockResolvedValue(baseSettings())
    renderPage('outbound')
    await screen.findByText('In effect')

    fireEvent.click(screen.getByRole('button', { name: /Remove/i }))
    // Still on screen, because it is still allowed until the save lands.
    expect(await screen.findByText('Removed on save')).toBeTruthy()
    expect(screen.getByText('10.20.0.5')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: /^Save settings$/i }))
    await waitFor(() =>
      expect(mockUpdateSettings).toHaveBeenCalledWith({ outbound: { privateDestinations: [] } }, 'test-token'),
    )
  })

  it('a hostname entry carries the DNS trade where an IP entry does not', async () => {
    mockGetSettings.mockResolvedValue(
      settingsFixture({
        outbound: {
          privateDestinations: [
            { destination: 'vllm.internal.example.com', reason: 'internal model server' },
            { destination: '10.20.0.5', reason: 'internal registry' },
          ],
        },
      }),
    )
    renderPage('outbound')
    await screen.findByRole('heading', { name: 'Private destinations' })

    expect(screen.getByText('Hostname')).toBeTruthy()
    expect(screen.getByText(/trust follows DNS/i)).toBeTruthy()
    expect(screen.getByText('IP address')).toBeTruthy()
  })

  it('the trade is stated while a destination is being typed, not only after it is saved', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('outbound')
    await screen.findByRole('heading', { name: 'Private destinations' })

    const input = screen.getByLabelText(/Destination/i, { selector: 'input' })
    fireEvent.change(input, { target: { value: 'ghe.internal.example.com' } })
    expect(await screen.findByText(/permit whatever it resolves to at dial time/i)).toBeTruthy()

    fireEvent.change(input, { target: { value: '10.20.0.0/16' } })
    expect(await screen.findByText(/no DNS change can move it/i)).toBeTruthy()
  })

  it('without org:settings:write the add and remove controls are disabled and name the capability, never hidden', async () => {
    capabilities.delete(CAP_ORG_SETTINGS_WRITE)
    mockGetSettings.mockResolvedValue(
      settingsFixture({
        outbound: { privateDestinations: [{ destination: '10.20.0.5', reason: 'internal registry' }] },
      }),
    )
    renderPage('outbound')
    await screen.findByRole('heading', { name: 'Private destinations' })

    const add = screen.getByRole('button', { name: /Add destination/i })
    expect(add).toHaveProperty('disabled', true)
    expect(add.title).toMatch(new RegExp(CAP_ORG_SETTINGS_WRITE))
    const remove = screen.getByRole('button', { name: /Remove/i })
    expect(remove).toHaveProperty('disabled', true)
    expect(remove.title).toMatch(new RegExp(CAP_ORG_SETTINGS_WRITE))
  })

  it("a save the hub refuses renders the hub's own reason, not a second copy of the rules", async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    // The real 400 from PUT /api/v1/admin/settings, verbatim
    // (internal/outbound.ParseAllowlist via validateOutboundSettingsRequest).
    mockUpdateSettings.mockRejectedValue(
      new ApiError(
        'Invalid outbound.privateDestinations',
        400,
        'outbound: "169.254.0.0/16" contains the cloud metadata address 169.254.169.254, which is refused unconditionally and cannot be allowlisted — name the specific addresses you need instead',
      ),
    )
    renderPage('outbound')
    await screen.findByRole('heading', { name: 'Private destinations' })

    fireEvent.change(screen.getByLabelText(/Destination/i, { selector: 'input' }), {
      target: { value: '169.254.0.0/16' },
    })
    fireEvent.change(screen.getByLabelText(/Reason/i, { selector: 'input' }), {
      target: { value: 'link-local range' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Add destination/i }))
    fireEvent.click(screen.getByRole('button', { name: /^Save settings$/i }))

    expect(await screen.findByText(/contains the cloud metadata address 169\.254\.169\.254/)).toBeTruthy()
  })
})

describe('SettingsPage — Roles & access section', () => {
  it('shows a loading skeleton, then an error, independent of the page-level settings query', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetRoles.mockRejectedValue(new ApiError('Request failed', 500, 'roles catalogue unreachable'))
    renderPage('access')
    await screen.findByText('Builtin roles')
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/roles catalogue unreachable/)
  })

  it('renders the builtin roles as a matrix: known capabilities under their group, unknown ones under "Other"', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetRoles.mockResolvedValue(
      rolesFixture({
        viewer: { capabilities: ['incident:read', 'remediation:approve', 'totally:unknown:capability'] },
      }),
    )
    renderPage('access')
    await screen.findByText('Viewer')

    const matrix = document.querySelector('.role-matrix') as HTMLElement
    expect(within(matrix).getByText('Incidents & analysis')).toBeTruthy()
    expect(within(matrix).getByText('Remediation')).toBeTruthy()
    expect(within(matrix).getByText('Other')).toBeTruthy()
    expect(within(matrix).getByText('totally:unknown:capability')).toBeTruthy()
    // The Viewer column is the last one; its "View incidents" cell says Granted
    // in text, not only with a green tick.
    const row = within(matrix).getByText('View incidents').closest('tr') as HTMLElement
    const cells = row.querySelectorAll('td')
    expect(cells[cells.length - 1].textContent).toMatch(/^Granted$/)
    expect(within(matrix).getByText('3 capabilities')).toBeTruthy()
  })

  it('renders one column per builtin role even when a role has no capabilities at all', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetRoles.mockResolvedValue(rolesFixture())
    renderPage('access')
    await screen.findByText('Super-admin')
    expect(screen.getByText('Tenant-admin')).toBeTruthy()
    expect(screen.getByText('Resolver')).toBeTruthy()
    expect(screen.getByText('PR approver')).toBeTruthy()
    expect(screen.getByText('Viewer')).toBeTruthy()
    expect(document.querySelectorAll('.role-matrix thead th').length).toBe(6)
  })
})

// BACKLOG.md S3 — custom roles and cluster groups. Both cards live inside
// the same "Roles & access" section as the builtin-role reference above,
// each fetching its own data (CustomRolesCard/ClusterGroupsCard), matching
// RepositoriesCard's own established shape one section over.
describe('SettingsPage — Custom roles section (BACKLOG S3)', () => {
  it('shows an empty state when no custom role exists yet', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('access')
    await screen.findByText('No custom roles yet')
  })

  it('renders a custom role grouped by capability area, with its capability count', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetCustomRoles.mockResolvedValue(customRolesResponse([customRole()]))
    renderPage('access')
    await screen.findByText('on-call-viewer')
    expect(screen.getByText('2 capabilities')).toBeTruthy()
    expect(screen.getByText('Incidents & analysis')).toBeTruthy()
    expect(screen.getByText('View incidents')).toBeTruthy()
  })

  it('disables Create/Edit/Delete, each with the missing-capability reason, without role:manage', async () => {
    capabilities.delete(CAP_ROLE_MANAGE)
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetCustomRoles.mockResolvedValue(customRolesResponse([customRole()]))
    renderPage('access')
    await screen.findByText('on-call-viewer')

    const createButton = screen.getByRole('button', { name: /\+ Create role/i })
    expect(createButton).toHaveProperty('disabled', true)
    expect(createButton.title).toMatch(new RegExp(CAP_ROLE_MANAGE))

    const editButton = screen.getByRole('button', { name: 'Edit capabilities' })
    expect(editButton).toHaveProperty('disabled', true)
    const deleteButton = screen.getByRole('button', { name: 'Delete' })
    expect(deleteButton).toHaveProperty('disabled', true)
  })

  it('creating a role submits exactly the checked capabilities and refreshes the list', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockCreateCustomRole.mockResolvedValue(customRole())
    renderPage('access')
    await screen.findByText('No custom roles yet')

    fireEvent.click(screen.getByRole('button', { name: /\+ Create role/i }))
    fireEvent.change(await screen.findByLabelText('Name'), { target: { value: 'on-call-viewer' } })
    fireEvent.click(screen.getByLabelText('View incidents'))
    fireEvent.click(screen.getByRole('button', { name: 'Create role' }))

    await waitFor(() =>
      expect(mockCreateCustomRole).toHaveBeenCalledWith(
        { name: 'on-call-viewer', capabilities: ['incident:read'] },
        'test-token',
      ),
    )
  })

  it('a duplicate-name conflict from the hub is shown as a form error, not swallowed', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockCreateCustomRole.mockRejectedValue(new ApiError('Already exists', 409, 'a custom role with this name already exists'))
    renderPage('access')
    await screen.findByText('No custom roles yet')

    fireEvent.click(screen.getByRole('button', { name: /\+ Create role/i }))
    fireEvent.change(await screen.findByLabelText('Name'), { target: { value: 'dup' } })
    fireEvent.click(screen.getByLabelText('View incidents'))
    fireEvent.click(screen.getByRole('button', { name: 'Create role' }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/already exists/)
  })

  it('deleting a role asks for confirmation, then calls deleteCustomRole', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetCustomRoles.mockResolvedValue(customRolesResponse([customRole()]))
    mockDeleteCustomRole.mockResolvedValue({ roleId: 'crole_1', status: 'deleted' })
    renderPage('access')
    await screen.findByText('on-call-viewer')

    fireEvent.click(screen.getByRole('button', { name: 'Delete' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm delete' }))

    await waitFor(() => expect(mockDeleteCustomRole).toHaveBeenCalledWith('crole_1', 'test-token'))
  })
})

describe('SettingsPage — Cluster groups section (BACKLOG S3)', () => {
  it('shows an empty state when no cluster group exists yet', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('access')
    await screen.findByText('No cluster groups yet')
  })

  it('renders a group and its member cluster by real display name, not a raw id', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetClusterGroups.mockResolvedValue(clusterGroupsResponse([clusterGroup({ clusterIds: ['cl_a'] })]))
    renderPage('access')
    await screen.findByText('payments-team')
    expect(screen.getByText('rke2-prod')).toBeTruthy()
    expect(screen.queryByText('cl_a')).toBeNull()
  })

  it('disables Create group/Delete group without cluster:group:manage', async () => {
    capabilities.delete(CAP_CLUSTER_GROUP_MANAGE)
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetClusterGroups.mockResolvedValue(clusterGroupsResponse([clusterGroup()]))
    renderPage('access')
    await screen.findByText('payments-team')

    const createButton = screen.getByRole('button', { name: /\+ Create group/i })
    expect(createButton).toHaveProperty('disabled', true)
    expect(createButton.title).toMatch(new RegExp(CAP_CLUSTER_GROUP_MANAGE))
    expect(screen.getByRole('button', { name: 'Delete group' })).toHaveProperty('disabled', true)
    // The add-member control is gated the same way as every other control
    // here: disabled with the missing capability named, never hidden (a
    // whole-repo review pass, 2026-09-27, found this form conditionally
    // unrendered instead — the exact anti-pattern this test now guards
    // against rather than encodes).
    const addClusterSelect = screen.getByLabelText('Cluster to add')
    expect(addClusterSelect).toHaveProperty('disabled', true)
    expect((addClusterSelect as HTMLSelectElement).title).toMatch(new RegExp(CAP_CLUSTER_GROUP_MANAGE))
  })

  it('creating a group submits the typed name', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockCreateClusterGroup.mockResolvedValue(clusterGroup())
    renderPage('access')
    await screen.findByText('No cluster groups yet')

    fireEvent.click(screen.getByRole('button', { name: /\+ Create group/i }))
    fireEvent.change(await screen.findByLabelText('Name'), { target: { value: 'payments-team' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create group' }))

    await waitFor(() => expect(mockCreateClusterGroup).toHaveBeenCalledWith({ name: 'payments-team' }, 'test-token'))
  })

  it('adding a cluster to a group confirms (it widens access immediately) then calls addClusterToGroup', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetClusterGroups.mockResolvedValue(clusterGroupsResponse([clusterGroup()]))
    mockAddClusterToGroup.mockResolvedValue({ groupId: 'clg_1', clusterId: 'cl_a' })
    renderPage('access')
    await screen.findByText('payments-team')

    fireEvent.change(screen.getByLabelText('Cluster to add'), { target: { value: 'cl_a' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add' }))

    expect(window.confirm).toHaveBeenCalled()
    await waitFor(() => expect(mockAddClusterToGroup).toHaveBeenCalledWith('clg_1', 'cl_a', 'test-token'))
  })

  it('declining the add-cluster confirm does not call addClusterToGroup', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(false)
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetClusterGroups.mockResolvedValue(clusterGroupsResponse([clusterGroup()]))
    renderPage('access')
    await screen.findByText('payments-team')

    fireEvent.change(screen.getByLabelText('Cluster to add'), { target: { value: 'cl_a' } })
    fireEvent.click(screen.getByRole('button', { name: 'Add' }))

    expect(mockAddClusterToGroup).not.toHaveBeenCalled()
  })

  it('removing a member cluster confirms (it narrows access immediately) then calls removeClusterFromGroup', async () => {
    vi.spyOn(window, 'confirm').mockReturnValue(true)
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetClusterGroups.mockResolvedValue(clusterGroupsResponse([clusterGroup({ clusterIds: ['cl_a'] })]))
    mockRemoveClusterFromGroup.mockResolvedValue({ groupId: 'clg_1', clusterId: 'cl_a', status: 'removed' })
    renderPage('access')
    await screen.findByText('rke2-prod')

    fireEvent.click(screen.getByTitle('Remove from this group'))

    expect(window.confirm).toHaveBeenCalled()
    await waitFor(() => expect(mockRemoveClusterFromGroup).toHaveBeenCalledWith('clg_1', 'cl_a', 'test-token'))
  })

  it('a 409 in-use conflict deleting a group is shown, not swallowed', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetClusterGroups.mockResolvedValue(clusterGroupsResponse([clusterGroup()]))
    mockDeleteClusterGroup.mockRejectedValue(
      new ApiError('This group still has at least one active grant scoped to it', 409, ''),
    )
    renderPage('access')
    await screen.findByText('payments-team')

    fireEvent.click(screen.getByRole('button', { name: 'Delete group' }))
    fireEvent.click(screen.getByRole('button', { name: 'Confirm delete' }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/active grant scoped to it/)
  })
})

// PROJECT.md T18 — the diagnostics bundle download: the opt-in connectivity
// probe checkbox, the capability gate, and the pending/success/error result
// slot. mockGetDiagnosticsBundle stands in for the real hub round trip;
// diagnostics.go's own redaction/bounding is covered by the Go-side tests,
// not here — this is the UI's contract with what that endpoint returns.
describe('SettingsPage — Diagnostics bundle', () => {
  function diagnosticsBundleFixture() {
    const bundle = {
      generatedAt: '2026-09-18T00:00:00Z',
      hub: { version: '1.2.3' },
      migration: { version: 110, dirty: false, known: true },
      clusters: [{ id: 'cl_1', displayName: 'prod', state: 'Active' }],
      clustersTruncated: false,
      aiProviders: [
        {
          id: 'aip_1',
          name: 'primary',
          kind: 'api' as const,
          active: true,
          apiKeySet: true,
          runnerTokenSet: false,
          connectivityChecked: false,
        },
      ],
      aiProvidersTruncated: false,
      repositories: [],
      repositoriesTruncated: false,
      recentInternalErrors: [],
      recentInternalErrorsTruncated: false,
      probed: false,
      manifest: {
        included: ['hub version: 1.2.3'],
        omitted: [{ field: 'AI provider API keys / CLI runner tokens', reason: 'presence only' }],
        truncated: false,
        bundleSizeBytes: 512,
        maxBundleBytes: 4194304,
      },
    }
    return { bundle, raw: JSON.stringify(bundle), filename: 'argus-diagnostics_20260918T000000Z.json' }
  }

  // jsdom does not implement the Blob-URL machinery a real browser download
  // needs; stubbed here (this test file only) so the component's actual
  // save side effect can run without throwing, rather than skipped.
  beforeEach(() => {
    vi.stubGlobal('URL', {
      ...URL,
      createObjectURL: vi.fn(() => 'blob:mock'),
      revokeObjectURL: vi.fn(),
    })
  })

  it('defaults to no connectivity probe: clicking Download calls getDiagnosticsBundle with probe=false', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetDiagnosticsBundle.mockResolvedValue(diagnosticsBundleFixture())
    renderPage('diagnostics')
    await screen.findByRole('heading', { name: 'Diagnostics bundle' })

    const checkbox = screen.getByLabelText('Include live connectivity checks') as HTMLInputElement
    expect(checkbox.checked).toBe(false)
    fireEvent.click(screen.getByRole('button', { name: 'Download diagnostics bundle' }))

    await waitFor(() => expect(mockGetDiagnosticsBundle).toHaveBeenCalledWith('test-token', false))
  })

  it('checking "include live connectivity checks" sends probe=true', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetDiagnosticsBundle.mockResolvedValue(diagnosticsBundleFixture())
    renderPage('diagnostics')
    await screen.findByRole('heading', { name: 'Diagnostics bundle' })

    fireEvent.click(screen.getByLabelText('Include live connectivity checks'))
    fireEvent.click(screen.getByRole('button', { name: 'Download diagnostics bundle' }))

    await waitFor(() => expect(mockGetDiagnosticsBundle).toHaveBeenCalledWith('test-token', true))
  })

  it('a successful download shows the manifest-derived counts, not an invented summary', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetDiagnosticsBundle.mockResolvedValue(diagnosticsBundleFixture())
    renderPage('diagnostics')
    await screen.findByRole('heading', { name: 'Diagnostics bundle' })

    fireEvent.click(screen.getByRole('button', { name: 'Download diagnostics bundle' }))

    expect(await screen.findByText(/Downloaded argus-diagnostics_20260918T000000Z\.json/)).toBeTruthy()
    // Every number shown is read straight from the fixture's own bundle —
    // this is the "never invent/duplicate a count" rule from the design
    // system, checked structurally rather than just eyeballed.
    expect(screen.getByText(/1 cluster\(s\)/)).toBeTruthy()
    expect(screen.getByText(/1 AI provider\(s\)/)).toBeTruthy()
    expect(screen.getByText(/0 repository binding\(s\)/)).toBeTruthy()
    expect(screen.getByText(/512/)).toBeTruthy()
  })

  it('a failed download shows the hub error message and detail, not a generic failure', async () => {
    mockGetSettings.mockResolvedValue(baseSettings())
    mockGetDiagnosticsBundle.mockRejectedValue(
      new ApiError('Could not build the diagnostics bundle', 500, 'internal error building the bundle'),
    )
    renderPage('diagnostics')
    await screen.findByRole('heading', { name: 'Diagnostics bundle' })

    fireEvent.click(screen.getByRole('button', { name: 'Download diagnostics bundle' }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/Could not build the diagnostics bundle/)
    expect(alert.textContent).toMatch(/internal error building the bundle/)
  })

  it('without org:settings:write, the button and checkbox are disabled with the missing capability named — never hidden', async () => {
    capabilities.delete(CAP_ORG_SETTINGS_WRITE)
    mockGetSettings.mockResolvedValue(baseSettings())
    renderPage('diagnostics')

    const button = (await screen.findByRole('button', {
      name: 'Download diagnostics bundle',
    })) as HTMLButtonElement
    expect(button).toBeTruthy()
    expect(button.disabled).toBe(true)
    expect(button.title).toMatch(new RegExp(CAP_ORG_SETTINGS_WRITE))

    const checkbox = screen.getByLabelText('Include live connectivity checks') as HTMLInputElement
    expect(checkbox.disabled).toBe(true)

    expect(mockGetDiagnosticsBundle).not.toHaveBeenCalled()
  })
})
