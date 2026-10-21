import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { CAP_CLUSTER_INSPECT, CAP_CLUSTER_READ } from '../api/capabilities'

// The cluster-detail tabs (docs/CLUSTER_INSIGHT_SPECS.md CI-S5/S4/S16/S13/S14,
// CI-S11): each one's four states, and the honesty rules that are easy to
// lose — unknown is never zero, unavailable says why, partial says so.

const mockInspect = vi.fn()
const mockLatestScan = vi.fn()
const mockRunScan = vi.fn()
const mockChanges = vi.fn()
const mockFleetScans = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    inspectCluster: (...a: unknown[]) => mockInspect(...a),
    getLatestUpgradeScan: (...a: unknown[]) => mockLatestScan(...a),
    runUpgradeScan: (...a: unknown[]) => mockRunScan(...a),
    getResourceChanges: (...a: unknown[]) => mockChanges(...a),
    getFleetUpgradeScans: (...a: unknown[]) => mockFleetScans(...a),
  }
})
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 't' }) }))
const caps = new Set<string>()
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (c: string) => caps.has(c),
  useMissingCapabilities: (list: string[]) => ({ resolved: true, missing: list.filter((c) => !caps.has(c)) }),
}))
vi.mock('../graph/GraphCanvas', () => ({
  GraphCanvas: ({ label, edgeLabels }: { label: string; edgeLabels: Record<string, string> }) => (
    <div role="group" aria-label={label}>
      {Object.values(edgeLabels).join(' | ')}
    </div>
  ),
}))

import { ApiError } from '../api/client'
import { UpgradeReadinessPanel } from './UpgradeReadinessPanel'
import { PosturePanel } from './PosturePanel'
import { CertificatesPanel } from './CertificatesPanel'
import { TrafficPanel } from './TrafficPanel'
import { CostPanel } from './CostPanel'
import { AgentCoverageSection, ClusterOverviewSummary, OverviewFreshness, WatchCoverageCard } from './ClusterOverviewSummary'

function Search() {
  return <p data-testid="search">{useLocation().search}</p>
}

function wrap(ui: ReactNode, url = '/clusters/cl_1') {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>
        {ui}
        <Search />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const live = { stale: false }
const inspectResult = (result: unknown) => ({ tool: 'x', receivedAt: '2026-10-10T10:00:00Z', result })

beforeEach(() => {
  vi.clearAllMocks()
  caps.clear()
  caps.add(CAP_CLUSTER_INSPECT)
  caps.add(CAP_CLUSTER_READ)
})

describe('Upgrade readiness', () => {
  const scan = {
    id: 'ups_1',
    clusterId: 'cl_1',
    currentVersion: '1.31.4',
    targetVersion: '1.32',
    verdict: 'blocked',
    reviewedThrough: '1.34',
    scannedAt: '2026-10-10T09:00:00Z',
    result: {
      checks: [
        { id: 'p', category: 'API', title: 'Passing check', status: 'passed', summary: 'fine', findings: [] },
        { id: 'u', category: 'Metrics', title: 'Deprecated API requests', status: 'unknown', summary: 'needs API server metrics', findings: null },
        {
          id: 'b',
          category: 'API',
          title: 'Removed API in use',
          status: 'blocked',
          summary: 'objects use a removed API',
          caveat: 'only live objects were read',
          findings: [{ ruleID: 'r', title: 'uses flowcontrol v1beta3', level: 'blocker', resource: { kind: 'FlowSchema', namespace: '', name: 'fs1', group: 'flowcontrol.apiserver.k8s.io' }, impact: 'breaks', remediation: 'migrate', references: [] }],
          findingsTotal: 60,
          truncated: true,
        },
      ],
    },
  }

  it('shows the verdict as a word, the catalogue boundary, groups in order, and a partial finding count', async () => {
    mockLatestScan.mockResolvedValue({ scan })
    wrap(<UpgradeReadinessPanel clusterId="cl_1" kubernetesVersion="1.31.4" />)
    expect(await screen.findByText(/Upgrade 1\.31\.4 → 1\.32/)).toBeTruthy()
    expect(screen.getByText(/rules through 1\.34/)).toBeTruthy()
    // Every check in one strip, worst first, each named with its verdict.
    const strip = screen.getByRole('list', { name: 'Every check, worst first' })
    expect(within(strip).getAllByRole('listitem').map((li) => li.textContent)).toEqual([
      'Removed API in use: Blocked',
      'Deprecated API requests: Incomplete',
      'Passing check: Passed',
    ])
    // The blocker leads, with its partial count: 60 exist, 1 was sent.
    const blocker = screen.getByRole('region', { name: 'Blocked: Removed API in use' })
    expect(within(blocker).getByText('60 findings · 1 sent')).toBeTruthy()
    expect(within(blocker).getByText('only live objects were read')).toBeTruthy()
    // An unchecked check is "could not check", never Passed.
    const unknown = screen.getByRole('region', { name: 'Could not check' })
    expect(within(unknown).getByText('Deprecated API requests')).toBeTruthy()
    expect(screen.getByText('Passing check', { selector: '.upgrade-quiet-names' })).toBeTruthy()
  })

  it('states the impact and fix once for a group of look-alike findings', async () => {
    const f = (name: string) => ({ ruleID: 'e', title: 'Pod uses node-local emptyDir data', level: 'blocker', resource: { kind: 'Pod', namespace: name === 'c' ? 'ns2' : 'ns1', name }, impact: 'data is lost', remediation: 'move to a PVC', references: [] })
    mockLatestScan.mockResolvedValue({ scan: { ...scan, result: { checks: [{ ...scan.result.checks[2], findings: [f('a'), f('b'), f('c')], findingsTotal: 3, truncated: false }] } } })
    wrap(<UpgradeReadinessPanel clusterId="cl_1" kubernetesVersion="1.31.4" />)
    expect(await screen.findByText('Pod uses node-local emptyDir data')).toBeTruthy()
    expect(screen.getAllByText('data is lost')).toHaveLength(1)
    expect(screen.getAllByText('3 Pods').length).toBeGreaterThan(0)
    expect(screen.getByRole('img', { name: 'ns1: 2 findings' })).toBeTruthy()
  })

  it('opens the inspector from a finding', async () => {
    mockLatestScan.mockResolvedValue({ scan })
    wrap(<UpgradeReadinessPanel clusterId="cl_1" />)
    fireEvent.click(await screen.findByRole('button', { name: 'FlowSchema fs1' }))
    expect(screen.getByTestId('search').textContent).toContain('panel=obj%3Acl_1%3Aflowcontrol.apiserver.k8s.io%2FFlowSchema%3A%2Ffs1')
  })

  it('distinguishes "never scanned" and explains a rate-limited run', async () => {
    mockLatestScan.mockResolvedValue({ scan: null })
    mockRunScan.mockRejectedValue(new ApiError('Scan just ran', 429, 'this cluster was scanned less than a minute ago'))
    wrap(<UpgradeReadinessPanel clusterId="cl_1" kubernetesVersion="1.31.4" />)
    expect(await screen.findByText(/No upgrade scan has run for this cluster yet/)).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Scan now for 1.32' }))
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringMatching(/less than a minute ago/))
  })

  // Owner QA 2026-10-11: a one-off scan for 1.99 replaced the cluster's
  // "next upgrade" verdict everywhere. The tab shows the one-off with its
  // target and says which verdict the fleet views carry.
  it('marks a one-off scan as such and shows the next-minor verdict beside it', async () => {
    mockLatestScan.mockResolvedValue({ scan: { ...scan, currentVersion: '1.31', targetVersion: '1.33', verdict: 'unknown' } })
    mockFleetScans.mockResolvedValue({ scans: [{ ...scan, currentVersion: '1.31', targetVersion: '1.32', verdict: 'review', result: undefined }] })
    wrap(<UpgradeReadinessPanel clusterId="cl_1" kubernetesVersion="1.31.4" />)
    const note = await screen.findByText(/A one-off scan for 1\.33\. The Clusters list and the Overview show the verdict for the next minor, 1\.32/)
    await waitFor(() => expect(note.textContent).toContain('Review'))
  })

  it('refuses a target that is not newer than the cluster, and shows the hub’s range for one it rejects', async () => {
    mockLatestScan.mockResolvedValue({ scan: null })
    mockRunScan.mockRejectedValue(
      new ApiError('Target version out of range', 400, "ARGUS's upgrade checks are reviewed through Kubernetes 1.37, so a scan for 1.99 would have nothing reviewed to check; choose 1.32 to 1.37."),
    )
    wrap(<UpgradeReadinessPanel clusterId="cl_1" kubernetesVersion="1.31.4" />)
    const input = await screen.findByLabelText('Target version')
    fireEvent.change(input, { target: { value: '1.31' } })
    expect(screen.getByText(/Choose a version newer than the cluster's 1\.31\.4, starting at 1\.32/)).toBeTruthy()
    fireEvent.change(input, { target: { value: '1.99' } })
    fireEvent.click(screen.getByRole('button', { name: 'Scan now for 1.99' }))
    expect(await screen.findByRole('alert')).toHaveProperty('textContent', expect.stringMatching(/choose 1\.32 to 1\.37/))
  })

  it('rejects a malformed target before asking the hub', async () => {
    mockLatestScan.mockResolvedValue({ scan: null })
    wrap(<UpgradeReadinessPanel clusterId="cl_1" kubernetesVersion="1.31.4" />)
    fireEvent.change(await screen.findByLabelText('Target version'), { target: { value: '1.32.1' } })
    expect(screen.getByText(/Use the form 1\.N/)).toBeTruthy()
    expect((screen.getByRole('button', { name: /Scan now/ }) as HTMLButtonElement).disabled).toBe(true)
  })
})

describe('Posture', () => {
  const result = {
    observedAt: '2026-10-10T10:00:00Z',
    truncated: true,
    total: 900,
    checks: { privileged: { id: 'privileged', title: 'Privileged container', category: 'Security', description: 'Runs privileged', remediation: 'Set privileged: false', frameworks: ['CIS'] } },
    findings: [
      { kind: 'Pod', namespace: 'a', name: 'p1', checkID: 'privileged', category: 'Security', severity: 'danger', message: 'container x is privileged' },
      { kind: 'Pod', namespace: 'a', name: 'p2', checkID: 'privileged', category: 'Security', severity: 'danger', message: 'container y is privileged' },
    ],
  }

  it('collapses to one row per check with a lower-bound count when truncated, expands to objects with the remediation', async () => {
    mockInspect.mockResolvedValue(inspectResult(result))
    wrap(<PosturePanel clusterId="cl_1" liveness={live} />)
    const toggle = await screen.findByRole('button', { name: /Privileged container/, expanded: false })
    expect(screen.getByText(/each count below is a lower bound/)).toBeTruthy()
    expect(screen.getAllByLabelText('at least 2').length).toBe(2)
    fireEvent.click(toggle)
    expect(screen.getByText('Set privileged: false')).toBeTruthy()
    expect(screen.getByTestId('search').textContent).toContain('pexp=privileged')
    fireEvent.click(screen.getByRole('button', { name: 'Pod a/p1' }))
    expect(screen.getByTestId('search').textContent).toContain('panel=')
  })

  it('passes the category filter to the agent and keeps it in the URL', async () => {
    mockInspect.mockResolvedValue(inspectResult({ ...result, findings: [], truncated: false }))
    wrap(<PosturePanel clusterId="cl_1" liveness={live} />, '/clusters/cl_1?pcat=Security')
    expect(await screen.findByText(/No posture check fired for these filters/)).toBeTruthy()
    expect(mockInspect).toHaveBeenCalledWith('cl_1', 'get_posture_findings', { category: 'Security' }, 't')
  })

  it('charts each category from the agent summary and filters by a namespace bar', async () => {
    mockInspect.mockResolvedValue(
      inspectResult({
        ...result,
        truncated: false,
        summary: { danger: 2, warning: 1, passing: 40, categories: { Security: { danger: 2, warning: 1, passing: 40 } } },
        findings: [
          ...result.findings,
          { kind: 'Deployment', namespace: 'b', name: 'd1', checkID: 'privileged', category: 'Security', severity: 'warning', message: 'm' },
        ],
      }),
    )
    wrap(<PosturePanel clusterId="cl_1" liveness={live} />)
    expect(await screen.findByRole('img', { name: 'Security checks: 2 danger, 1 warning, 40 passing' })).toBeTruthy()
    // Row severity uses the same words as the bars.
    expect(screen.getAllByText('Danger').length).toBeGreaterThan(0)
    fireEvent.click(screen.getByRole('button', { name: /^b/ }))
    expect(screen.getByTestId('search').textContent).toContain('pns=b')
    // Narrowed to namespace b, the check fired on one object.
    expect(document.querySelector('.posture-objects-count')?.textContent).toBe('1')
  })

  it('names the missing capability instead of running the tool', async () => {
    caps.delete(CAP_CLUSTER_INSPECT)
    wrap(<PosturePanel clusterId="cl_1" liveness={live} />)
    expect(screen.getByRole('note').textContent).toMatch(/cluster:inspect/)
    expect(mockInspect).not.toHaveBeenCalled()
  })

  it('renders the hub error', async () => {
    mockInspect.mockRejectedValue(new ApiError('Cluster not connected', 503, 'the agent is not connected'))
    wrap(<PosturePanel clusterId="cl_1" liveness={live} />)
    expect((await screen.findByRole('alert')).textContent).toBe('Cluster not connected — the agent is not connected')
  })
})

describe('Certificates', () => {
  it('shows unknown days as unknown, health as words, and says when served probing is off', async () => {
    mockInspect.mockResolvedValue(
      inspectResult({
        servedProbed: false,
        certificates: [
          { name: 'pending', namespace: 'web', issuer: 'le', domains: 'a.example', health: 'unknown', source: 'cert-manager' },
          { name: 'soon', namespace: 'web', issuer: 'le', domains: 'b.example', daysLeft: 3, expiry: '2026-10-13T00:00:00Z', health: 'unhealthy', source: 'cert-manager' },
        ],
      }),
    )
    wrap(<CertificatesPanel clusterId="cl_1" liveness={live} />)
    expect(await screen.findByText(/Served-certificate probing off/)).toBeTruthy()
    expect(screen.getByText('Source: cert-manager only')).toBeTruthy()
    const rows = screen.getAllByRole('row').slice(1)
    expect(within(rows[0]).getByText('Expires within 7 days or expired')).toBeTruthy()
    expect(within(rows[1]).getByLabelText('expiry unknown')).toBeTruthy()
    expect(within(rows[1]).queryByText('0')).toBeNull()
    // The runway draws the known expiry in the unhealthy zone and counts the
    // unknown one rather than placing it.
    expect(screen.getByRole('img', { name: 'soon · 3d' })).toBeTruthy()
    expect(screen.getByText(/1 within 30 days · next in 3 days · 1 expiry unknown/)).toBeTruthy()
  })

  it('groups certificates that would overlap on the runway into one pin', async () => {
    mockInspect.mockResolvedValue(
      inspectResult({
        servedProbed: true,
        certificates: [84, 84, 85, 248, 1708].map((d, i) => ({ name: `c${i}`, namespace: 'n', issuer: 'ca', domains: 'x, y +3 more', daysLeft: d, expiry: '2027-01-04T00:00:00Z', health: 'healthy', source: 'cert-manager' })),
      }),
    )
    wrap(<CertificatesPanel clusterId="cl_1" liveness={live} />)
    expect(await screen.findByRole('img', { name: '3 certificates · 84–85d; c3 · 248d; c4 · 1708d' })).toBeTruthy()
    expect(screen.getByText('Source: cert-manager and served endpoints')).toBeTruthy()
    // "x, y +3 more" is five domains: the first, plus four.
    expect(screen.getAllByText('+4').length).toBe(5)
    // A healthy row carries no redundant health word.
    expect(screen.queryByText('Valid 30+ days')).toBeNull()
  })
})

describe('Traffic', () => {
  it('states the reason when traffic is unavailable', async () => {
    mockInspect.mockResolvedValue(inspectResult({ available: false, reason: 'no Prometheus is configured for this agent' }))
    wrap(<TrafficPanel clusterId="cl_1" liveness={live} />)
    // An older agent's config-key sentence is read as what it means.
    expect(await screen.findByText('Not connected')).toBeTruthy()
    expect(screen.getByText(/No metrics source on this agent/)).toBeTruthy()
    // Nothing to copy when no Prometheus was found.
    expect(screen.queryByText(/metrics\.prometheusService/)).toBeNull()
  })

  it('offers the exact chart values when the agent found a Prometheus', async () => {
    mockInspect.mockResolvedValue(
      inspectResult({ available: false, reasonCode: 'not_configured', detectedPrometheus: { namespace: 'mon', name: 'prom', port: 9091 } }),
    )
    wrap(<TrafficPanel clusterId="cl_1" liveness={live} />)
    expect((await screen.findByLabelText('argus-agent chart values')).textContent).toBe(
      'metrics.prometheusService.namespace=mon\nmetrics.prometheusService.name=prom\nmetrics.prometheusService.port=9091',
    )
    expect(screen.getByRole('button', { name: /Copy helm values/ })).toBeTruthy()
  })

  it('labels edges in text and lists every flow in a table', async () => {
    mockInspect.mockResolvedValue(
      inspectResult({
        available: true,
        source: 'istio',
        windowSeconds: 900,
        flows: [{ src: { namespace: 'shop', name: 'web', kind: 'Workload' }, dst: { namespace: 'shop', name: 'api', kind: 'Workload' }, port: 80, protocol: 'http', requestRate: 10, errorRate: 0.5 }],
        missing: ['TCP bytes'],
      }),
    )
    wrap(<TrafficPanel clusterId="cl_1" liveness={live} />, '/clusters/cl_1?tns=shop')
    expect((await screen.findByRole('group', { name: /Traffic between workloads/ })).textContent).toBe('10 req/s · 5% 5xx')
    expect(screen.getByText(/Not measured: TCP bytes/)).toBeTruthy()
    expect(screen.getByText('5% (errors)')).toBeTruthy()
    expect(mockInspect).toHaveBeenCalledWith('cl_1', 'get_traffic', { namespace: 'shop', windowMinutes: 15 }, 't')
  })
})

describe('Cost', () => {
  it('states why cost is unavailable rather than showing zero', async () => {
    mockInspect.mockResolvedValue(inspectResult({ summary: { available: false, reason: 'no_metrics' } }))
    wrap(<CostPanel clusterId="cl_1" liveness={live} />)
    expect(await screen.findByText(/OpenCost is not installed/)).toBeTruthy()
    expect(screen.queryByText(/0\.00/)).toBeNull()
  })

  it('renders unmeasured figures as a dash and labels the currency as OpenCost’s', async () => {
    mockInspect.mockResolvedValue(
      inspectResult({
        summary: { available: true, totalHourlyCost: 1.5, hourlyCostBasis: 'allocated', namespaces: [{ name: 'shop', hourlyCost: 1.5, cpuCost: 1, memoryCost: 0.5 }] },
      }),
    )
    wrap(<CostPanel clusterId="cl_1" liveness={live} />)
    expect(await screen.findByText(/that tool's own currency/)).toBeTruthy()
    expect(screen.getByRole('list', { name: 'Cost per namespace' })).toBeTruthy()
    fireEvent.click(screen.getByText('Every figure per namespace'))
    const row = screen.getByRole('row', { name: /shop/ })
    expect(within(row).getAllByText('not measured')).toHaveLength(3)
  })
})

const noIncidents = { items: [], openCount: 0, loading: false, error: null, truncated: false, onShowAll: () => {} }

describe('Overview health summary', () => {
  beforeEach(() => {
    mockChanges.mockResolvedValue({ changes: [], gaps: [] })
    mockFleetScans.mockResolvedValue({ scans: [] })
    mockInspect.mockResolvedValue(inspectResult({ findings: [], certificates: [] }))
  })

  it('says a kind is not visible to the agent instead of counting it', async () => {
    wrap(
      <ClusterOverviewSummary
        clusterId="cl_1"
        factsUpdatedAt="2026-10-10T10:00:00Z"
        liveness={{ stale: true, staleReason: 'Stopped sending heartbeats' }}
        nodes={[]}
        incidents={noIncidents}
        facts={{
          summary: {
            computedAt: '2026-10-10T10:00:00Z',
            resourceCounts: { pods: { total: 10, running: 9, pending: 1, failed: 0, succeeded: 0 }, unavailable: ['nodes'] },
            networkPolicyCoverage: { policies: 2, coveredWorkloads: 3, totalWorkloads: 8 },
            gitopsControllers: ['argocd'],
          },
          objectCache: { syncedAt: 'x', kinds: [{ kind: 'Pod', state: 'synced' }, { kind: 'Ingress', group: 'networking.k8s.io', state: 'forbidden' }] },
        }}
      />,
    )
    // The Nodes ring has no number, and says why.
    expect(screen.getByRole('img', { name: 'Nodes: Not visible to the agent' })).toBeTruthy()
    expect(screen.getByText(/3 of 8 workloads selected/)).toBeTruthy()
    expect(screen.getByText('Argo CD')).toBeTruthy()
    // Coverage lives on the Agent tab now (AgentCoverageSection), not here.
    expect(screen.queryByText(/Forbidden to the agent/)).toBeNull()
    // The "as of" stamp lives in the tab row now (OverviewFreshness), and
    // still says Stale for a cluster that stopped reporting.
    const { unmount: u2 } = wrap(<OverviewFreshness facts={{}} factsUpdatedAt="2026-10-10T10:00:00Z" liveness={{ stale: true, staleReason: 'Stopped sending heartbeats' }} />)
    expect(screen.getAllByRole('status').some((s) => /Stale/.test(s.textContent ?? ''))).toBe(true)
    u2()
    expect(screen.getByRole('link', { name: /Signals from this cluster/ }).getAttribute('href')).toBe('/signals?clusterId=cl_1')
    expect(await screen.findByText('No changes recorded in the last 60 minutes.')).toBeTruthy()
  })

  it('draws each ring with its breakdown in words, never colour alone', () => {
    wrap(
      <ClusterOverviewSummary
        clusterId="cl_1"
        factsUpdatedAt={null}
        liveness={live}
        nodes={[]}
        incidents={noIncidents}
        facts={{
          summary: {
            resourceCounts: {
              pods: { total: 166, running: 151, pending: 0, failed: 2, succeeded: 13 },
              deployments: { total: 70, ready: 69, notReady: 1, scaledToZero: 3 },
              statefulSets: { total: 6, ready: 6, notReady: 0, scaledToZero: 0 },
              daemonSets: { total: 8, ready: 7, notReady: 1, scaledToZero: 0 },
              nodes: { total: 5, ready: 5, notReady: 0, cordoned: 1 },
              services: 69,
              jobs: { total: 12, active: 0, succeeded: 11, failed: 1 },
            },
            nodeVersionSkew: { min: '1.35', max: '1.35', skewed: false },
          },
        }}
      />,
    )
    const pods = screen.getByRole('region', { name: 'Pods' })
    expect(within(pods).getByText(/151 running/)).toBeTruthy()
    expect(within(pods).getByText(/13 completed/)).toBeTruthy()
    expect(within(pods).getByText(/2 failed/)).toBeTruthy()
    const workloads = screen.getByRole('region', { name: 'Workloads' })
    expect(within(workloads).getByText(/82 ready/)).toBeTruthy()
    expect(within(workloads).getByText(/2 not ready/)).toBeTruthy()
    expect(within(workloads).getByText(/3 Deployments scaled to zero/)).toBeTruthy()
    const nodes = screen.getByRole('region', { name: 'Nodes' })
    expect(within(nodes).getByText(/5 ready/)).toBeTruthy()
    // A zero problem part keeps its word and count, but is not drawn as danger;
    // a non-zero one is.
    expect(within(nodes).getByText(/0 not ready/).closest('li')?.hasAttribute('data-tone')).toBe(false)
    expect(within(pods).getByText(/2 failed/).closest('li')?.getAttribute('data-tone')).toBe('bad')
    expect(within(nodes).getByText(/1 cordoned · kubelet 1.35 on every node/)).toBeTruthy()
    // The object counts, grouped, with the detail beside the count and an
    // absent kind as "—".
    const objects = screen.getByRole('group', { name: 'Objects' })
    expect(within(objects).getByText('Objects by kind')).toBeTruthy()
    expect(within(objects).getAllByText(/69/).length).toBeGreaterThan(0)
    expect(within(objects).getByText(/1 failed/)).toBeTruthy()
    expect(screen.getAllByText(/not reported by this agent/).length).toBeGreaterThan(0)
  })

  it('shows used and requested against allocatable, and says requested is unreported on an old agent', () => {
    const nodes = [
      { name: 'n1', ready: true, cpuAllocatable: '4', memoryAllocatable: '8Gi', cpuUsed: '1', memoryUsed: '2Gi' },
      { name: 'n2', ready: true, cpuAllocatable: '4', memoryAllocatable: '8Gi', cpuUsed: '1', memoryUsed: '2Gi' },
    ]
    const { unmount } = wrap(
      <ClusterOverviewSummary clusterId="cl_1" factsUpdatedAt={null} liveness={live} nodes={nodes} incidents={noIncidents} facts={{ summary: {} }} />,
    )
    const card = screen.getByRole('region', { name: 'Resource use' })
    expect(within(card).getByText('2 of 8 cores · 25%')).toBeTruthy()
    expect(within(card).getByText('4 of 16 GiB · 25%')).toBeTruthy()
    expect(within(card).getAllByText(/Not reported by this agent/)).toHaveLength(2)
    unmount()
    wrap(
      <ClusterOverviewSummary
        clusterId="cl_1"
        factsUpdatedAt={null}
        liveness={live}
        nodes={nodes}
        incidents={noIncidents}
        facts={{ summary: { capacity: { cpuRequestedMillicores: 6000, cpuAllocatableMillicores: 8000, memoryRequestedBytes: 4 * 1024 ** 3, memoryAllocatableBytes: 16 * 1024 ** 3, podsCounted: 40 } } }}
      />,
    )
    const card2 = screen.getByRole('region', { name: 'Resource use' })
    expect(within(card2).getByText('6 of 8 cores · 75%')).toBeTruthy()
    expect(within(card2).getAllByText('requests of 40 scheduled pods')).toHaveLength(2)
  })

  it('previews the worst open incidents with the whole-set count, and links to the tab', () => {
    const onShowAll = vi.fn()
    const inc = (id: string, severity: string, state = 'Detected') => ({
      id,
      clusterId: 'cl_1',
      clusterDisplayName: 'c',
      fingerprint: id,
      severity,
      state,
      firstSeen: '2026-10-10T09:00:00Z',
      lastSeen: '2026-10-10T09:30:00Z',
      occurrenceCount: 1,
      objectName: `obj-${id}`,
      objectGvk: 'apps/v1/Deployment',
      openingReason: 'Unhealthy',
    })
    wrap(
      <ClusterOverviewSummary
        clusterId="cl_1"
        factsUpdatedAt={null}
        liveness={live}
        nodes={[]}
        incidents={{
          ...noIncidents,
          openCount: 31,
          onShowAll,
          items: [inc('a', 'low'), inc('b', 'critical'), inc('c', 'high', 'Resolved'), inc('d', 'medium'), inc('e', 'high')] as never,
        }}
        facts={{ summary: {} }}
      />,
    )
    const card = screen.getByRole('region', { name: 'Needs attention' })
    const names = within(card)
      .getAllByRole('listitem')
      .map((li) => within(li).getByRole('link').textContent)
    // Open worst first; the one row left over shows the recently closed one,
    // under its own heading.
    expect(names).toEqual(['obj-b', 'obj-e', 'obj-d', 'obj-a', 'obj-c'])
    expect(within(card).getByRole('heading', { name: 'Recently closed' })).toBeTruthy()
    // Where each incident is in ARGUS's loop, beside its severity.
    expect(within(card).getAllByText('Not investigated')).toHaveLength(4)
    expect(within(card).getByText('Resolved')).toBeTruthy()
    // The card's foot also reaches what this cluster reported but did not raise.
    expect(within(card).getByRole('link', { name: /Signals from this cluster/ }).getAttribute('href')).toContain('/signals?clusterId=')
    expect(within(card).getByText('31 open')).toBeTruthy()
    fireEvent.click(within(card).getByRole('button', { name: /All 31 open incidents/ }))
    expect(onShowAll).toHaveBeenCalled()
  })

  it('says the agent is still reading the cluster while its first sync runs, not "not visible"', () => {
    const startedAt = new Date(Date.now() - 20_000).toISOString()
    wrap(
      <ClusterOverviewSummary
        clusterId="cl_1"
        factsUpdatedAt={null}
        liveness={live}
        nodes={[{ name: 'n1', ready: true, cpuAllocatable: '4', memoryAllocatable: '8Gi' }]}
        incidents={noIncidents}
        facts={{ summary: { cacheState: 'syncing', cacheStartedAt: startedAt, computedAt: startedAt } }}
      />,
    )
    expect(screen.getByText(/The agent is still reading the cluster/).textContent).toMatch(/started 20s ago\) — figures appear when its first sync completes/)
    expect(screen.getByRole('img', { name: 'Nodes: Still being read by the agent' })).toBeTruthy()
    expect(screen.getByRole('img', { name: 'Workloads: Still being read by the agent' })).toBeTruthy()
    expect(screen.queryByText(/not visible to the agent/i)).toBeNull()
    expect(screen.queryByText(/newer agent build/)).toBeNull()
    expect(within(screen.getByRole('region', { name: 'Resource use' })).getAllByText(/first read of the cluster/)).toHaveLength(2)
  })

  it('reads an older agent\'s mid-sync snapshot (every kind unavailable, cache still syncing) as syncing', () => {
    wrap(
      <ClusterOverviewSummary
        clusterId="cl_1"
        factsUpdatedAt={null}
        liveness={live}
        nodes={[]}
        incidents={noIncidents}
        facts={{
          summary: { resourceCounts: { unavailable: ['pods', 'nodes', 'deployments', 'statefulsets', 'daemonsets'] } },
          objectCache: { syncedAt: '0001-01-01T00:00:00Z', kinds: [{ kind: 'Pod', state: 'syncing' }, { kind: 'Node', state: 'synced' }] },
        }}
      />,
    )
    expect(screen.getByText(/The agent is still reading the cluster — figures appear/)).toBeTruthy()
    expect(screen.getByRole('img', { name: 'Pods: Still being read by the agent' })).toBeTruthy()
    expect(screen.queryByText(/not visible to the agent/i)).toBeNull()
  })

  it('lists kinds the agent cannot see on the Agent tab', () => {
    wrap(
      <AgentCoverageSection
        facts={{ objectCache: { syncedAt: 'x', kinds: [{ kind: 'Pod', state: 'synced' }, { kind: 'Ingress', group: 'networking.k8s.io', state: 'forbidden' }] } }}
      />,
    )
    expect(screen.getByText('1 forbidden to the agent')).toBeTruthy()
    expect(screen.getByTitle('Ingress.networking.k8s.io')).toBeTruthy()
  })

  it('does not invent counts when no summary was reported', () => {
    wrap(<ClusterOverviewSummary clusterId="cl_1" factsUpdatedAt={null} liveness={live} nodes={null} incidents={noIncidents} facts={{ nodeCount: 3 }} />)
    expect(screen.getByText(/No health summary yet/)).toBeTruthy()
    expect(screen.getByRole('img', { name: 'Pods: Not reported by this agent' })).toBeTruthy()
    expect(screen.queryByText(/^0$/)).toBeNull()
  })
})

describe('Watch coverage (Agent tab)', () => {
  it('says not reported for an agent without the field, never 0 of 0', () => {
    wrap(<WatchCoverageCard facts={{ nodeCount: 1 }} />)
    expect(screen.getByText(/Not reported by this agent/)).toBeTruthy()
    expect(screen.queryByText(/of 0/)).toBeNull()
  })

  it('reads an unchecked coverage as unknown with the agent’s reason', () => {
    wrap(<WatchCoverageCard facts={{ coverage: { checked: false, kindsServed: 0, kindsReadable: 0, error: 'rules review failed' } }} />)
    expect(screen.getByText('Unknown')).toBeTruthy()
    expect(screen.getByText(/rules review failed/)).toBeTruthy()
  })

  it('shows readable of served as words and a meter, the sweep breakdown, and the denied sample with its truncation', () => {
    wrap(
      <WatchCoverageCard
        facts={{
          coverage: {
            checked: true,
            kindsServed: 216,
            kindsReadable: 44,
            deniedSample: ['/secrets', 'velero.io/backups'],
            deniedSampleTruncated: true,
            lastSweep: { at: '2026-10-10T10:00:00Z', kindsRead: 40, kindsForbidden: 3, kindsNotServed: 5, kindsNotAffordable: 1, kindsFailed: 0, kindsNotListed: 1 },
          },
        }}
      />,
    )
    expect(screen.getByRole('img', { name: 'Watching 44 of 216 resource kinds, 20%' })).toBeTruthy()
    expect(screen.getByText(/172 kinds are not readable/)).toBeTruthy()
    expect(screen.getByRole('img', { name: /^Last sweep, resource kinds: 40 read, 3 forbidden by RBAC, 1 skipped by the memory guard, 5 CRD not installed, 1 never listed/ })).toBeTruthy()
    expect(screen.getByText(/Denied kinds · 2 shown, more exist/)).toBeTruthy()
    expect(screen.getByText('velero.io/backups')).toBeTruthy()
  })
})

describe('Refresh', () => {
  it('re-asks the agent', async () => {
    mockInspect.mockResolvedValue(inspectResult({ available: false, reason: 'none' }))
    wrap(<TrafficPanel clusterId="cl_1" liveness={live} />)
    fireEvent.click(await screen.findByRole('button', { name: /Refresh traffic/ }))
    await waitFor(() => expect(mockInspect).toHaveBeenCalledTimes(2))
  })
})
