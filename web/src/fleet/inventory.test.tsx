import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { CAP_CLUSTER_INSPECT, CAP_CLUSTER_READ } from '../api/capabilities'
import type { GitOpsAppList, HelmReleaseList, Incident, NamespaceTopology } from '../api/types'

// The cluster page's Helm, GitOps and Map tabs (PROJECT.md AD5/AD6). Fixtures
// are trimmed from what list_helm_releases, list_gitops_apps and
// get_namespace_topology returned against rke2 on 2026-10-11 (run as the
// agent's own read-only identity): Argo CD apps with a repository credential
// failure, a release whose objects were adopted with no Helm record, and the
// nebula namespace whose one NetworkPolicy selects every workload.

const mockInspect = vi.fn()
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return { ...actual, inspectCluster: (...a: unknown[]) => mockInspect(...a), getFleetUpgradeScans: () => Promise.resolve({ scans: [] }) }
})
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 't' }) }))
const caps = new Set<string>()
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (c: string) => caps.has(c),
  useMissingCapabilities: (list: string[]) => ({ resolved: true, missing: list.filter((c) => !caps.has(c)) }),
}))

import { ApiError } from '../api/client'
import { HelmPanel } from './HelmPanel'
import { GitOpsPanel } from './GitOpsPanel'
import { NamespaceMapPanel } from './NamespaceMapPanel'
import { ChecksCard } from './ClusterPreviews'
import { gradedSummary, isHelmProblem, sortReleases } from './helmModel'
import { destinationText, groupProblems, shortRepo, sourceText } from './gitopsModel'
import { OPEN_BY_DEFAULT, UNTIED_GROUP, buildNamespaceMap, defaultNamespace, defaultOpen, mapPartialNote, mapStatusCounts, mapStatusText, namespaceOptionLabel, nodeDetail, type MapCard } from './namespaceMapModel'

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
const ok = (result: unknown) => ({ tool: 'x', receivedAt: '2026-10-11T09:36:00Z', result })
const search = () => decodeURIComponent(screen.getByTestId('search').textContent ?? '')

beforeEach(() => {
  vi.clearAllMocks()
  caps.clear()
  caps.add(CAP_CLUSTER_INSPECT)
  caps.add(CAP_CLUSTER_READ)
})

// ---------------------------------------------------------------- Helm

const helm: HelmReleaseList = {
  observedAt: '2026-10-11T09:36:00Z',
  coverage: [{ group: 'apiextensions.k8s.io', kind: 'CustomResourceDefinition', state: 'forbidden' }],
  total: 3,
  note: 'labels only',
  releases: [
    {
      name: 'argus-hub',
      namespace: 'argus-system',
      revision: 15,
      status: 'deployed',
      updated: '2026-09-29T10:35:28Z',
      objects: 13,
      objectKinds: [{ kind: 'Service', count: 4 }],
      graded: 6,
      healthCounts: { healthy: 4, neutral: 2 },
      health: 'healthy',
      mainObject: { kind: 'Deployment', apiGroup: 'apps', namespace: 'argus-system', name: 'argus-hub-argus-hub' },
    },
    {
      name: 'nebula',
      namespace: 'nebula',
      statusUnavailable: 'no release Secret found under this name; the release may be stored elsewhere',
      objects: 74,
      graded: 16,
      healthCounts: { healthy: 15, unhealthy: 1 },
      health: 'unhealthy',
      problems: [{ kind: 'Deployment', apiGroup: 'apps', namespace: 'nebula', name: 'nebula-control', health: 'unhealthy', reason: 'NoneReady' }],
      mainObject: { kind: 'Deployment', apiGroup: 'apps', namespace: 'nebula', name: 'nebula-admin' },
    },
    {
      name: 'rancher-monitoring-crd',
      namespace: 'cattle-monitoring-system',
      revision: 7,
      revisionLowerBound: true,
      status: 'pending-upgrade',
      objects: 4,
      graded: 0,
      lastOperation: { message: 'pending-upgrade at rev 7 for 40m; another operation is in progress.' },
    },
  ],
}

describe('Helm tab', () => {
  it('puts failed, pending and unhealthy releases first, with status as a word and the revision honest', async () => {
    mockInspect.mockResolvedValue(ok(helm))
    wrap(<HelmPanel clusterId="cl_1" liveness={live} />)
    const table = await screen.findByRole('table', { name: /Helm releases/ })
    const rows = within(table).getAllByRole('row').slice(1)
    // rancher-monitoring-crd and nebula are problems; argus-hub is last.
    expect(rows[0]?.textContent).toContain('rancher-monitoring-crd')
    expect(rows.at(-1)?.textContent).toContain('argus-hub')
    expect(screen.getByText('Pending upgrade')).toBeTruthy()
    expect(screen.getByText('Deployed')).toBeTruthy()
    expect(screen.getByLabelText('at least 7')).toBeTruthy()
    expect(screen.getByText(/Status not read: no release Secret found/)).toBeTruthy()
    expect(screen.getByText(/another operation is in progress/)).toBeTruthy()
    expect(screen.getByText(/nebula-control/)).toBeTruthy()
    expect(screen.getByText(/objects · 4 healthy · 2 idle$/)).toBeTruthy()
    expect(screen.getByText(/objects · nothing to grade$/)).toBeTruthy()
    expect(screen.getByRole('button', { name: /^All\s*3$/ })).toBeTruthy()
    expect(screen.getByText(/status not read for 1/)).toBeTruthy()
    // What is never read is said, and there is no control to change a release.
    expect(screen.getByText(/chart versions, values and manifests are not read/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: /upgrade|rollback|uninstall/i })).toBeNull()
    expect(screen.getByText(/CustomResourceDefinition/)).toBeTruthy()
  })

  it('puts releases behind an open incident first, matched through their own objects', async () => {
    const rel: HelmReleaseList = {
      ...helm,
      releases: [
        ...helm.releases,
        {
          ...helm.releases[0],
          name: 'shop-apps',
          namespace: 'default',
          status: 'deployed',
          lastOperation: undefined,
          health: 'healthy',
          members: [{ kind: 'Deployment', apiGroup: 'apps', namespace: 'apps', name: 'gwas-frontend', health: 'healthy' }],
        },
      ],
    }
    mockInspect.mockResolvedValue(ok(rel))
    const inc = (name: string, kind: string, ns: string, state = 'Detected') =>
      ({ id: name, objectGvk: `v1/${kind}`, objectNamespace: ns, objectName: name, state, severity: 'critical' }) as never
    wrap(
      <HelmPanel
        clusterId="cl_1"
        liveness={live}
        incidents={[inc('gwas-frontend-7d9f-abcde', 'Pod', 'apps'), inc('gwas-frontend-x', 'Pod', 'other'), inc('gwas-frontend-old', 'Pod', 'apps', 'Resolved')]}
      />,
    )
    const table = await screen.findByRole('table', { name: /Helm releases/ })
    const first = within(table).getAllByRole('row')[1]
    expect(first.textContent).toContain('shop-apps')
    expect(first.textContent).toContain('1critical')
    fireEvent.click(screen.getByRole('button', { name: /^With an open incident\s*1$/ }))
    expect(within(screen.getByRole('table', { name: /Helm releases/ })).getAllByRole('row')).toHaveLength(2)
  })

  // Owner QA 2026-10-11: clicking shop-apps opened "Deployment farmreport",
  // one arbitrary member. A release row now opens the RELEASE in place — its
  // objects (each opening in the inspector) and its revision history, dated
  // by when each revision was created rather than Helm's stale label.
  it('opens a release in place: its objects and its revision history', async () => {
    const withMembers: HelmReleaseList = {
      ...helm,
      releases: [
        {
          ...helm.releases[0],
          name: 'shop-apps',
          namespace: 'default',
          objects: 3,
          members: [
            { kind: 'Deployment', apiGroup: 'apps', namespace: 'apps', name: 'gwas-frontend', health: 'degraded' },
            { kind: 'Deployment', apiGroup: 'apps', namespace: 'apps', name: 'farmreport', health: 'healthy' },
            { kind: 'Service', namespace: 'apps', name: 'gwas-frontend' },
          ],
        },
      ],
    }
    mockInspect.mockImplementation((_c: string, tool: string) =>
      Promise.resolve(
        ok(
          tool === 'get_helm_release_status'
            ? {
                release: 'shop-apps',
                history: [
                  { revision: 17, status: 'superseded', updated: '2026-03-18T13:03:58Z', modifiedAt: '2026-03-18T13:03:58Z', createdAt: '2026-09-30T09:00:00Z' },
                  { revision: 18, status: 'deployed', updated: '2026-10-05T12:36:18Z', modifiedAt: '2026-03-18T13:03:58Z', createdAt: '2026-10-05T12:36:18Z' },
                ],
              }
            : withMembers,
        ),
      ),
    )
    wrap(<HelmPanel clusterId="cl_1" liveness={live} />)
    const toggle = await screen.findByRole('button', { name: 'shop-apps' })
    expect(toggle.getAttribute('aria-expanded')).toBe('false')
    fireEvent.click(toggle)
    expect(toggle.getAttribute('aria-expanded')).toBe('true')
    // Nothing navigated: the release opened under its row.
    expect(search()).not.toContain('panel=')
    const objects = await screen.findByRole('region', { name: 'Objects in release shop-apps' })
    expect(within(objects).getAllByRole('button').map((b) => b.textContent)).toEqual([
      'Deployment gwas-frontend',
      'Deployment farmreport',
      'Service gwas-frontend',
    ])
    const history = await screen.findByRole('region', { name: 'Revision history of release shop-apps' })
    await waitFor(() => expect(within(history).getAllByRole('row')).toHaveLength(3))
    const rows = within(history).getAllByRole('row').slice(1)
    expect(rows[0].textContent).toContain('18')
    // Dated by createdAt (title carries the full time), not the shared stale label.
    expect(within(rows[0]).getByTitle(/2026/)).toBeTruthy()
    expect(rows[0].querySelector('[title]')?.getAttribute('title')).not.toBe(rows[1].querySelector('[title]')?.getAttribute('title'))
    expect(screen.queryByText(/Helm’s “modified” label/)).toBeNull()
    const call = mockInspect.mock.calls.find((c) => c[1] === 'get_helm_release_status')
    expect(call?.[2]).toEqual({ namespace: 'default', name: 'shop-apps' })
    fireEvent.click(within(objects).getByRole('button', { name: 'Deployment farmreport' }))
    expect(search()).toContain('panel=obj:cl_1:apps/Deployment:apps/farmreport')
  })

  it('says so when no release exists, and caps a long list behind Show all', async () => {
    mockInspect.mockResolvedValueOnce(ok({ ...helm, total: 0, releases: [], coverage: [] }))
    wrap(<HelmPanel clusterId="cl_1" liveness={live} />)
    expect(await screen.findByText(/no Helm release was found/)).toBeTruthy()
    expect(screen.queryByText(/0 failed/)).toBeNull()

    const many = Array.from({ length: 30 }, (_, i) => ({ ...helm.releases[0], name: `rel-${String(i).padStart(2, '0')}` }))
    mockInspect.mockResolvedValueOnce(ok({ ...helm, total: 230, truncated: true, releases: many }))
    wrap(<HelmPanel clusterId="cl_2" liveness={live} />)
    expect(await screen.findByText(/lists at most 30 releases; 230 exist/)).toBeTruthy()
    const showAll = screen.getByRole('button', { name: 'Show all 30 releases' })
    expect(screen.getAllByRole('button', { name: /^rel-/ })).toHaveLength(25)
    fireEvent.click(showAll)
    expect(screen.getAllByRole('button', { name: /^rel-/ })).toHaveLength(30)
  })

  it('shows a skeleton, then the agent error with a retry', async () => {
    let reject: (e: unknown) => void = () => {}
    mockInspect.mockReturnValue(new Promise((_, r) => (reject = r)))
    wrap(<HelmPanel clusterId="cl_1" liveness={live} />)
    expect(screen.getByLabelText('Loading helm releases')).toBeTruthy()
    reject(new ApiError('Agent error', 502, 'unknown tool "list_helm_releases"'))
    expect((await screen.findByRole('alert')).textContent).toContain('unknown tool')
    expect(screen.getByRole('button', { name: 'Try again' })).toBeTruthy()
  })

  it('names the missing capability instead of reading', () => {
    caps.delete(CAP_CLUSTER_INSPECT)
    wrap(<HelmPanel clusterId="cl_1" liveness={live} />)
    expect(screen.getByRole('note')?.textContent).toContain('Helm releases runs a live read')
    expect(mockInspect).not.toHaveBeenCalled()
  })
})

describe('helm model', () => {
  it('grades only what was graded and sorts problems first', () => {
    expect(gradedSummary({ ...helm.releases[1] })).toBe('1 unhealthy · 15 healthy')
    expect(isHelmProblem(helm.releases[0])).toBe(false)
    expect(sortReleases(helm.releases).map((r) => r.name)).toEqual(['rancher-monitoring-crd', 'nebula', 'argus-hub'])
  })
})

// ---------------------------------------------------------------- GitOps

const authFail =
  'Argo CD cannot build the desired state from Git, so whether the cluster matches it is unknown: Failed to load target state: failed to list refs: authentication required: Invalid username or token.'
const argo = (name: string, extra: Partial<GitOpsAppList['apps'][number]> = {}) => ({
  tool: 'argocd',
  kind: 'Application',
  apiGroup: 'argoproj.io',
  namespace: 'argocd',
  name,
  sync: 'Unknown',
  health: 'Healthy',
  repoURL: 'https://github.com/example-org/argocd-argus-test.git',
  path: `apps/${name}`,
  targetRevision: 'main',
  destinationServer: 'https://kubernetes.default.svc',
  destinationNamespace: 'argus-gitops-rke2',
  lastSync: '2026-09-19T14:05:55Z',
  autoSync: 'Auto · prune · self-heal',
  managed: 1,
  headline: authFail,
  causes: ['Verify the repo URL, branch/tag, and credentials. Check argocd-repo-server logs for fetch errors.'],
  problem: true,
  ...extra,
})

const gitops: GitOpsAppList = {
  observedAt: '2026-10-11T09:36:00Z',
  counts: { total: 3, outOfSync: 0, syncUnknown: 2, degraded: 0, suspended: 0, reconciling: 0 },
  kinds: [
    { group: 'argoproj.io', kind: 'Application', state: 'synced' },
    { group: 'kustomize.toolkit.fluxcd.io', kind: 'Kustomization', state: 'absent' },
    { group: 'helm.toolkit.fluxcd.io', kind: 'HelmRelease', state: 'absent' },
  ],
  apps: [
    argo('argus-gitops-api'),
    argo('argus-gitops-cache'),
    argo('argus-e2e-guestbook', { sync: 'Synced', headline: undefined, causes: undefined, problem: undefined, path: 'guestbook', repoURL: 'https://github.com/argoproj/argocd-example-apps.git', targetRevision: 'HEAD' }),
  ],
}

describe('GitOps tab', () => {
  it('counts every state and says each reason once, with every app it affects under it', async () => {
    mockInspect.mockResolvedValue(ok(gitops))
    wrap(<GitOpsPanel clusterId="cl_1" liveness={live} />)
    // Sync and health as two bars, every state a word with its count.
    expect(await screen.findByRole('img', { name: 'Sync: 2 unknown, 1 synced, 0 out of sync' })).toBeTruthy()
    expect(screen.getByRole('img', { name: 'Health: 3 healthy, 0 degraded, 0 progressing' })).toBeTruthy()
    expect(screen.getByText('3 applications')).toBeTruthy()
    // One reason, said once, two apps under it: the summary before the
    // controller's first colon leads; the raw message is one click away.
    const card = screen.getByRole('region', { name: /^2 applications: Argo CD cannot build/ })
    expect(within(card).getByText('2 apps')).toBeTruthy()
    expect(within(card).getByText('Sync unknown')).toBeTruthy()
    expect(within(card).getByText(/^Controller message$/)).toBeTruthy()
    expect(within(card).getByText('authentication required: Invalid username or token.')).toBeTruthy()
    expect(within(card).getByRole('button', { name: 'argus-gitops-api' })).toBeTruthy()
    expect(within(card).getByRole('button', { name: 'argus-gitops-cache' })).toBeTruthy()
    expect(screen.getAllByText(/Verify the repo URL/)).toHaveLength(1)
    // The quiet table holds the rest.
    expect(screen.getByText('In sync and healthy · 1')).toBeTruthy()
    const quiet = screen.getByRole('table', { name: /nothing reported wrong/ })
    expect(within(quiet).getByRole('button', { name: 'argus-e2e-guestbook' })).toBeTruthy()
    expect(screen.getByText('Argo CD · Flux not installed on this cluster')).toBeTruthy()
    expect(within(card).getByText(/apps\/argus-gitops-api @ main/)).toBeTruthy()
    expect(screen.queryByRole('button', { name: /^sync|refresh app|suspend/i })).toBeNull()
  })

  it('opens an app at its GitOps tab', async () => {
    mockInspect.mockResolvedValue(ok(gitops))
    wrap(<GitOpsPanel clusterId="cl_1" liveness={live} />)
    fireEvent.click(await screen.findByRole('button', { name: 'argus-e2e-guestbook' }))
    expect(search()).toContain('panel=obj:cl_1:argoproj.io/Application:argocd/argus-e2e-guestbook')
    expect(search()).toContain('ptab=gitops')
  })

  it('states that no controller is visible, rather than an empty table of zeros', async () => {
    mockInspect.mockResolvedValue(
      ok({ ...gitops, apps: [], counts: { total: 0, outOfSync: 0, syncUnknown: 0, degraded: 0, suspended: 0, reconciling: 0 }, kinds: gitops.kinds.map((k) => ({ ...k, state: 'absent' })) }),
    )
    wrap(<GitOpsPanel clusterId="cl_1" liveness={live} />)
    expect(await screen.findByText(/No GitOps controller this page reads is visible/)).toBeTruthy()
    expect(screen.queryByRole('img', { name: /^Sync:/ })).toBeNull()
  })

  it('shows the agent error', async () => {
    mockInspect.mockRejectedValue(new ApiError('Cluster not connected', 503, 'this cluster’s agent is not connected'))
    wrap(<GitOpsPanel clusterId="cl_1" liveness={live} />)
    expect((await screen.findByRole('alert')).textContent).toContain('not connected')
  })
})

describe('gitops model', () => {
  it('reads sources and destinations as a person would', () => {
    expect(shortRepo('git@github.com:org/repo.git')).toBe('github.com/org/repo')
    expect(sourceText({ ...gitops.apps[0], sourceCount: 3 })).toBe('github.com/example-org/argocd-argus-test · apps/argus-gitops-api @ main (+2 more sources)')
    expect(sourceText({ ...gitops.apps[0], repoURL: undefined, path: undefined, sourceRef: 'HelmRepository/podinfo', chart: 'podinfo', targetRevision: '6.5.x' })).toBe(
      'HelmRepository/podinfo · podinfo @ 6.5.x',
    )
    expect(destinationText(gitops.apps[0])).toBe('argus-gitops-rke2')
    expect(destinationText({ ...gitops.apps[0], destinationServer: 'https://prod.example:6443' })).toBe('argus-gitops-rke2 on prod.example:6443')
    const { groups, quiet } = groupProblems(gitops.apps)
    expect(groups.map((g) => [g.apps.length, g.causes.length])).toEqual([[2, 1]])
    expect(quiet.map((a) => a.name)).toEqual(['argus-e2e-guestbook'])
  })
})

// ---------------------------------------------------------------- Map

const index: NamespaceTopology = {
  observedAt: '2026-10-11T09:36:00Z',
  namespaces: [
    { name: 'cattle-monitoring-system', pods: 29, workloads: 16, services: 18, notHealthy: 0 },
    { name: 'nebula', pods: 37, workloads: 16, services: 8, notHealthy: 1 },
    { name: 'argus-gitops-rke2', pods: 10, workloads: 6, services: 1, notHealthy: 0 },
  ],
}

const deploy = (name: string, status = 'healthy') => ({ id: `deployment/nebula/${name}`, kind: 'Deployment', apiGroup: 'apps', namespace: 'nebula', name, status })
const nebulaGraph: NamespaceTopology = {
  observedAt: '2026-10-11T09:36:00Z',
  namespace: 'nebula',
  totalNodes: 160,
  omittedNodes: 10,
  omittedByKind: { ConfigMap: 6, ServiceAccount: 4 },
  clusterNodes: 5,
  nodes: [
    deploy('nebula-api'),
    deploy('nebula-control', 'unhealthy'),
    deploy('nebula-admin'),
    { id: 'podgroup/nebula/nebula-api', kind: 'PodGroup', namespace: 'nebula', name: 'nebula-api-768d', status: 'healthy', summary: { podCount: 2 } },
    { id: 'service/nebula/nebula-api', kind: 'Service', namespace: 'nebula', name: 'nebula-api', status: 'healthy' },
    { id: 'networkpolicy/nebula/nebula-default-deny', kind: 'NetworkPolicy', apiGroup: 'networking.k8s.io', namespace: 'nebula', name: 'nebula-default-deny', status: 'healthy' },
    { id: 'serviceaccount/nebula/nebula-api', kind: 'ServiceAccount', namespace: 'nebula', name: 'nebula-api', status: 'healthy' },
  ],
  edges: [
    { id: 'e1', source: 'deployment/nebula/nebula-api', target: 'podgroup/nebula/nebula-api', type: 'owns' },
    { id: 'e2', source: 'service/nebula/nebula-api', target: 'deployment/nebula/nebula-api', type: 'exposes' },
    { id: 'e3', source: 'networkpolicy/nebula/nebula-default-deny', target: 'deployment/nebula/nebula-api', type: 'protects' },
    { id: 'e4', source: 'networkpolicy/nebula/nebula-default-deny', target: 'deployment/nebula/nebula-control', type: 'protects' },
    { id: 'e5', source: 'networkpolicy/nebula/nebula-default-deny', target: 'deployment/nebula/nebula-admin', type: 'protects' },
    { id: 'e6', source: 'serviceaccount/nebula/nebula-api', target: 'deployment/nebula/nebula-api', type: 'configures' },
  ],
}

const incident = (ns: string, state = 'Open') => ({ id: `inc_${ns}_${Math.random()}`, state, objectNamespace: ns }) as unknown as Incident

function mockMap(graph: NamespaceTopology | Error = nebulaGraph) {
  mockInspect.mockImplementation((_c: string, _t: string, args: { namespace?: string }) => {
    if (!args.namespace) return Promise.resolve(ok(index))
    if (graph instanceof Error) return Promise.reject(graph)
    return Promise.resolve(ok({ ...graph, namespace: args.namespace }))
  })
}

describe('Map tab', () => {
  it('opens on the namespace with the most open incidents, as a card per workload in fixed lanes', async () => {
    mockMap()
    wrap(
      <NamespaceMapPanel
        clusterId="cl_1"
        clusterName="rke2"
        incidents={[incident('nebula'), incident('nebula'), incident('argus-gitops-rke2'), incident('cattle-monitoring-system', 'Resolved')]}
        liveness={live}
      />,
    )
    expect(await screen.findByText('Opened on nebula: most open incidents (2).')).toBeTruthy()
    // A healthy workload with no incident is one line; selecting it draws it in full.
    fireEvent.click(await screen.findByRole('button', { name: /nebula-api/, expanded: false }))
    const api = await screen.findByRole('article', { name: 'Deployment nebula-api' })
    // The lanes, in order, with each object's health as a word.
    const lanes = api.querySelectorAll('.nsmap-lane')
    expect([...lanes].map((l) => l.getAttribute('data-lane'))).toEqual(['entry', 'service', 'workload', 'pods'])
    expect(lanes[1].textContent).toContain('nebula-api')
    expect(lanes[1].textContent).toContain('Healthy')
    expect(lanes[3].textContent).toContain('all 2 healthy')
    // The unhealthy workload opens first and says so.
    const cards = screen.getAllByRole('article')
    expect(cards[0].getAttribute('aria-label')).toBe('Deployment nebula-control')
    expect(cards[0].textContent).toContain('Unhealthy')
    // The policy wired to every workload is listed once, not in each card.
    expect(screen.getByText(/guards 3 workloads · Healthy/)).toBeTruthy()
    expect(within(api).queryByText('nebula-default-deny')).toBeNull()
    expect(screen.getByText(/10 of 160 objects are not drawn \(6 ConfigMap, 4 ServiceAccount\)/)).toBeTruthy()
    expect(screen.getByText(/ · 5 nodes/)).toBeTruthy()
    // Two open incidents in the namespace, said beside what is not healthy now.
    expect(screen.getByRole('status').textContent).toMatch(/2 open incidents, 1 not healthy now/)
    // Config is hidden until asked for.
    expect(within(api).queryByText('ServiceAccount')).toBeNull()
    const config = screen.getByRole('button', { name: /Config & storage 1/ })
    expect(config.getAttribute('aria-pressed')).toBe('false')
    fireEvent.click(config)
    expect(within(screen.getByRole('article', { name: 'Deployment nebula-api' })).getByTitle(/^configures · ServiceAccount/)).toBeTruthy()
    // A kind with nothing in it cannot be toggled.
    expect((screen.getByRole('button', { name: /Autoscalers 0/ }) as HTMLButtonElement).disabled).toBe(true)
  })

  it('opens an object in the panel, finds by name, draws more on request, and follows the picker', async () => {
    mockMap()
    wrap(<NamespaceMapPanel clusterId="cl_1" clusterName="rke2" incidents={[]} liveness={live} />)
    // No open incident names a namespace: the largest one.
    expect(await screen.findByText(/Opened on cattle-monitoring-system: the largest namespace/)).toBeTruthy()
    fireEvent.click(await screen.findByRole('button', { name: /^Deployment\s*nebula-control/ }))
    expect(search()).toContain('panel=obj:cl_1:apps/Deployment:nebula/nebula-control')
    fireEvent.change(screen.getByLabelText('Find a workload or object'), { target: { value: 'admin' } })
    expect(screen.getByText(/Matching “admin” · 1/)).toBeTruthy()
    expect(screen.getAllByRole('article').map((a) => a.getAttribute('aria-label'))).toEqual(['Deployment nebula-admin'])
    fireEvent.change(screen.getByLabelText('Find a workload or object'), { target: { value: '' } })
    fireEvent.click(screen.getByRole('button', { name: 'Draw up to 300 objects' }))
    await waitFor(() => expect(mockInspect).toHaveBeenCalledWith('cl_1', 'get_namespace_topology', { namespace: 'cattle-monitoring-system', cap: 300 }, 't'))
    fireEvent.click(screen.getByRole('button', { name: /^argus-gitops-rke2/ }))
    await waitFor(() => expect(search()).toContain('mapns=argus-gitops-rke2'))
    await waitFor(() => expect(mockInspect).toHaveBeenCalledWith('cl_1', 'get_namespace_topology', { namespace: 'argus-gitops-rke2' }, 't'))
  })

  it('draws a workload healthy now but with an open incident in full, saying both', async () => {
    mockMap()
    const onPod = {
      id: 'inc_api',
      state: 'Detected',
      severity: 'critical',
      objectNamespace: 'nebula',
      objectGvk: 'v1/Pod',
      objectName: 'nebula-api-768d-abcde',
      firstSeen: '2026-10-10T10:00:00Z',
      lastSeen: '2026-10-10T11:00:00Z',
    } as unknown as Incident
    wrap(<NamespaceMapPanel clusterId="cl_1" clusterName="rke2" incidents={[onPod]} liveness={live} />)
    const api = await screen.findByRole('article', { name: 'Deployment nebula-api' })
    expect(within(api).getByText('Critical incident open')).toBeTruthy()
    expect(within(api).getByText('Healthy now')).toBeTruthy()
    expect(within(api).getByRole('link', { name: 'Incident →' }).getAttribute('href')).toBe('/incidents/inc_api')
  })

  it('says a namespace with nothing to draw is empty', async () => {
    mockMap({ ...nebulaGraph, nodes: [], edges: [], omittedNodes: 0, omittedByKind: {}, totalNodes: 0, clusterNodes: 0 })
    wrap(<NamespaceMapPanel clusterId="cl_1" clusterName="rke2" incidents={[]} liveness={live} />, '/clusters/cl_1?mapns=empty-ns')
    expect(await screen.findByText(/Namespace empty-ns has nothing the map draws/)).toBeTruthy()
    // A namespace someone chose needs no reason beside it.
    expect(screen.queryByText(/Opened on/)).toBeNull()
  })

  it('shows the agent error with a retry', async () => {
    mockMap(new ApiError('Agent error', 502, 'unknown tool "get_namespace_topology"'))
    wrap(<NamespaceMapPanel clusterId="cl_1" clusterName="rke2" incidents={[]} liveness={live} />)
    expect((await screen.findByRole('alert')).textContent).toContain('unknown tool')
  })

  it('names the missing capability and reads nothing', () => {
    caps.delete(CAP_CLUSTER_INSPECT)
    wrap(<NamespaceMapPanel clusterId="cl_1" clusterName="rke2" incidents={[]} liveness={live} />)
    expect(screen.getByRole('note')?.textContent).toContain('Namespace map runs a live read')
    expect(mockInspect).not.toHaveBeenCalled()
  })
})

describe('namespace map model', () => {
  it('puts each object in its workload card, lists the shared, and gathers the rest', () => {
    const m = buildNamespaceMap({
      ...nebulaGraph,
      nodes: [...(nebulaGraph.nodes ?? []), { id: 'pdb/x', kind: 'PodDisruptionBudget', namespace: 'nebula', name: 'nebula-db-primary', status: 'healthy' }],
    })
    const api = m.cards.find((c) => c.title === 'nebula-api')!
    expect(api.lanes.service.map((n) => n.name)).toEqual(['nebula-api'])
    expect(api.lanes.pods.map((n) => [n.name, n.openable])).toEqual([['nebula-api-768d', false]])
    expect(api.pods).toBe(2)
    expect(m.shared.map((x) => [x.node.name, x.workloads])).toEqual([['nebula-default-deny', 3]])
    expect(m.cards.at(-1)?.title).toBe(UNTIED_GROUP)
    expect(m.cards.at(-1)?.attached.map((n) => n.name)).toEqual(['nebula-db-primary'])
    expect(m.cards[0].title).toBe('nebula-control')
    expect(m.filterCounts.config).toBe(1)
    expect(nodeDetail('Service', { type: 'ClusterIP', ports: [{ port: 8080 }] })).toBe('ClusterIP :8080')
    expect(nodeDetail('Deployment', { replicas: 3, readyReplicas: 2 })).toBe('2/3 ready')
    expect(nodeDetail('PodGroup', { podCount: 3, unhealthy: 1, degraded: 0 })).toBe('1 of 3 not healthy')
  })

  it('counts the same thing in the picker and the status line, and its parts add up', () => {
    const m = buildNamespaceMap({
      ...nebulaGraph,
      nodes: [
        ...(nebulaGraph.nodes ?? []).map((n) => (n.id === 'podgroup/nebula/nebula-api' ? { ...n, status: 'unhealthy' } : n)),
        { id: 'pdb/x', kind: 'PodDisruptionBudget', namespace: 'nebula', name: 'nebula-db-primary', status: 'healthy' },
      ],
    })
    // 3 workloads: nebula-control is itself unhealthy; nebula-api is healthy
    // but its pod group is not; plus the untied card.
    expect(mapStatusCounts(m.cards)).toEqual({ workloads: 3, workloadsNotHealthy: 1, otherProblems: 1, untied: true })
    expect(mapStatusText(m.cards, 'nebula', 2, 2)).toBe(
      '3 workloads in nebula: 1 not healthy now; 1 card has a pod or object not healthy — shown first. 4 cards (one per workload, and one for objects tied to no single workload): 2 open, 2 collapsed to a line — select one to open it',
    )
    // The picker's workload figure is the agent's count of workloads whose own
    // health is bad — the same "1 not healthy" — with pods named apart.
    expect(namespaceOptionLabel({ name: 'nebula', pods: 37, workloads: 3, services: 8, notHealthy: 2, podsNotHealthy: 1, workloadsNotHealthy: 1 }, 0)).toBe(
      'nebula — 37 pods (1 not healthy), 3 workloads (1 not healthy), 8 Services',
    )
    // An agent that predates the split: the sum, said as exactly that.
    expect(namespaceOptionLabel({ name: 'apps', pods: 4, workloads: 2, services: 0, notHealthy: 2 }, 1)).toBe('apps — 4 pods, 2 workloads, 2 pods or workloads not healthy, 1 open incident')
  })

  it('opens every problem card and fills the rest of the budget in map order', () => {
    const cards = Array.from({ length: 9 }, (_, i) => ({ key: `c${i}`, problem: i === 8 }) as unknown as MapCard)
    const open = defaultOpen(cards)
    expect(open.size).toBe(OPEN_BY_DEFAULT)
    expect(open.has('c8')).toBe(true)
    expect(open.has('c7')).toBe(false)
    expect(mapPartialNote({ observedAt: '' })).toBeNull()
    expect(defaultNamespace([], [])).toBeNull()
    expect(defaultNamespace([incident('gone')], index.namespaces!)?.name).toBe('cattle-monitoring-system')
  })
})

// ---------------------------------------------------------------- Overview Checks

describe('Overview Checks, Helm row', () => {
  it('counts releases and links to the Helm tab', async () => {
    mockInspect.mockImplementation((_c: string, tool: string) =>
      Promise.resolve(ok(tool === 'list_helm_releases' ? helm : { observedAt: '2026-10-11T09:36:00Z', findings: [], certificates: [] })),
    )
    wrap(<ChecksCard clusterId="cl_1" summary={null} />)
    // The whole cell is the link to the Helm tab: label, answer, caption.
    const link = await screen.findByRole('link', { name: /^Helm releases/ })
    expect(link.getAttribute('href')).toBe('/clusters/cl_1?tab=helm')
    await waitFor(() => expect(link.textContent).toBe('Helm releases32 failing1 status not read'))
    expect(screen.getByRole('link', { name: 'GitOps' }).getAttribute('href')).toBe('/clusters/cl_1?tab=gitops')
  })
})
