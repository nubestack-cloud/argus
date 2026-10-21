import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ApiError } from '../api/client'
import { CAP_CLUSTER_INSPECT, CAP_CLUSTER_READ } from '../api/capabilities'
import { encodeObjectPanel } from './panelUrl'

// Live QA on rke2/lab-dev, 2026-10-11 (fix agent FC): each test is one defect,
// against fixtures shaped like the objects it was found on.

const mockInspect = vi.fn()
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    inspectCluster: (...a: unknown[]) => mockInspect(...a),
    getCluster: () => Promise.resolve({ id: 'c1', displayName: 'lab-dev', state: 'Active', lastHeartbeatAt: new Date().toISOString() }),
    getResourceChanges: () => Promise.resolve({ changes: [], gaps: [] }),
  }
})
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 't' }) }))
vi.mock('../auth/useCapabilities', () => ({ useHasCapability: (c: string) => c === CAP_CLUSTER_INSPECT || c === CAP_CLUSTER_READ }))
vi.mock('../graph/GraphCanvas', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../graph/GraphCanvas')>()
  return { ...actual, GraphCanvas: () => <div data-testid="graph" /> }
})

import { ObjectInspectorHost } from './ObjectInspector'

type Answer = (tool: string, args: Record<string, unknown>) => unknown

function answerWith(fn: Answer) {
  mockInspect.mockImplementation((_c: string, tool: string, args: Record<string, unknown>) => {
    try {
      const result = fn(tool, args)
      if (result instanceof Error) return Promise.reject(result)
      return Promise.resolve({ tool, receivedAt: new Date().toISOString(), result })
    } catch (e) {
      return Promise.reject(e)
    }
  })
}

function renderAt(kind: string, apiGroup: string | undefined, name: string, namespace = 'apps', ptab?: string) {
  const panel = encodeObjectPanel({ clusterId: 'c1', kind, apiGroup, namespace, name })
  const qs = new URLSearchParams({ panel })
  if (ptab) qs.set('ptab', ptab)
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={[`/x?${qs}`]}>
        <ObjectInspectorHost />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

const gwasFrontend = {
  apiVersion: 'apps/v1',
  kind: 'Deployment',
  metadata: { name: 'gwas-frontend', namespace: 'apps', creationTimestamp: '2026-03-18T10:00:00Z', creationTimestampSecondsSince: 17280000 },
  spec: { replicas: 1, template: { spec: { containers: [{ name: 'frontend', image: 'gwas/frontend:18' }] } } },
  status: { observedGeneration: 18, replicas: 2, readyReplicas: 1, updatedReplicas: 1, availableReplicas: 1 },
}

// The agent draws a Deployment straight to its pods (ReplicaSets hidden).
const gwasNeighborhood = {
  root: { kind: 'Deployment', apiGroup: 'apps', namespace: 'apps', name: 'gwas-frontend' },
  nodes: [
    { id: 'd', kind: 'Deployment', apiGroup: 'apps', namespace: 'apps', name: 'gwas-frontend', status: 'degraded' },
    { id: 'p-old', kind: 'Pod', namespace: 'apps', name: 'gwas-frontend-86c9b566b8-thvcf', status: 'healthy', summary: { phase: 'Running', restarts: 0 } },
    { id: 'p-new', kind: 'Pod', namespace: 'apps', name: 'gwas-frontend-5dc7fb87d4-b65jw', status: 'degraded', statusReason: 'ContainerCreating', summary: { phase: 'Pending' } },
  ],
  edges: [
    { id: 'e1', source: 'd', target: 'p-old', type: 'owns' },
    { id: 'e2', source: 'd', target: 'p-new', type: 'owns' },
  ],
}

const runningPod = (name: string) => ({
  kind: 'Pod',
  metadata: { name, namespace: 'apps' },
  spec: { nodeName: 'w1', containers: [{ name: 'frontend', image: 'gwas/frontend:17' }] },
  status: { phase: 'Running', containerStatuses: [{ name: 'frontend', ready: true, restartCount: 0, state: { running: {} } }] },
})

const creatingPod = {
  kind: 'Pod',
  metadata: { name: 'gwas-frontend-5dc7fb87d4-b65jw', namespace: 'apps' },
  spec: { nodeName: 'lab-w2', containers: [{ name: 'frontend', image: 'gwas/frontend:18' }] },
  status: {
    phase: 'Pending',
    conditions: [{ type: 'PodScheduled', status: 'True' }],
    containerStatuses: [{ name: 'frontend', ready: false, restartCount: 0, state: { waiting: { reason: 'ContainerCreating' } } }],
  },
}

beforeEach(() => {
  mockInspect.mockReset()
})

describe('object panel — QA fixes', () => {
  it('lists a Deployment’s pods in Logs from the same read the Summary uses, and reads the running one', async () => {
    answerWith((tool, args) => {
      if (tool === 'describe_resource') return args.gvk === 'v1/Pod' ? { object: runningPod(String(args.name)) } : { object: gwasFrontend }
      if (tool === 'get_neighborhood') return gwasNeighborhood
      if (tool === 'get_logs') return { lines: ['listening on :8080'] }
      return {}
    })
    renderAt('Deployment', 'apps', 'gwas-frontend', 'apps', 'logs')
    const select = (await screen.findByLabelText('Pod')) as HTMLSelectElement
    expect(within(select).getAllByRole('option').map((o) => o.textContent)).toEqual([
      'gwas-frontend-5dc7fb87d4-b65jw — Pending, degraded',
      'gwas-frontend-86c9b566b8-thvcf — Running, healthy',
    ])
    expect(screen.queryByText(/owns no running pods/)).toBeNull()
    expect(mockInspect.mock.calls.some((c) => c[1] === 'get_owner_chain')).toBe(false)
    fireEvent.change(select, { target: { value: 'gwas-frontend-86c9b566b8-thvcf' } })
    expect(await screen.findByText('listening on :8080')).toBeTruthy()
  })

  it('says a ContainerCreating container has no logs instead of asking the agent, and offers no previous log without a restart', async () => {
    answerWith((tool) => (tool === 'describe_resource' ? { object: creatingPod } : {}))
    renderAt('Pod', undefined, 'gwas-frontend-5dc7fb87d4-b65jw', 'apps', 'logs')
    expect(await screen.findByText(/Container frontend has not started yet \(ContainerCreating\)/)).toBeTruthy()
    expect(mockInspect.mock.calls.some((c) => c[1] === 'get_logs')).toBe(false)
    expect((screen.getByRole('checkbox', { name: /Previous container/ }) as HTMLInputElement).disabled).toBe(true)
  })

  it('shows the agent’s own reason when a read fails', async () => {
    answerWith((tool) => {
      if (tool === 'describe_resource') return { object: runningPod('web-1') }
      if (tool === 'get_logs') return new ApiError('The agent could not answer', 502, 'The agent reported: pods "web-1" not found.')
      return {}
    })
    renderAt('Pod', undefined, 'web-1', 'apps', 'logs')
    expect(await screen.findByText(/The agent reported: pods "web-1" not found\./)).toBeTruthy()
  })

  it('hides the agent’s *SecondsSince helpers from the YAML and its copy', async () => {
    answerWith((tool) => (tool === 'describe_resource' ? { object: gwasFrontend } : {}))
    renderAt('Deployment', 'apps', 'gwas-frontend', 'apps', 'yaml')
    await screen.findByRole('button', { name: 'Copy YAML' })
    const yaml = screen.getByLabelText(/as YAML/).textContent ?? ''
    expect(yaml).toContain('creationTimestamp')
    expect(yaml).not.toContain('SecondsSince')
  })

  it('keeps a failed relationship read quiet on the Summary, and says when a kind is not mapped', async () => {
    const app = { apiVersion: 'argoproj.io/v1alpha1', kind: 'Application', metadata: { name: 'argus-gitops-api', namespace: 'argocd' }, spec: {}, status: {} }
    answerWith((tool) => {
      if (tool === 'describe_resource') return { object: app }
      if (tool === 'get_neighborhood') return new ApiError('The agent could not answer', 502, 'The agent reported: unsupported kind.')
      return {}
    })
    const { unmount } = renderAt('Application', 'argoproj.io', 'argus-gitops-api', 'argocd')
    expect(await screen.findByText(/Relationships could not be read for this object/)).toBeTruthy()
    expect(within(screen.getByRole('region', { name: 'Connected objects' })).queryByRole('alert')).toBeNull()
    unmount()

    answerWith((tool) => {
      if (tool === 'describe_resource') return { object: app }
      if (tool === 'get_neighborhood') return { root: { kind: 'Application', name: 'argus-gitops-api' }, nodes: [], edges: [], unmapped: true, note: 'Relationships for Application are not mapped yet.' }
      return {}
    })
    renderAt('Application', 'argoproj.io', 'argus-gitops-api', 'argocd')
    expect(await screen.findByText('Relationships for Application are not mapped yet.')).toBeTruthy()
  })

  it('shows the pods a ServiceAccount configures under Connected, as Related does', async () => {
    const sa = { kind: 'ServiceAccount', metadata: { name: 'default', namespace: 'apps' } }
    answerWith((tool) => {
      if (tool === 'describe_resource') return { object: sa }
      if (tool === 'get_neighborhood')
        return {
          root: { kind: 'ServiceAccount', namespace: 'apps', name: 'default' },
          nodes: [
            { id: 'sa', kind: 'ServiceAccount', namespace: 'apps', name: 'default' },
            { id: 'p1', kind: 'Pod', namespace: 'apps', name: 'farmreport-676747fd55-c4dhk', status: 'healthy' },
            { id: 'p2', kind: 'Pod', namespace: 'apps', name: 'gwas-db-6f48fb4464-d5bt2', status: 'healthy' },
          ],
          edges: [
            { id: 'c1', source: 'sa', target: 'p1', type: 'configures' },
            { id: 'c2', source: 'sa', target: 'p2', type: 'configures' },
          ],
        }
      return {}
    })
    renderAt('ServiceAccount', undefined, 'default', 'apps', 'summary')
    const card = await screen.findByRole('region', { name: 'Connected objects' })
    await waitFor(() => expect(within(card).getByRole('button', { name: /farmreport-676747fd55-c4dhk/ })).toBeTruthy())
    expect(within(card).queryByText(/Nothing is connected/)).toBeNull()
  })

  it('keeps focus on the newly active tab when an arrow key changes it', async () => {
    answerWith((tool) => (tool === 'describe_resource' ? { object: gwasFrontend } : tool === 'get_neighborhood' ? gwasNeighborhood : {}))
    renderAt('Deployment', 'apps', 'gwas-frontend')
    const summary = screen.getByRole('tab', { name: 'Summary' })
    summary.focus()
    fireEvent.keyDown(summary, { key: 'ArrowRight' })
    const rollout = screen.getByRole('tab', { name: 'Rollout' })
    await waitFor(() => expect(rollout.getAttribute('aria-selected')).toBe('true'))
    expect(document.activeElement).toBe(rollout)
    fireEvent.keyDown(rollout, { key: 'ArrowRight' })
    const events = screen.getByRole('tab', { name: 'Events' })
    await waitFor(() => expect(events.getAttribute('aria-selected')).toBe('true'))
    expect(document.activeElement).toBe(events)
  })

  it('gives an Ingress its routing table and a Service its ports, selector and ready endpoints', async () => {
    const ing = {
      kind: 'Ingress',
      metadata: { name: 'gwas-frontend', namespace: 'apps' },
      spec: {
        ingressClassName: 'nginx',
        tls: [{ hosts: ['gwas.lab.example.org'], secretName: 'gwas-tls' }],
        rules: [{ host: 'gwas.lab.example.org', http: { paths: [{ path: '/', pathType: 'Prefix', backend: { service: { name: 'gwas-frontend', port: { number: 80 } } } }] } }],
      },
      status: { loadBalancer: { ingress: [{ ip: '192.0.2.10' }] } },
    }
    answerWith((tool) => (tool === 'describe_resource' ? { object: ing } : {}))
    const { unmount } = renderAt('Ingress', 'networking.k8s.io', 'gwas-frontend')
    const routing = await screen.findByRole('region', { name: 'Routing' })
    expect(within(routing).getByText('gwas.lab.example.org')).toBeTruthy()
    expect(within(routing).getByRole('button', { name: 'gwas-frontend:80' })).toBeTruthy()
    expect(within(routing).getByText(/secret gwas-tls/)).toBeTruthy()
    expect(within(routing).getByText(/class nginx · address 192\.0\.2\.10/)).toBeTruthy()
    unmount()

    const svc = {
      kind: 'Service',
      metadata: { name: 'gwas-frontend', namespace: 'apps' },
      spec: { type: 'ClusterIP', clusterIP: '10.43.12.7', selector: { app: 'gwas-frontend' }, ports: [{ name: 'http', port: 80, targetPort: 8080, protocol: 'TCP' }] },
    }
    const endpoints = { kind: 'Endpoints', metadata: { name: 'gwas-frontend' }, subsets: [{ addresses: [{ ip: '10.42.1.5' }], notReadyAddresses: [{ ip: '10.42.2.9' }] }] }
    answerWith((tool, args) => (tool === 'describe_resource' ? { object: args.gvk === 'v1/Endpoints' ? endpoints : svc } : {}))
    renderAt('Service', undefined, 'gwas-frontend')
    const card = await screen.findByRole('region', { name: 'Service' })
    expect(within(card).getByText('http 80→8080/TCP')).toBeTruthy()
    expect(within(card).getByText('app=gwas-frontend')).toBeTruthy()
    await waitFor(() => expect(card.textContent).toContain('1 ready, 1 not ready'))
  })

  it('leads the GitOps tab with the comparison error, not the last successful operation', async () => {
    answerWith((tool) => {
      if (tool === 'describe_resource') return { object: { kind: 'Application', metadata: { name: 'argus-gitops-api', namespace: 'argocd' } } }
      if (tool === 'get_gitops_insight')
        return {
          summary: {
            tool: 'argocd',
            kind: 'Application',
            namespace: 'argocd',
            name: 'argus-gitops-api',
            sync: 'Unknown',
            health: 'Healthy',
            operationPhase: 'Succeeded',
            operationMessage: 'successfully synced (all tasks run)',
            conditions: [{ type: 'ComparisonError', message: 'Failed to load target state: authentication required', action: 'Verify the repo URL.' }],
          },
        }
      return {}
    })
    renderAt('Application', 'argoproj.io', 'argus-gitops-api', 'argocd', 'gitops')
    const lead = await screen.findByText(/Sync is Unknown: Comparison error\./)
    expect(lead.closest('p')?.textContent).toContain('authentication required')
    expect(screen.getByText(/Last operation \(Succeeded\) — what the controller last ran/)).toBeTruthy()
  })

  it('reports a stuck single-replica rollout as stuck, with the pod holding it up, and the replica note as a note', async () => {
    answerWith((tool) => {
      if (tool === 'describe_resource') return { object: gwasFrontend }
      if (tool === 'diagnose_rollout')
        return {
          verdict: 'stuck',
          reason: 'The rollout is stuck (ProgressDeadlineExceeded): ReplicaSet "gwas-frontend-5dc7fb87d4" has timed out progressing.',
          strategy: 'RollingUpdate',
          replicas: 1,
          progress: {
            state: 'stuck',
            conditionReason: 'ProgressDeadlineExceeded',
            desired: 1,
            updated: 1,
            ready: 1,
            available: 1,
            newReplicaSet: 'gwas-frontend-5dc7fb87d4',
            notReadyPods: [{ name: 'gwas-frontend-5dc7fb87d4-b65jw', phase: 'Pending', waiting: 'ContainerCreating', node: 'lab-w2' }],
          },
          policyVerdict: 'notApplicable',
          policyReason: 'Availability during a rollout needs at least 2 replicas.',
          notes: ['With 1 replica, any rollout briefly has no ready replica unless maxSurge adds one first.'],
        }
      return {}
    })
    renderAt('Deployment', 'apps', 'gwas-frontend', 'apps', 'rollout')
    expect(await screen.findByText('Stuck')).toBeTruthy()
    expect(screen.getByText(/has timed out progressing/)).toBeTruthy()
    expect(screen.queryByText(/^Not applicable: the Deployment wants/)).toBeNull()
    expect(screen.getByText('gwas-frontend-5dc7fb87d4-b65jw')).toBeTruthy()
    expect(screen.getByText(/Pending · ContainerCreating · on lab-w2/)).toBeTruthy()
    expect(screen.getByText(/With 1 replica, any rollout briefly/)).toBeTruthy()
  })
})
