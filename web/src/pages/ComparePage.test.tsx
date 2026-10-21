import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ApiError } from '../api/client'
import { CAP_CLUSTER_INSPECT } from '../api/capabilities'
import { encodeObjectPanel, type ObjectRef } from '../insight/panelUrl'

const mockInspect = vi.fn()
const mockGetCluster = vi.fn()
const mockSearch = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    inspectCluster: (...a: unknown[]) => mockInspect(...a),
    getCluster: (...a: unknown[]) => mockGetCluster(...a),
    searchObjects: (...a: unknown[]) => mockSearch(...a),
  }
})
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 't' }) }))
const granted = new Set<string>()
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (c: string) => granted.has(c),
  useMissingCapabilities: (caps: string[]) => ({ resolved: true, missing: caps.filter((c) => !granted.has(c)) }),
}))

import { ComparePage } from './ComparePage'

const pod = (name: string, image: string, phase = 'Running') => ({
  apiVersion: 'v1',
  kind: 'Pod',
  metadata: {
    name,
    namespace: 'apps',
    uid: `uid-${name}`,
    resourceVersion: String(name.length),
    labels: { app: 'web' },
    ownerReferences: [{ kind: 'ReplicaSet', name: 'web-6f9', controller: true }],
  },
  spec: { containers: [{ name: 'app', image, env: [{ name: 'TOKEN', value: '[REDACTED]' }] }] },
  status: { phase },
})

const refA: ObjectRef = { clusterId: 'c1', kind: 'Pod', namespace: 'apps', name: 'web-6f9-aaaaa' }
const refB: ObjectRef = { clusterId: 'c2', kind: 'Pod', namespace: 'apps', name: 'web-6f9-bbbbb' }
const objects: Record<string, unknown> = {
  'web-6f9-aaaaa': pod('web-6f9-aaaaa', 'r/web:1', 'Pending'),
  'web-6f9-bbbbb': pod('web-6f9-bbbbb', 'r/web:2'),
}

function renderAt(q: Record<string, string>) {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <MemoryRouter initialEntries={[`/compare?${new URLSearchParams(q)}`]}>
        <ComparePage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  granted.clear()
  granted.add(CAP_CLUSTER_INSPECT)
  mockInspect.mockReset()
  mockSearch.mockReset()
  mockGetCluster.mockImplementation((id: string) => Promise.resolve({ id, displayName: id === 'c1' ? 'rke2' : 'lab-dev', state: 'Active' }))
  mockInspect.mockImplementation((_c: string, tool: string, args: { name?: string }) => {
    if (tool === 'describe_resource') return Promise.resolve({ tool, receivedAt: new Date().toISOString(), result: { object: objects[args.name ?? ''], events: [] } })
    return Promise.resolve({ tool, receivedAt: new Date().toISOString(), result: { hits: [] } })
  })
})

const both = () => ({ a: encodeObjectPanel(refA), b: encodeObjectPanel(refB) })

describe('ComparePage', () => {
  it('shows both identities across clusters and a field summary of what differs', async () => {
    renderAt(both())
    const a = screen.getByRole('region', { name: 'Object A' })
    expect(within(a).getByText('apps/web-6f9-aaaaa')).toBeTruthy()
    await waitFor(() => expect(within(a).getByText('rke2')).toBeTruthy())
    expect(within(screen.getByRole('region', { name: 'Object B' })).getByText('lab-dev')).toBeTruthy()
    const summary = await screen.findByRole('region', { name: 'What differs' })
    expect(within(summary).getByText(/^2 fields differ: name, image$/)).toBeTruthy()
    expect(within(summary).getByRole('button', { name: 'spec.containers[app].image' })).toBeTruthy()
    // uid and resourceVersion differ between the two but are noise.
    expect(within(summary).queryByText(/metadata\.uid/)).toBeNull()
    expect(within(summary).getByText(/Hidden on both sides:.*uid.*status/)).toBeTruthy()
  })

  it('says redacted values were compared only as markers', async () => {
    renderAt(both())
    const summary = await screen.findByRole('region', { name: 'What differs' })
    expect(summary.textContent).toMatch(/1 value is redacted on both sides and is not counted as differing/)
    expect(within(summary).queryByText(/env\[TOKEN\]/)).toBeNull()
  })

  it('draws +/− markers with words, not colour alone, and folds nothing when everything is near a change', async () => {
    renderAt(both())
    const table = await screen.findByRole('table')
    expect(within(table).getAllByText('removed').length).toBeGreaterThan(0)
    expect(within(table).getAllByText('added').length).toBeGreaterThan(0)
    expect(table.textContent).toContain('−')
    expect(table.textContent).toContain('+')
    expect(table.textContent).toContain('‹redacted›')
  })

  it('switches to unified and shows status when asked, through the URL', async () => {
    renderAt({ ...both(), view: 'unified', status: '1' })
    const summary = await screen.findByRole('region', { name: 'What differs' })
    expect(within(summary).getByRole('button', { name: 'status.phase' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Unified' }).getAttribute('aria-pressed')).toBe('true')
    expect(document.querySelector('.compare-diff-unified')).toBeTruthy()
  })

  it('jumps to a changed field from the summary', async () => {
    renderAt(both())
    const summary = await screen.findByRole('region', { name: 'What differs' })
    fireEvent.click(within(summary).getByRole('button', { name: 'spec.containers[app].image' }))
    await waitFor(() => expect(document.querySelector('.compare-row-target')?.textContent).toContain('image'))
  })

  it('shows the empty state for identical objects', async () => {
    objects['web-6f9-ccccc'] = pod('web-6f9-ccccc', 'r/web:1')
    renderAt({ a: encodeObjectPanel(refA), b: encodeObjectPanel({ ...refB, name: 'web-6f9-ccccc' }), spec: '1' })
    expect(await screen.findByText(/No differences between A and B/)).toBeTruthy()
    expect(screen.getByText(/1 redacted value matches only as a redaction marker/)).toBeTruthy()
    expect(screen.queryByRole('region', { name: 'What differs' })).toBeNull()
  })

  it('loads each side on its own', async () => {
    let resolveB: (v: unknown) => void = () => {}
    mockInspect.mockImplementation((_c: string, tool: string, args: { name?: string }) => {
      if (args.name === refB.name) return new Promise((r) => (resolveB = r))
      return Promise.resolve({ tool, receivedAt: new Date().toISOString(), result: { object: objects[args.name ?? ''] } })
    })
    renderAt(both())
    await waitFor(() => expect(within(screen.getByRole('region', { name: 'Object A' })).getByText('Pending')).toBeTruthy())
    expect(within(screen.getByRole('region', { name: 'Object B' })).getByLabelText('Reading B')).toBeTruthy()
    expect(screen.getByLabelText('Reading both objects')).toBeTruthy()
    resolveB({ tool: 'describe_resource', receivedAt: new Date().toISOString(), result: { object: objects[refB.name] } })
    expect(await screen.findByRole('region', { name: 'What differs' })).toBeTruthy()
  })

  it('says which side could not be read, with the server’s reason, and does not diff', async () => {
    mockInspect.mockImplementation((_c: string, tool: string, args: { name?: string }) => {
      if (args.name === refB.name) return Promise.reject(new ApiError('Forbidden', 403, 'missing cluster:inspect on lab-dev'))
      return Promise.resolve({ tool, receivedAt: new Date().toISOString(), result: { object: objects[args.name ?? ''] } })
    })
    renderAt(both())
    const b = screen.getByRole('region', { name: 'Object B' })
    expect(await within(b).findByRole('alert')).toBeTruthy()
    expect(within(b).getByRole('alert').textContent).toContain('missing cluster:inspect on lab-dev')
    expect(await screen.findByText(/Nothing to compare until B can be read/)).toBeTruthy()
    expect(screen.queryByRole('table')).toBeNull()
  })

  it('says when one side no longer exists', async () => {
    renderAt({ a: encodeObjectPanel(refA), b: encodeObjectPanel({ ...refB, name: 'gone' }) })
    expect(await screen.findByText(/may have been deleted/)).toBeTruthy()
    expect(await screen.findByText(/Nothing to compare until B can be read/)).toBeTruthy()
  })

  it('refuses two different kinds', async () => {
    renderAt({ a: encodeObjectPanel(refA), b: encodeObjectPanel({ clusterId: 'c1', kind: 'Deployment', apiGroup: 'apps', namespace: 'apps', name: 'web' }) })
    expect((await screen.findByRole('alert')).textContent).toMatch(/A is of kind Pod and B is of kind Deployment \(apps\)\. Compare only works on two objects of one kind/)
    expect(screen.queryByRole('table')).toBeNull()
  })

  it('swaps A and B', async () => {
    renderAt(both())
    await screen.findByRole('region', { name: 'What differs' })
    fireEvent.click(screen.getByRole('button', { name: 'Swap A and B' }))
    await waitFor(() => expect(within(screen.getByRole('region', { name: 'Object A' })).getByText('apps/web-6f9-bbbbb')).toBeTruthy())
  })

  it('without cluster:inspect says so and disables choosing, rather than hiding it', () => {
    granted.clear()
    renderAt(both())
    expect(screen.getByText(/Restricted/)).toBeTruthy()
    const change = within(screen.getByRole('region', { name: 'Object A' })).getByRole('button', { name: 'Change…' }) as HTMLButtonElement
    expect(change.disabled).toBe(true)
    expect(mockInspect).not.toHaveBeenCalled()
  })

  it('opens B’s picker on arrival with the Pod’s sibling replicas, healthy first', async () => {
    mockInspect.mockImplementation((_c: string, tool: string) => {
      if (tool === 'search_objects')
        return Promise.resolve({
          tool,
          receivedAt: '',
          result: {
            hits: [
              { kind: 'Pod', namespace: 'apps', name: 'web-6f9-zzzzz', status: 'CrashLoopBackOff' },
              { kind: 'Pod', namespace: 'apps', name: 'web-6f9-bbbbb', status: 'Running' },
              { kind: 'Pod', namespace: 'apps', name: 'web-6f9-aaaaa', status: 'Pending' },
            ],
          },
        })
      return Promise.resolve({ tool, receivedAt: '', result: { object: { ...pod('web-6f9-aaaaa', 'r/web:1'), metadata: { ...(objects['web-6f9-aaaaa'] as { metadata: object }).metadata, labels: { 'pod-template-hash': '6f9' } } } } })
    })
    renderAt({ a: encodeObjectPanel(refA), pick: 'b' })
    const dialog = await screen.findByRole('dialog', { name: 'Choose object B' })
    const group = await within(dialog).findByRole('region', { name: /Sibling replicas of web/ })
    const names = within(group)
      .getAllByRole('button')
      .map((b) => b.textContent)
    expect(names[0]).toContain('web-6f9-bbbbb')
    expect(names[1]).toContain('web-6f9-zzzzz')
    expect(names.join()).not.toContain('web-6f9-aaaaa')
    fireEvent.click(within(group).getAllByRole('button')[0])
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(within(screen.getByRole('region', { name: 'Object B' })).getByText('apps/web-6f9-bbbbb')).toBeTruthy()
  })

  it('asks for both objects when none are chosen', () => {
    renderAt({})
    expect(screen.getByText(/Choose two objects of one kind to compare/)).toBeTruthy()
    expect(screen.getAllByRole('button', { name: 'Choose…' })).toHaveLength(2)
  })

  it('offers a Deployment’s namesakes elsewhere and marks a count from a partial search as a lower bound', async () => {
    const dep = { clusterId: 'c1', kind: 'Deployment', apiGroup: 'apps', namespace: 'apps', name: 'web' }
    mockInspect.mockImplementation((_c: string, tool: string) =>
      Promise.resolve({
        tool,
        receivedAt: '',
        result: tool === 'search_objects' ? { hits: [] } : { object: { apiVersion: 'apps/v1', kind: 'Deployment', metadata: { name: 'web', namespace: 'apps' } } },
      }),
    )
    mockSearch.mockResolvedValue({
      query: 'kind:Deployment web',
      hits: [
        { clusterId: 'c2', clusterName: 'lab-dev', score: 100, kind: 'Deployment', apiGroup: 'apps', namespace: 'apps', name: 'web', status: '1/1 ready' },
        { clusterId: 'c1', clusterName: 'rke2', score: 100, kind: 'Deployment', apiGroup: 'apps', namespace: 'apps', name: 'web', status: '1/1 ready' },
        { clusterId: 'c2', clusterName: 'lab-dev', score: 50, kind: 'Deployment', apiGroup: 'apps', namespace: 'apps', name: 'web-worker' },
      ],
      clustersQueried: 3,
      clustersAnswered: 2,
      clustersFailed: [],
      clustersDisconnected: [],
    })
    renderAt({ a: encodeObjectPanel(dep), pick: 'b' })
    const dialog = await screen.findByRole('dialog', { name: 'Choose object B' })
    const group = await within(dialog).findByRole('region', { name: /Same name in other namespaces or clusters/ })
    expect(within(group).getAllByRole('button').map((b) => b.textContent)).toEqual([expect.stringContaining('lab-dev')])
    expect(group.textContent).toContain('≥')
    expect(group.textContent).toContain('1 of 3 clusters did not answer')
    expect(mockSearch.mock.calls[0][0]).toBe('kind:Deployment web')
  })

  it('hides per-instance differences by default for two pods of one workload, says so, and leads with the revision', async () => {
    const mk = (hash: string, name: string, checksum: string) => ({
      apiVersion: 'v1',
      kind: 'Pod',
      metadata: {
        name,
        namespace: 'apps',
        labels: { 'pod-template-hash': hash },
        annotations: { checksum: checksum, 'cni.projectcalico.org/podIP': name },
        ownerReferences: [{ kind: 'ReplicaSet', name: `gwas-${hash}`, controller: true }],
      },
      spec: { nodeName: 'n1' },
    })
    objects['gwas-aaa-1'] = mk('aaa', 'gwas-aaa-1', 'old')
    objects['gwas-bbb-2'] = mk('bbb', 'gwas-bbb-2', 'new')
    const pa = { clusterId: 'c1', kind: 'Pod', namespace: 'apps', name: 'gwas-aaa-1' }
    renderAt({ a: encodeObjectPanel(pa), b: encodeObjectPanel({ ...pa, name: 'gwas-bbb-2' }) })
    const summary = await screen.findByRole('region', { name: 'What differs' })
    const leads = summary.querySelectorAll('.insight-lead')
    expect(leads[0].textContent).toBe('Different revisions of Deployment gwas (ReplicaSet gwas-aaa vs gwas-bbb)')
    expect(leads[1].textContent).toBe('1 field differs: checksum')
    expect(summary.textContent).toMatch(/Per-instance differences hidden — \d+ fields: ReplicaSet owner and pod-template-hash \(2\), pod name \(1\), CNI-assigned annotations \(1\)/)
    const box = screen.getByRole('checkbox', { name: 'Ignore per-instance differences' }) as HTMLInputElement
    expect(box.checked).toBe(true)
    fireEvent.click(box)
    await waitFor(() => expect(within(screen.getByRole('region', { name: 'What differs' })).getByRole('button', { name: 'metadata.name' })).toBeTruthy())
    expect(screen.queryByText(/Different revisions of Deployment/)).toBeNull()
  })

  it('leaves per-instance differences visible by default for objects of different workloads', async () => {
    renderAt(both())
    await screen.findByRole('region', { name: 'What differs' })
    expect((screen.getByRole('checkbox', { name: 'Ignore per-instance differences' }) as HTMLInputElement).checked).toBe(false)
  })
})
