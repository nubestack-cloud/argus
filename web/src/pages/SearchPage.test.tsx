import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CAP_CLUSTER_INSPECT } from '../api/capabilities'

// CI-S12: hits grouped by cluster, what was not searched stated in words,
// each hit opens the inspector over the page.

const mockSearch = vi.fn()
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return { ...actual, searchObjects: (...a: unknown[]) => mockSearch(...a) }
})
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 't' }) }))
const caps = new Set<string>()
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (c: string) => caps.has(c),
  useMissingCapabilities: (list: string[]) => ({ resolved: true, missing: list.filter((c) => !caps.has(c)) }),
}))

import { SearchPage } from './SearchPage'

function Loc() {
  return <p data-testid="loc">{useLocation().search}</p>
}

function renderAt(url: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={[url]}>
        <SearchPage />
        <Loc />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  caps.clear()
  caps.add(CAP_CLUSTER_INSPECT)
})

describe('SearchPage', () => {
  it('groups hits by cluster and names the clusters that did not answer', async () => {
    mockSearch.mockResolvedValue({
      query: 'payments',
      hits: [
        { clusterId: 'c1', clusterName: 'prod', score: 100, kind: 'Deployment', apiGroup: 'apps', namespace: 'shop', name: 'payments', status: '2/3 ready', matched: ['name'] },
        { clusterId: 'c2', clusterName: 'dev', score: 60, kind: 'Service', namespace: 'shop', name: 'payments-svc', matched: ['name'] },
      ],
      clustersQueried: 4,
      clustersAnswered: 2,
      clustersFailed: [{ id: 'c3', name: 'edge' }],
      clustersDisconnected: [{ id: 'c4', name: 'lab' }],
    })
    renderAt('/search?q=payments')
    expect(await screen.findByRole('region', { name: 'Matches on prod' })).toBeTruthy()
    expect(screen.getByRole('region', { name: 'Matches on dev' })).toBeTruthy()
    expect(screen.getByText(/1 cluster did not answer in time \(edge\)/)).toBeTruthy()
    expect(screen.getByText(/1 cluster is disconnected and could not be searched \(lab\)/)).toBeTruthy()
    expect(screen.getByText('2/3 ready')).toBeTruthy()
    expect(screen.getByText('No status reported')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'payments' }))
    expect(screen.getByTestId('loc').textContent).toContain('panel=obj%3Ac1%3Aapps%2FDeployment%3Ashop%2Fpayments')
    expect(screen.getByTestId('loc').textContent).toContain('q=payments')
  })

  it('distinguishes no matches from no query', async () => {
    mockSearch.mockResolvedValue({ query: 'zzz', hits: [], clustersQueried: 1, clustersAnswered: 1, clustersFailed: [], clustersDisconnected: [] })
    renderAt('/search')
    expect(screen.getByText(/Type at least 2 characters/)).toBeTruthy()
    fireEvent.change(screen.getByLabelText('Search objects'), { target: { value: 'zzz' } })
    await waitFor(() => expect(screen.getByText(/No objects match “zzz” on the 1 cluster that answered/)).toBeTruthy())
  })

  it('disables the search and names the capability when it is missing', () => {
    caps.clear()
    renderAt('/search?q=payments')
    expect((screen.getByLabelText('Search objects') as HTMLInputElement).disabled).toBe(true)
    expect(screen.getByRole('note').textContent).toMatch(/cluster:inspect/)
    expect(mockSearch).not.toHaveBeenCalled()
  })
})
