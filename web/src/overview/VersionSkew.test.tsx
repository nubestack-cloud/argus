import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { Application } from './VersionSkew'

const mockList = vi.fn()
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return { ...actual, listApplications: (...a: unknown[]) => mockList(...a) }
})
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 't' }) }))

import { VersionSkew } from './VersionSkew'

const inst = (clusterId: string, version: string) => ({ clusterId, clusterName: clusterId, kind: 'Helm release', namespace: 'argus-system', name: 'argus-agent', version })
const agent: Application = { key: 'a', name: 'argus-agent', matchedBy: 'name', instances: [inst('rke2', '12'), inst('lab-dev', '12')], skew: false }

function show(apps: Application[], scope = 'all') {
  mockList.mockResolvedValue({ asOf: '2026-10-15T10:00:00Z', applications: apps })
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const view = render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <VersionSkew scope={scope} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
  const loaded = () => vi.waitFor(() => expect(qc.getQueryState(['applications'])?.status).toBe('success'))
  return { ...view, loaded }
}

describe('VersionSkew', () => {
  beforeEach(() => mockList.mockReset())

  it('says nothing while every application runs one version', async () => {
    const { container, loaded } = show([agent])
    await loaded()
    expect(container.textContent).toBe('')
  })

  it('is one line, with each copy and its version behind it', async () => {
    show([{ ...agent, skew: true, instances: [inst('rke2', '12'), inst('lab-dev', '11')] }])
    const line = await screen.findByText(/different versions across clusters/)
    expect(line.textContent).toContain('1 application runs different versions')
    fireEvent.click(line)
    expect(screen.getByRole('link', { name: /lab-dev 11/ }).getAttribute('href')).toBe('/clusters/lab-dev?tab=helm')
    expect(screen.getByText('(by name)')).toBeTruthy()
  })

  it('leaves out skew on clusters outside the scope', async () => {
    const elsewhere = { ...agent, skew: true, instances: [inst('rke2', '12'), inst('prod', '11')] }
    const { container, loaded } = show([elsewhere], 'lab-dev')
    await loaded()
    expect(container.textContent).toBe('')
  })
})
