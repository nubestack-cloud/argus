import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, useLocation } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { CAP_AUDIT_READ, CAP_CLUSTER_INSPECT, CAP_CLUSTER_READ, CAP_INCIDENT_READ } from '../api/capabilities'
import { KeyboardShortcutProvider } from '../keyboard/shortcuts'

// CI-S18: Mod+K opens it, a page the viewer cannot use is listed disabled
// with the capability named, Enter navigates.

const mockIncidents = vi.fn()
const mockClusters = vi.fn()
const mockSearch = vi.fn()
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    getIncidents: (...a: unknown[]) => mockIncidents(...a),
    getClusters: (...a: unknown[]) => mockClusters(...a),
    searchObjects: (...a: unknown[]) => mockSearch(...a),
  }
})
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 't' }) }))
const caps = new Set<string>()
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (c: string) => caps.has(c),
  useMissingCapabilities: (list: string[]) => ({ resolved: true, missing: list.filter((c) => !caps.has(c)) }),
}))

import { CommandPaletteHost } from './CommandPalette'

function Loc() {
  const l = useLocation()
  return <p data-testid="loc">{l.pathname + l.search}</p>
}

function renderHost() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={['/overview']}>
        <KeyboardShortcutProvider mac={false}>
          <CommandPaletteHost />
          <Loc />
        </KeyboardShortcutProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  caps.clear()
  for (const c of [CAP_INCIDENT_READ, CAP_CLUSTER_READ, CAP_CLUSTER_INSPECT]) caps.add(c)
  mockIncidents.mockResolvedValue({ incidents: [] })
  mockClusters.mockResolvedValue({ clusters: [{ id: 'cl_1', displayName: 'prod-eu', state: 'Active' }] })
  mockSearch.mockResolvedValue({ query: '', hits: [], clustersQueried: 1, clustersAnswered: 1, clustersFailed: [], clustersDisconnected: [] })
})

describe('CommandPalette', () => {
  it('opens on Ctrl+K and lists a page the viewer lacks access to as disabled, naming the capability', () => {
    renderHost()
    expect(screen.queryByRole('dialog')).toBeNull()
    fireEvent.keyDown(document.body, { key: 'k', ctrlKey: true })
    expect(screen.getByRole('dialog', { name: 'Go to…' })).toBeTruthy()
    const audit = screen.getByRole('option', { name: /Audit Log/ })
    expect(audit.getAttribute('aria-disabled')).toBe('true')
    expect(audit.textContent).toMatch(new RegExp(CAP_AUDIT_READ))
  })

  it('ranks matches and navigates on Enter', async () => {
    renderHost()
    fireEvent.keyDown(document.body, { key: 'k', ctrlKey: true })
    const input = screen.getByRole('combobox')
    expect(document.activeElement).toBe(input)
    fireEvent.change(input, { target: { value: 'prod' } })
    expect(await screen.findByRole('option', { name: /prod-eu/ })).toBeTruthy()
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(screen.getByTestId('loc').textContent).toBe('/clusters/cl_1')
    expect(screen.queryByRole('dialog')).toBeNull()
  })

  it('does nothing on Enter over a disabled entry', () => {
    renderHost()
    fireEvent.keyDown(document.body, { key: 'k', ctrlKey: true })
    const input = screen.getByRole('combobox')
    fireEvent.change(input, { target: { value: 'audit log' } })
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(screen.getByTestId('loc').textContent).toBe('/overview')
    expect(screen.getByRole('dialog')).toBeTruthy()
  })
})
