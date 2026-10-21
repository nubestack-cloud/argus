import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router-dom'

import { CAP_CLUSTER_INSPECT, CAP_CLUSTER_READ, CAP_INCIDENT_READ, CAP_MCP_USE } from '../api/capabilities'

const mockList = vi.fn()
const mockCreate = vi.fn()
const mockRevoke = vi.fn()

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    listPersonalTokens: (...a: unknown[]) => mockList(...a),
    createPersonalToken: (...a: unknown[]) => mockCreate(...a),
    revokePersonalToken: (...a: unknown[]) => mockRevoke(...a),
  }
})
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 'test-token' }) }))

const granted = new Set<string>()
let permissionsResolved = true
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (c: string) => granted.has(c),
  useMissingCapabilities: (caps: string[]) =>
    permissionsResolved ? { resolved: true, missing: caps.filter((c) => !granted.has(c)) } : { resolved: false, missing: [] },
}))

import { PersonalTokensSection } from './PersonalTokensSection'

const day = 86_400_000
const iso = (offsetMs: number) => new Date(Date.now() + offsetMs).toISOString()

// The shape GET /api/v1/users/me/mcp-tokens returns. No secret anywhere — the
// list never carries one.
function tokenList(over: Record<string, unknown> = {}) {
  return {
    tokens: [
      {
        id: 'pat_a',
        name: 'Claude Code — work laptop',
        hint: 'ad02',
        createdAt: iso(-2 * day),
        expiresAt: iso(88 * day),
        lastUsedAt: iso(-3 * 3_600_000),
        revokedAt: null,
        status: 'active',
      },
      {
        id: 'pat_b',
        name: 'Short-lived experiment',
        hint: 'ac38',
        createdAt: iso(-1 * day),
        expiresAt: iso(3 * day),
        lastUsedAt: null,
        revokedAt: null,
        status: 'active',
      },
      {
        id: 'pat_c',
        name: 'Old pairing token',
        hint: '9f3c',
        createdAt: iso(-100 * day),
        expiresAt: iso(-10 * day),
        lastUsedAt: null,
        revokedAt: null,
        status: 'expired',
      },
    ],
    defaultDays: 90,
    maxDays: 365,
    maxActive: 20,
    ...over,
  }
}

function renderSection() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <PersonalTokensSection />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  mockList.mockReset()
  mockCreate.mockReset()
  mockRevoke.mockReset()
  granted.clear()
  permissionsResolved = true
  for (const c of [CAP_MCP_USE, CAP_CLUSTER_READ, CAP_INCIDENT_READ, CAP_CLUSTER_INSPECT]) granted.add(c)
})

describe('PersonalTokensSection', () => {
  it('lists active tokens with status as words, and keeps ended ones behind an honest count', async () => {
    mockList.mockResolvedValue(tokenList())
    renderSection()

    const row = (await screen.findByText('Claude Code — work laptop')).closest('tr') as HTMLElement
    expect(within(row).getByText('Active')).toBeTruthy()
    expect(within(row).getByText('…ad02')).toBeTruthy()
    expect(within(row).getByText('3h ago')).toBeTruthy()

    const soon = screen.getByText('Short-lived experiment').closest('tr') as HTMLElement
    expect(within(soon).getByText('Never')).toBeTruthy()
    expect(within(soon).getByText('in 3 days')).toBeTruthy()

    // The expired token is not in the active table, but is counted and reachable.
    expect(screen.getByText('2 of 20 active')).toBeTruthy()
    const summary = screen.getByText(/Expired and revoked/)
    expect(summary.textContent).toContain('1')
    const expiredRow = screen.getByText('Old pairing token').closest('tr') as HTMLElement
    expect(within(expiredRow).getByText('Expired')).toBeTruthy()
    expect(within(expiredRow).queryByRole('button', { name: /Revoke/ })).toBeNull()
  })

  it('distinguishes "no tokens yet" from "none active"', async () => {
    mockList.mockResolvedValue(tokenList({ tokens: [] }))
    const { unmount } = renderSection()
    expect(await screen.findByText(/You have no tokens yet/)).toBeTruthy()
    unmount()

    mockList.mockResolvedValue(tokenList({ tokens: [tokenList().tokens[2]] }))
    renderSection()
    expect(await screen.findByText(/You have no active tokens\. 1 expired or revoked token is listed below/)).toBeTruthy()
  })

  it('shows the secret exactly once after creating, and fills it into the setup snippet', async () => {
    mockList.mockResolvedValue(tokenList())
    mockCreate.mockResolvedValue({
      token: { ...tokenList().tokens[0], id: 'pat_new', name: 'Cursor on the VM', hint: 'beef', status: 'active' },
      secret: 'argus_pat_01abcdefghijklmnopqrstuvwx_' + 'b'.repeat(60) + 'beef',
    })
    renderSection()
    await screen.findByText('Claude Code — work laptop')

    // The snippet starts with a placeholder, never a secret.
    expect(screen.getByText(/claude mcp add --transport http argus/).textContent).toContain('<your-token>')

    fireEvent.change(screen.getByLabelText('Name'), { target: { value: '  Cursor on the VM ' } })
    fireEvent.change(screen.getByLabelText('Expires after'), { target: { value: '30' } })
    fireEvent.click(screen.getByRole('button', { name: 'Create token' }))

    await waitFor(() => expect(mockCreate).toHaveBeenCalled())
    expect(mockCreate.mock.calls[0][0]).toEqual({ name: 'Cursor on the VM', expiresInDays: 30 })

    expect(await screen.findByText(/Copy “Cursor on the VM” now\./)).toBeTruthy()
    const secret = screen.getAllByText(/argus_pat_01abcdefghijklmnopqrstuvwx_/)
    expect(secret.length).toBeGreaterThanOrEqual(2) // the reveal and the Claude Code snippet
    expect(screen.getByRole('button', { name: 'Copy token' })).toBeTruthy()

    // VS Code's snippet never embeds the secret — it prompts for it.
    fireEvent.click(screen.getByRole('tab', { name: 'VS Code' }))
    const vscode = screen.getByText(/"servers"/).textContent ?? ''
    expect(vscode).toContain('${input:argus-token}')
    expect(vscode).not.toContain('argus_pat_')
    expect(vscode).toContain('"type": "http"')

    // Cursor's carries it, in Cursor's own mcpServers/url/headers shape.
    fireEvent.click(screen.getByRole('tab', { name: 'Cursor' }))
    const cursor = screen.getByText(/"mcpServers"/).textContent ?? ''
    expect(cursor).toContain('"headers"')
    expect(cursor).toContain('Bearer argus_pat_')

    // Done drops it; it cannot be shown again.
    fireEvent.click(screen.getByRole('button', { name: /Done — I have copied it/ }))
    expect(screen.queryByText(/argus_pat_01abcdefghijklmnopqrstuvwx_/)).toBeNull()
  })

  it('disables creation with the missing capability named, but still lists and revokes', async () => {
    granted.delete(CAP_MCP_USE)
    mockList.mockResolvedValue(tokenList())
    renderSection()
    await screen.findByText('Claude Code — work laptop')

    const create = screen.getByRole('button', { name: 'Create token' }) as HTMLButtonElement
    expect(create.disabled).toBe(true)
    expect(create.title).toContain('mcp:use')
    expect((screen.getByLabelText('Name') as HTMLInputElement).disabled).toBe(true)
    expect(screen.getAllByText(/You do not have permission to use ARGUS from your own AI tools/).length).toBeGreaterThan(0)

    // Revoking your own token is never gated.
    const revoke = within(screen.getByText('Claude Code — work laptop').closest('tr') as HTMLElement).getByRole('button', {
      name: /Revoke/,
    }) as HTMLButtonElement
    expect(revoke.disabled).toBe(false)

    // And the reach rows say why nothing works, rather than reporting "Yes".
    expect(screen.getAllByText('No — needs mcp:use').length).toBe(3)
  })

  it('disables creation at the active-token ceiling', async () => {
    mockList.mockResolvedValue(tokenList({ maxActive: 2 }))
    renderSection()
    await screen.findByText('Claude Code — work laptop')
    const create = screen.getByRole('button', { name: 'Create token' }) as HTMLButtonElement
    expect(create.disabled).toBe(true)
    expect(create.title).toContain('2 active tokens')
  })

  it('revokes only after a confirmation that names the token', async () => {
    mockList.mockResolvedValue(tokenList())
    mockRevoke.mockResolvedValue(undefined)
    renderSection()
    const row = (await screen.findByText('Claude Code — work laptop')).closest('tr') as HTMLElement
    fireEvent.click(within(row).getByRole('button', { name: /Revoke/ }))

    const dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByText(/stops working on its next request/)).toBeTruthy()
    expect(mockRevoke).not.toHaveBeenCalled()

    fireEvent.click(within(dialog).getByRole('button', { name: 'Revoke “Claude Code — work laptop”' }))
    await waitFor(() => expect(mockRevoke).toHaveBeenCalledWith('pat_a', 'test-token'))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  it('reports reach per capability, and says nothing until permissions are known', async () => {
    granted.delete(CAP_CLUSTER_INSPECT)
    mockList.mockResolvedValue(tokenList())
    const { unmount } = renderSection()
    await screen.findByText('Claude Code — work laptop')
    const rows = screen.getByText('What a connected tool can reach').nextElementSibling as HTMLElement
    expect(within(rows).getAllByText('Yes').length).toBe(2)
    expect(within(rows).getByText('No — needs cluster:inspect')).toBeTruthy()
    expect(within(rows).getByText(/Never\./)).toBeTruthy()
    unmount()

    permissionsResolved = false
    renderSection()
    await screen.findByText('Claude Code — work laptop')
    const pending = screen.getByText('What a connected tool can reach').nextElementSibling as HTMLElement
    expect(within(pending).queryByText('Yes')).toBeNull()
    expect(within(pending).getAllByText('—').length).toBe(3)
  })

  it('renders the hub problem when the list fails, not an empty list', async () => {
    const { ApiError } = await import('../api/client')
    mockList.mockRejectedValue(new ApiError('Could not list your tokens', 500, ''))
    renderSection()
    expect(await screen.findByRole('alert')).toBeTruthy()
    expect(screen.queryByText(/You have no tokens/)).toBeNull()
  })
})
