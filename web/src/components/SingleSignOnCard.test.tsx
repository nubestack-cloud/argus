import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

const mockGetIdentityProviders = vi.fn()
const mockSaveIdentityProvider = vi.fn()
const mockAddMapping = vi.fn()
const mockGetRoles = vi.fn()

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    getIdentityProviders: (...a: unknown[]) => mockGetIdentityProviders(...a),
    saveIdentityProvider: (...a: unknown[]) => mockSaveIdentityProvider(...a),
    addIdentityGroupMapping: (...a: unknown[]) => mockAddMapping(...a),
    deleteIdentityGroupMapping: vi.fn(),
    deleteIdentityProvider: vi.fn(),
    getRoles: (...a: unknown[]) => mockGetRoles(...a),
  }
})
vi.mock('../auth/useAuth', () => ({ useAuth: () => ({ accessToken: 'test-token' }) }))

import { SingleSignOnCard } from './SingleSignOnCard'

const provider = {
  id: 'idp_1', displayName: 'Corp SSO', issuer: 'https://dex.example.com',
  clientId: 'argus', scopes: ['openid', 'groups'], groupsClaim: 'groups',
  redirectUri: 'http://localhost:8080/api/v1/auth/sso/callback',
  enabled: true, hasClientSecret: true,
  groupMappings: [{ id: 'idpg_1', groupName: 'platform', roleId: 'resolver' }],
}

function renderCard(canWrite = true) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <SingleSignOnCard canWrite={canWrite} disabledReason={canWrite ? undefined : 'Missing capability: identity:manage'} />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  mockGetIdentityProviders.mockReset(); mockSaveIdentityProvider.mockReset()
  mockAddMapping.mockReset(); mockGetRoles.mockReset()
  mockGetRoles.mockResolvedValue({ roles: { 'super-admin': { capabilities: [] }, resolver: { capabilities: [] }, viewer: { capabilities: [] } } })
})

describe('SingleSignOnCard (PROJECT.md S2)', () => {
  it('lists a configured provider with its group mappings', async () => {
    mockGetIdentityProviders.mockResolvedValue({ providers: [provider] })
    renderCard()
    expect(await screen.findByText('Corp SSO')).toBeTruthy()
    expect(screen.getByText('https://dex.example.com')).toBeTruthy()
    expect(screen.getByText('platform')).toBeTruthy()
    expect(screen.getByText(/resolver/)).toBeTruthy()
  })

  it('states the break-glass rule, because an admin cannot infer it', async () => {
    mockGetIdentityProviders.mockResolvedValue({ providers: [] })
    renderCard()
    // If this sentence goes, an operator has no way to know an IdP outage does
    // not lock them out — the reason the exception exists at all.
    expect(await screen.findByText(/super-admin/i)).toBeTruthy()
    expect(screen.getByText(/cannot lock every operator out/i)).toBeTruthy()
  })

  it('says plainly that nothing is granted when no groups are mapped', async () => {
    mockGetIdentityProviders.mockResolvedValue({
      providers: [{ ...provider, groupMappings: [] }],
    })
    renderCard()
    expect(await screen.findByText(/grants nothing yet/i)).toBeTruthy()
  })

  it('renders an honest empty state rather than a fabricated provider', async () => {
    mockGetIdentityProviders.mockResolvedValue({ providers: [] })
    renderCard()
    expect(await screen.findByText(/No identity provider configured/i)).toBeTruthy()
  })

  it('disables the controls with the missing capability named, never hiding them', async () => {
    mockGetIdentityProviders.mockResolvedValue({ providers: [provider] })
    renderCard(false)
    // Wait for the LIST, not just the page furniture: "Add a provider" renders
    // before the query settles, so asserting on it alone passed while the
    // per-provider controls had not mounted yet.
    await screen.findByText('Corp SSO')
    const add = screen.getByRole('button', { name: /Add a provider/i })
    expect(add).toHaveProperty('disabled', true)
    expect(add.title).toMatch(/identity:manage/)
    for (const name of [/Edit…/i, /Remove…/i, /Map a group…/i]) {
      const b = screen.getByRole('button', { name })
      expect(b).toHaveProperty('disabled', true)
      expect(b.title).toMatch(/identity:manage/)
    }
  })

  it('sends a null client secret on edit so a blank field keeps the stored one', async () => {
    mockGetIdentityProviders.mockResolvedValue({ providers: [provider] })
    mockSaveIdentityProvider.mockResolvedValue(provider)
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: /Edit…/i }))
    fireEvent.click(screen.getByRole('button', { name: /Save provider/i }))
    await waitFor(() => expect(mockSaveIdentityProvider).toHaveBeenCalled())
    const [body, , id] = mockSaveIdentityProvider.mock.calls[0]
    expect(body.clientSecret).toBeNull()
    expect(id).toBe('idp_1')
  })

  // PROJECT.md B189: internal/api/idp_admin.go declares Scopes as a plain
  // []string with no omitempty, so a provider stored with no extra scopes
  // arrives as JSON null. The hand-written type said string[], and opening the
  // edit form on such a provider threw on .join.
  it('opens the edit form for a provider whose scopes arrive as null, not []', async () => {
    mockGetIdentityProviders.mockResolvedValue({ providers: [{ ...provider, scopes: null }] })
    mockSaveIdentityProvider.mockResolvedValue(provider)
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: /Edit…/i }))
    expect((screen.getByLabelText(/Scopes/i) as HTMLInputElement).value).toBe('')
  })

  it('adds a group mapping through the real API', async () => {
    mockGetIdentityProviders.mockResolvedValue({ providers: [provider] })
    mockAddMapping.mockResolvedValue({ id: 'idpg_2', groupName: 'sre', roleId: 'viewer' })
    renderCard()
    fireEvent.click(await screen.findByRole('button', { name: /Map a group…/i }))
    fireEvent.change(screen.getByLabelText(/Group/i, { selector: 'input' }), { target: { value: 'sre' } })
    fireEvent.change(screen.getByLabelText(/Role/i), { target: { value: 'viewer' } })
    fireEvent.click(screen.getByRole('button', { name: /Add mapping/i }))
    await waitFor(() => expect(mockAddMapping).toHaveBeenCalledWith('idp_1', { groupName: 'sre', roleId: 'viewer' }, 'test-token'))
  })
})
