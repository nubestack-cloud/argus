import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type {
  ClusterGroup,
  ClusterGroupsResponse,
  ClustersResponse,
  CreateUserResponse,
  CustomRole,
  CustomRolesResponse,
  User,
  UserLifecycleResponse,
  UsersResponse,
} from '../api/types'
import { CAP_USER_MANAGE, CAP_USER_REMOVE } from '../api/capabilities'

// BACKLOG P3. UsersPage is this app's RBAC admin console: search/status/role
// filters over a fetched list, a capability-gated "Create user" action, and a
// per-row ActionMenu whose Disable/Enable/Reset password/Remove/Add-grant
// items must be disabled-with-a-reason (never hidden) when the actor lacks
// user:manage — the exact discipline lld/11-ui-design.md §6 requires and
// argus-context's implementation-conventions point 10 calls a finding, not a
// style nit, when missing. This file was touched by unrelated work earlier
// today (adding the pr-approver role) — the fixtures and assertions below
// were written against ITS CURRENT shape, not an assumed older one.

const mockGetUsers = vi.fn()
const mockGetClusters = vi.fn()
const mockCreateUser = vi.fn()
const mockDisableUser = vi.fn()
const mockEnableUser = vi.fn()
const mockRemoveUser = vi.fn()
const mockResetPassword = vi.fn()
const mockRevokeGrant = vi.fn()
const mockCreateGrant = vi.fn()
const mockGetCustomRoles = vi.fn()
const mockGetClusterGroups = vi.fn()

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    getUsers: (...args: unknown[]) => mockGetUsers(...args),
    getClusters: (...args: unknown[]) => mockGetClusters(...args),
    createUser: (...args: unknown[]) => mockCreateUser(...args),
    disableUser: (...args: unknown[]) => mockDisableUser(...args),
    enableUser: (...args: unknown[]) => mockEnableUser(...args),
    removeUser: (...args: unknown[]) => mockRemoveUser(...args),
    resetPassword: (...args: unknown[]) => mockResetPassword(...args),
    revokeGrant: (...args: unknown[]) => mockRevokeGrant(...args),
    createGrant: (...args: unknown[]) => mockCreateGrant(...args),
    getCustomRoles: (...args: unknown[]) => mockGetCustomRoles(...args),
    getClusterGroups: (...args: unknown[]) => mockGetClusterGroups(...args),
  }
})

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({ accessToken: 'test-token' }),
}))

// Capability state is per-test mutable, read by the mocked hook — this is
// the same "deny by default unless a test says otherwise" posture the real
// hook has, just without needing a live effective-permissions fetch.
const capabilities = new Set<string>([CAP_USER_MANAGE, CAP_USER_REMOVE])
vi.mock('../auth/useCapabilities', () => ({
  useHasCapability: (capability: string) => capabilities.has(capability),
}))

import { UsersPage } from './UsersPage'
import { ApiError } from '../api/client'

function user(over: Partial<User>): User {
  return {
    id: 'usr_default',
    email: 'default@example.com',
    displayName: '',
    mustChangePassword: false,
    disabledAt: null,
    createdAt: '2026-08-01T00:00:00Z',
    grants: [],
    ...over,
  }
}

const ALICE = user({
  id: 'usr_alice',
  email: 'alice@example.com',
  displayName: 'Alice',
  grants: [
    {
      id: 'grant_alice',
      role: 'resolver',
      scope: { type: 'AllClusters' },
      grantedBy: 'admin@example.com',
      grantedAt: '2026-08-01T00:00:00Z',
      expiresAt: null,
    },
  ],
})

const BOB = user({
  id: 'usr_bob',
  email: 'bob@example.com',
  displayName: 'Bob',
  disabledAt: '2026-08-10T00:00:00Z',
})

function usersResponse(users: User[]): UsersResponse {
  return { users }
}

function clustersResponse(): ClustersResponse {
  return {
    clusters: [
      {
        id: 'cl_1',
        displayName: 'prod-eu',
        state: 'Active',
        agentVersion: '1.0',
        lastHeartbeatAt: null,
        createdAt: '2026-08-01T00:00:00Z',
        archivedAt: null,
        // T16: every Cluster now carries a server-computed verdict; this
        // suite doesn't exercise it, so a plain 'current' default is enough.
        compatibility: {
          verdict: 'current',
          label: 'Current',
          agentVersion: '1.0',
          minSupportedVersion: '1.0',
          recommendedVersion: '1.0',
          reason: 'Agent version 1.0 meets the recommended version 1.0.',
        },
      },
    ],
  }
}

function customRolesResponse(roles: CustomRole[] = []): CustomRolesResponse {
  return { roles }
}

function clusterGroupsResponse(groups: ClusterGroup[] = []): ClusterGroupsResponse {
  return { clusterGroups: groups }
}

function renderPage() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={queryClient}>
      <UsersPage />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  mockGetUsers.mockReset()
  mockGetClusters.mockReset().mockResolvedValue(clustersResponse())
  mockCreateUser.mockReset()
  mockDisableUser.mockReset()
  mockEnableUser.mockReset()
  mockRemoveUser.mockReset()
  mockResetPassword.mockReset()
  mockRevokeGrant.mockReset()
  mockCreateGrant.mockReset()
  mockGetCustomRoles.mockReset().mockResolvedValue(customRolesResponse())
  mockGetClusterGroups.mockReset().mockResolvedValue(clusterGroupsResponse())
  capabilities.clear()
  capabilities.add(CAP_USER_MANAGE)
  capabilities.add(CAP_USER_REMOVE)
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('UsersPage — loading, empty, and error states', () => {
  it('shows the empty state when there are no users at all', async () => {
    mockGetUsers.mockResolvedValue(usersResponse([]))
    renderPage()
    expect(await screen.findByText(/No users yet/i)).toBeTruthy()
  })

  it('shows the missing-capability banner on a 403, not a generic failure message', async () => {
    mockGetUsers.mockRejectedValue(new ApiError('Forbidden', 403, ''))
    renderPage()
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/don't have access to view users/i)
    expect(alert.textContent).toMatch(/user:read/)
  })
})

describe('UsersPage — search, status, and role filters', () => {
  beforeEach(() => {
    mockGetUsers.mockResolvedValue(usersResponse([ALICE, BOB]))
  })

  it('search narrows the table by email', async () => {
    renderPage()
    await screen.findByText('alice@example.com')
    fireEvent.change(screen.getByPlaceholderText(/Search name or email/i), { target: { value: 'bob' } })

    expect(screen.queryByText('alice@example.com')).toBeNull()
    expect(screen.getByText('bob@example.com')).toBeTruthy()
  })

  it('the status filter isolates disabled users', async () => {
    renderPage()
    await screen.findByText('alice@example.com')
    fireEvent.change(screen.getByLabelText(/Filter by status/i), { target: { value: 'disabled' } })

    expect(screen.queryByText('alice@example.com')).toBeNull()
    expect(screen.getByText('bob@example.com')).toBeTruthy()
  })

  it('the role filter matches on the grants a user actually holds', async () => {
    renderPage()
    await screen.findByText('alice@example.com')
    // Bob holds no grants at all, so filtering to any real role must drop him.
    fireEvent.change(screen.getByLabelText(/Filter by role/i), { target: { value: 'resolver' } })

    expect(screen.getByText('alice@example.com')).toBeTruthy()
    expect(screen.queryByText('bob@example.com')).toBeNull()
  })
})

describe('UsersPage — capability-gated controls are disabled, not hidden', () => {
  beforeEach(() => {
    mockGetUsers.mockResolvedValue(usersResponse([ALICE]))
  })

  it('disables "Create user" with the missing-capability reason when the actor lacks user:manage', async () => {
    capabilities.delete(CAP_USER_MANAGE)
    renderPage()
    await screen.findByText('alice@example.com')

    const createButton = screen.getByRole('button', { name: /Create user/i })
    expect(createButton).toHaveProperty('disabled', true)
    expect(createButton.title).toMatch(new RegExp(CAP_USER_MANAGE))
  })

  it('disables the "Remove user" menu item (but still shows it) when the actor lacks user:remove', async () => {
    capabilities.delete(CAP_USER_REMOVE)
    renderPage()
    await screen.findByText('alice@example.com')

    fireEvent.click(screen.getByRole('button', { name: /Actions for alice@example.com/i }))
    const removeItem = screen.getByRole('menuitem', { name: /Remove user/i })
    expect(removeItem).toHaveProperty('disabled', true)
    expect(removeItem.title).toMatch(new RegExp(CAP_USER_REMOVE))
  })
})

describe('UsersPage — actions with a real, checkable consequence', () => {
  it('disabling a user calls the API with that user\'s id and the row reflects the new status once it refetches', async () => {
    mockGetUsers
      .mockResolvedValueOnce(usersResponse([ALICE]))
      .mockResolvedValueOnce(usersResponse([{ ...ALICE, disabledAt: '2026-08-25T00:00:00Z' }]))
    mockDisableUser.mockResolvedValue({ userId: 'usr_alice', status: 'disabled' } as UserLifecycleResponse)
    const nativeConfirm = vi.spyOn(window, 'confirm')

    renderPage()
    await screen.findByText('alice@example.com')
    const row = () => screen.getByText('alice@example.com').closest('tr') as HTMLElement
    expect(within(row()).getByText('Active')).toBeTruthy()

    fireEvent.click(screen.getByRole('button', { name: /Actions for alice@example.com/i }))
    fireEvent.click(screen.getByRole('menuitem', { name: /^Disable$/i }))

    // The app's own dialog, naming the user — never the browser's prompt.
    const dialog = await screen.findByRole('dialog', { name: 'Disable user' })
    expect(within(dialog).getByText('alice@example.com')).toBeTruthy()
    expect(nativeConfirm).not.toHaveBeenCalled()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Disable user' }))
    await waitFor(() => expect(mockDisableUser).toHaveBeenCalledWith('usr_alice', 'test-token'))
    await waitFor(() => expect(within(row()).getByText('Disabled')).toBeTruthy())
    expect(within(row()).queryByText('Active')).toBeNull()
  })

  it('cancelling the confirm dialog does not call the API at all', async () => {
    mockGetUsers.mockResolvedValue(usersResponse([ALICE]))

    renderPage()
    await screen.findByText('alice@example.com')
    fireEvent.click(screen.getByRole('button', { name: /Actions for alice@example.com/i }))
    fireEvent.click(screen.getByRole('menuitem', { name: /^Disable$/i }))
    const dialog = await screen.findByRole('dialog', { name: 'Disable user' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }))

    expect(screen.queryByRole('dialog')).toBeNull()
    expect(mockDisableUser).not.toHaveBeenCalled()
  })

  it('a refused removal shows the hub\'s reason inside the dialog, which stays open', async () => {
    mockGetUsers.mockResolvedValue(usersResponse([ALICE]))
    mockRemoveUser.mockRejectedValue(new ApiError('Cannot remove the last remaining super-admin', 409, ''))

    renderPage()
    await screen.findByText('alice@example.com')
    fireEvent.click(screen.getByRole('button', { name: /Actions for alice@example.com/i }))
    fireEvent.click(screen.getByRole('menuitem', { name: /Remove user/i }))
    const dialog = await screen.findByRole('dialog', { name: 'Remove user' })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Remove user' }))
    expect(await within(dialog).findByText(/last remaining super-admin/)).toBeTruthy()
    expect(screen.getByRole('dialog', { name: 'Remove user' })).toBeTruthy()
  })

  it('creating a user submits the form fields and then shows the one-time temporary password', async () => {
    // BACKLOG D7e. Creating a user with a role granted at the same time now
    // confirms first, the same as every other privilege-affecting action on
    // this page — see the 'declining the confirm dialog' test above for the
    // same pattern applied to disable — as a step inside the dialog.
    mockGetUsers.mockResolvedValue(usersResponse([ALICE]))
    const created: CreateUserResponse = {
      user: user({ id: 'usr_new', email: 'newperson@example.com' }),
      temporaryPassword: 'temp-pw-xyz',
    }
    mockCreateUser.mockResolvedValue(created)

    renderPage()
    await screen.findByText('alice@example.com')
    fireEvent.click(screen.getByRole('button', { name: /Create user/i }))

    const dialog = await screen.findByRole('dialog')
    fireEvent.change(dialog.querySelector('#newUserEmail') as HTMLInputElement, {
      target: { value: 'newperson@example.com' },
    })
    fireEvent.click(within(dialog).getByRole('button', { name: /^Create user$/i }))
    // With a role granted, the dialog asks first — naming the user — and the
    // form stays in view above the question.
    expect(mockCreateUser).not.toHaveBeenCalled()
    expect(within(dialog).getByText('newperson@example.com', { selector: 'strong' })).toBeTruthy()
    fireEvent.click(within(dialog).getByRole('button', { name: /^Create user and grant$/i }))

    await waitFor(() => expect(mockCreateUser).toHaveBeenCalled())
    const [payload, token] = mockCreateUser.mock.calls[0]
    expect(payload.email).toBe('newperson@example.com')
    expect(token).toBe('test-token')

    expect(await screen.findByText('temp-pw-xyz')).toBeTruthy()
    // Operator wording, not the API field name.
    expect(screen.queryByText(/mustChangePassword/)).toBeNull()
  })
})

// BACKLOG.md S3 — custom roles and cluster groups reach this page through
// the EXISTING grant mechanism, not a parallel one: the role picker gains a
// second optgroup, and the scope picker gains a third option. No new control
// shape, so these tests focus on what's actually new: the extra option
// exists, and choosing it sends the right request shape.
describe('UsersPage — custom roles and cluster groups in the grant flow (BACKLOG S3)', () => {
  it('offers a fetched custom role alongside the five builtin ones when adding a grant', async () => {
    mockGetUsers.mockResolvedValue(usersResponse([ALICE]))
    mockGetCustomRoles.mockResolvedValue(customRolesResponse([{ id: 'crole_1', name: 'on-call-viewer', capabilities: ['incident:read'], createdBy: 'usr_admin', createdAt: '2026-08-30T00:00:00Z' }]))

    renderPage()
    await screen.findByText('alice@example.com')
    fireEvent.click(screen.getByRole('button', { name: /Actions for alice@example.com/i }))
    fireEvent.click(screen.getByRole('menuitem', { name: /Add grant/i }))

    const dialog = await screen.findByRole('dialog')
    const roleSelect = within(dialog).getByLabelText('Role') as HTMLSelectElement
    expect(within(roleSelect).getByRole('option', { name: 'on-call-viewer' })).toBeTruthy()
    expect(within(roleSelect).getByRole('option', { name: 'Resolver' })).toBeTruthy()
  })

  it('granting a custom role sends its id as the role, exactly like a builtin role name', async () => {
    mockGetUsers.mockResolvedValue(usersResponse([ALICE]))
    mockGetCustomRoles.mockResolvedValue(customRolesResponse([{ id: 'crole_1', name: 'on-call-viewer', capabilities: ['incident:read'], createdBy: 'usr_admin', createdAt: '2026-08-30T00:00:00Z' }]))
    mockCreateGrant.mockResolvedValue({
      id: 'grant_new',
      role: 'crole_1',
      scope: { type: 'AllClusters' },
      grantedBy: 'admin@example.com',
      grantedAt: '2026-08-30T00:00:00Z',
      expiresAt: null,
    })

    renderPage()
    await screen.findByText('alice@example.com')
    fireEvent.click(screen.getByRole('button', { name: /Actions for alice@example.com/i }))
    fireEvent.click(screen.getByRole('menuitem', { name: /Add grant/i }))

    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Role'), { target: { value: 'crole_1' } })
    fireEvent.click(within(dialog).getByRole('button', { name: /^Add grant$/i }))
    fireEvent.click(within(dialog).getByRole('button', { name: /^Confirm grant$/i }))

    await waitFor(() =>
      expect(mockCreateGrant).toHaveBeenCalledWith(
        'usr_alice',
        { role: 'crole_1', scope: { type: 'AllClusters' } },
        'test-token',
      ),
    )
  })

  it('choosing "A cluster group" scope sends a ClusterGroup scope with the selected group id', async () => {
    mockGetUsers.mockResolvedValue(usersResponse([ALICE]))
    mockGetClusterGroups.mockResolvedValue(
      clusterGroupsResponse([{ id: 'clg_1', name: 'payments-team', clusterIds: ['cl_1'] }]),
    )
    mockCreateGrant.mockResolvedValue({
      id: 'grant_new',
      role: 'viewer',
      scope: { type: 'ClusterGroup', clusterGroupId: 'clg_1' },
      grantedBy: 'admin@example.com',
      grantedAt: '2026-08-30T00:00:00Z',
      expiresAt: null,
    })

    renderPage()
    await screen.findByText('alice@example.com')
    fireEvent.click(screen.getByRole('button', { name: /Actions for alice@example.com/i }))
    fireEvent.click(screen.getByRole('menuitem', { name: /Add grant/i }))

    const dialog = await screen.findByRole('dialog')
    fireEvent.change(within(dialog).getByLabelText('Scope'), { target: { value: 'ClusterGroup' } })
    fireEvent.change(await within(dialog).findByLabelText('Cluster group'), { target: { value: 'clg_1' } })
    fireEvent.click(within(dialog).getByRole('button', { name: /^Add grant$/i }))
    fireEvent.click(within(dialog).getByRole('button', { name: /^Confirm grant$/i }))

    await waitFor(() =>
      expect(mockCreateGrant).toHaveBeenCalledWith(
        'usr_alice',
        { role: 'viewer', scope: { type: 'ClusterGroup', clusterGroupId: 'clg_1' } },
        'test-token',
      ),
    )
  })

  it('an existing grant scoped to a cluster group renders the group\'s real name, not its raw id', async () => {
    mockGetUsers.mockResolvedValue(
      usersResponse([
        {
          ...ALICE,
          grants: [
            {
              id: 'grant_alice_group',
              role: 'viewer',
              scope: { type: 'ClusterGroup', clusterGroupId: 'clg_1' },
              grantedBy: 'admin@example.com',
              grantedAt: '2026-08-01T00:00:00Z',
              expiresAt: null,
            },
          ],
        },
      ]),
    )
    mockGetClusterGroups.mockResolvedValue(
      clusterGroupsResponse([{ id: 'clg_1', name: 'payments-team', clusterIds: [] }]),
    )

    renderPage()
    await screen.findByText('alice@example.com')
    expect(await screen.findByText('@ Group: payments-team')).toBeTruthy()
    expect(screen.queryByText(/clg_1/)).toBeNull()
  })
})
