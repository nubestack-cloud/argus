import { describe, expect, it, vi, beforeEach } from 'vitest'
import { act, render, screen, waitFor } from '@testing-library/react'
import { CAP_REMEDIATION_APPROVE } from './api/capabilities'

// jsdom has no matchMedia implementation, and src/test/setup.ts deliberately
// doesn't polyfill it globally ("a test that needs [something like this]
// should set it up itself and say why" — its own header comment). Every
// other page test file renders its page in isolation, without AppShell, so
// none of them ever calls theme.ts's systemPrefersDark(); this file is the
// first to mount the real AppShell (via the real router/ProtectedAppLayout),
// which does on every render. Without this, every protected-route test below
// throws "window.matchMedia is not a function" and gets caught by the outer
// ErrorBoundary — a real crash, not a routing assertion failure, so it has to
// be fixed here rather than worked around in each test.
window.matchMedia = window.matchMedia || (() => ({
  matches: false,
  addEventListener: () => {},
  removeEventListener: () => {},
}))

// BACKLOG P3. Every other big-page test file renders one page component in
// isolation with a MemoryRouter wrapper it builds itself — none of them
// exercises App.tsx's own route table, ProtectedRoute's redirect-to-login
// gate, or the bootstrapping/error boundaries that wrap every route. This
// file mounts the real <App/> (real BrowserRouter, real ProtectedAppLayout,
// real lazy() route table) and asserts, per real path: an authenticated
// visitor gets the right page component, an unauthenticated one is bounced
// to /login, a still-bootstrapping session shows the loading gate rather than
// either, and a capability the mocked actor lacks degrades the way the real
// page already degrades (disabled-with-a-reason, never a blank screen or a
// crash) rather than being blocked at the router level (this app has no
// per-route capability guard — nav items render unconditionally, per
// AppShell's own comment — so "capability-gated route" means the page's own
// internal gating, which this test drives end to end through the real
// router).
//
// Every api/client function defaults to a promise that never resolves, so
// every page's own query stays in `isLoading` — deliberately: this file only
// has to prove ROUTING, not each page's data logic (already covered by that
// page's own test file), and every page in this codebase renders its <h1>
// unconditionally, before any isLoading/isError branch (verified by reading
// each of the ten big pages before writing this). Individual tests override
// one function's mock when a route's own behaviour genuinely depends on the
// response (the capability-gated Approvals case below).

let authState: {
  accessToken: string | null
  isBootstrapping: boolean
  userId: string | null
  email: string | null
  authMethod: 'password' | 'federated' | null
  identityStatus: 'pending' | 'ready' | 'unavailable'
  mustChangePassword: boolean
}
const deniedCapabilities = new Set<string>()

vi.mock('./auth/useAuth', () => ({
  useAuth: () => ({
    // Defaults for the Appearance/General effective-settings fields
    // (PROJECT.md, 2026-10-14) — not part of authState's own type below
    // since no test in this routing-only file varies them, but OverviewPage
    // (mounted via the real route table, not a mock) reads
    // overviewDefaultWindowDays reactively on every render once
    // identityStatus is 'ready', and `undefined` there is not a value the
    // real AuthContext ever produces (see AuthContextBase's own type).
    overviewDefaultWindowDays: 14,
    minPasswordLength: 12,
    sessionIdleTimeoutMinutes: null,
    endedForIdle: false,
    ...authState,
    login: vi.fn(),
    changePassword: vi.fn(),
    logout: vi.fn(),
  }),
}))

vi.mock('./auth/useCapabilities', () => ({
  // Grant-all by default (this file is testing routing, not RBAC UI, which
  // every page's own test file already covers) — individual tests deny one
  // capability via deniedCapabilities to drive the one route-level
  // capability-gating scenario this file does own.
  useHasCapability: (capability: string) => !deniedCapabilities.has(capability),
  // Same source of truth as useHasCapability above, so a test that denies a
  // capability sees it reported missing here too rather than the two mocks
  // disagreeing. `resolved: true` because this mock never has a pending
  // permissions fetch — the real hook returns false only while one is in
  // flight, and a route test that waited on that would hang.
  useMissingCapabilities: (capabilities: string[]) => ({
    resolved: true,
    missing: capabilities.filter((c) => deniedCapabilities.has(c)),
  }),
}))

vi.mock('./api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./api/client')>()
  const mocked: Record<string, unknown> = { ...actual }
  for (const [key, value] of Object.entries(actual)) {
    // Real exported functions are camelCase (getClusters, approveIncident,
    // ...); ApiError is a class and the PROBLEM_* entries are constants —
    // both start uppercase and must pass through untouched.
    if (typeof value === 'function' && /^[a-z]/.test(key)) {
      mocked[key] = vi.fn(() => new Promise(() => {}))
    }
  }
  return mocked
})

import * as client from './api/client'
import App from './App'

function resetApiMocksToPending() {
  for (const value of Object.values(client)) {
    if (vi.isMockFunction(value)) {
      value.mockReset()
      value.mockImplementation(() => new Promise(() => {}))
    }
  }
}

function renderAppAt(path: string) {
  window.history.pushState({}, '', path)
  return render(<App />)
}

beforeEach(() => {
  authState = {
    accessToken: 'test-token',
    isBootstrapping: false,
    userId: 'usr_admin',
    email: 'admin@example.com',
    authMethod: 'password',
    identityStatus: 'ready',
    mustChangePassword: false,
  }
  deniedCapabilities.clear()
  resetApiMocksToPending()
})

// Placed FIRST, deliberately, and not merely for narrative order: App.tsx's
// QueryClient is a module-level singleton (created once, not per render), so
// every test in this file shares one query cache for the process lifetime of
// this suite. getApprovals defaults to a promise that never resolves (see the
// header comment), and TanStack Query dedupes a still-in-flight fetch across
// remounts of the same query key rather than re-invoking the query function —
// so if any earlier test had already mounted a route touching the
// `['approvals']` key with that default mock, this test's own
// mockResolvedValue would never get called and isLoading would never turn
// false. Running this first, before the parametrized route list below ever
// visits `/approvals`, is what makes the mocked resolution actually reach the
// page.
describe('App — a route whose capability the actor lacks degrades in place, not to a blank page', () => {
  it('/approvals without remediation:approve still renders the queue heading and the disabled-controls note, never a blank screen', async () => {
    deniedCapabilities.add(CAP_REMEDIATION_APPROVE)
    vi.mocked(client.getApprovals).mockResolvedValue({ approvals: [], counts: { pending: 0, approved: 0, high: 0, medium: 0, low: 0 } })

    renderAppAt('/approvals')

    expect(await screen.findByRole('heading', { level: 1, name: 'Approvals' })).toBeTruthy()
    expect(await screen.findByText(new RegExp(`without ${CAP_REMEDIATION_APPROVE}`, 'i'))).toBeTruthy()
  })
})

describe('App — an authenticated visitor reaches the right page per real route', () => {
  it.each([
    ['/overview', 'Overview'],
    ['/clusters', 'Clusters'],
    ['/incidents', 'Incidents'],
    ['/tolerations', 'Tolerations'],
    ['/approvals', 'Approvals'],
    ['/users', 'Users'],
    ['/audit-log', 'Audit log'],
    ['/insights', 'Insights'],
    ['/settings', 'Settings'],
  ])('%s renders the %s page, not a blank screen or a crash', async (path, heading) => {
    renderAppAt(path)
    expect(await screen.findByRole('heading', { level: 1, name: heading })).toBeTruthy()
  })

  it('/clusters/:id renders ClusterDetailPage (a "Cluster" placeholder h1 while the fetch is pending, never blank)', async () => {
    renderAppAt('/clusters/cl_1')
    // The cluster page is the largest lazy chunk; its first import under a
    // full parallel run took ~1s, right at findBy's default wait.
    expect(await screen.findByRole('heading', { level: 1, name: 'Cluster' }, { timeout: 5000 })).toBeTruthy()
  })

  it('/incidents/:id renders IncidentDetailPage', async () => {
    renderAppAt('/incidents/inc_1')
    await waitFor(() => expect(document.querySelector('.incident-detail-page')).toBeTruthy())
  })

  it('/ redirects to /overview', async () => {
    renderAppAt('/')
    expect(await screen.findByRole('heading', { level: 1, name: 'Overview' })).toBeTruthy()
  })

  it('an unknown path redirects to /overview rather than a blank 404', async () => {
    renderAppAt('/this-route-does-not-exist')
    expect(await screen.findByRole('heading', { level: 1, name: 'Overview' })).toBeTruthy()
  })
})

describe('App — an unauthenticated visitor is bounced to /login, never shown a protected page', () => {
  it('hitting a protected route with no access token renders the login form', async () => {
    authState = {
      accessToken: null,
      isBootstrapping: false,
      userId: null,
      email: null,
      authMethod: null,
      identityStatus: 'pending',
      mustChangePassword: false,
    }
    renderAppAt('/clusters')
    expect(await screen.findByLabelText(/^Work email$/i)).toBeTruthy()
    expect(screen.queryByRole('heading', { level: 1, name: 'Clusters' })).toBeNull()
  })

  it('/login itself renders the form directly (not a redirect loop)', async () => {
    authState = {
      accessToken: null,
      isBootstrapping: false,
      userId: null,
      email: null,
      authMethod: null,
      identityStatus: 'pending',
      mustChangePassword: false,
    }
    renderAppAt('/login')
    expect(await screen.findByLabelText(/^Work email$/i)).toBeTruthy()
  })
})

describe('App — a still-bootstrapping session shows the loading gate, not the form or the page', () => {
  it('a protected route waits behind ProtectedRoute\'s own loading state while isBootstrapping is true', () => {
    authState = {
      accessToken: null,
      isBootstrapping: true,
      userId: null,
      email: null,
      authMethod: null,
      identityStatus: 'pending',
      mustChangePassword: false,
    }
    renderAppAt('/overview')
    expect(screen.getByText('Loading…')).toBeTruthy()
    expect(screen.queryByLabelText(/^Work email$/i)).toBeNull()
    expect(screen.queryByRole('heading', { level: 1, name: 'Overview' })).toBeNull()
  })
})

// The account control in the top bar (PROJECT.md B165). Tested here rather
// than in a component test because this file already mounts the REAL AppShell
// through the real router, which is the only place the identity states meet
// the markup that renders them.
describe('App — the account control names the session honestly and always offers sign out', () => {
  it('names the signed-in account once the identity is known', async () => {
    renderAppAt('/overview')
    expect(await screen.findByRole('button', { name: 'Account menu for admin@example.com' })).toBeTruthy()
  })

  it('still offers the menu, with no name and no invented placeholder, while the identity is loading', async () => {
    // A federated sign-in one moment after the exchange: tokens in hand,
    // identity not yet confirmed. Before B165 the whole control was gated on
    // knowing the email, so this state had no way to sign out at all.
    authState = {
      accessToken: 'test-token',
      isBootstrapping: false,
      userId: null,
      email: null,
      authMethod: null,
      identityStatus: 'pending',
      mustChangePassword: false,
    }
    renderAppAt('/overview')

    const trigger = await screen.findByRole('button', { name: 'Account menu' })
    act(() => trigger.click())
    expect(await screen.findByRole('menuitem', { name: 'Sign out' })).toBeTruthy()
    // No name, no stand-in for one.
    expect(screen.queryByText(/@/)).toBeNull()
    expect(screen.queryByText(/SSO user|Unknown user/i)).toBeNull()
  })

  it('says the account is unavailable, rather than guessing, when the identity could not be read', async () => {
    authState = {
      accessToken: 'test-token',
      isBootstrapping: false,
      userId: null,
      email: null,
      authMethod: null,
      identityStatus: 'unavailable',
      mustChangePassword: false,
    }
    renderAppAt('/overview')

    const trigger = await screen.findByRole('button', { name: 'Account menu' })
    expect(trigger.textContent).toContain('Account unavailable')
    act(() => trigger.click())
    expect(await screen.findByRole('menuitem', { name: 'Sign out' })).toBeTruthy()
  })

  it('disables changing a password for a federated account, with the reason, rather than hiding it', async () => {
    authState = {
      accessToken: 'test-token',
      isBootstrapping: false,
      userId: 'usr_federated',
      email: 'sso-user@example.com',
      authMethod: 'federated',
      identityStatus: 'ready',
      mustChangePassword: false,
    }
    renderAppAt('/overview')

    const trigger = await screen.findByRole('button', { name: 'Account menu for sso-user@example.com' })
    act(() => trigger.click())

    // Present in the DOM (lld/11 §6: disabled, never omitted), disabled, and
    // saying why — the flow behind it cannot work for an account with no ARGUS
    // password, and submitting it reached a 500 before this gate existed.
    const changePassword = await screen.findByRole('menuitem', { name: 'Change password' })
    expect((changePassword as HTMLButtonElement).disabled).toBe(true)
    expect(changePassword.getAttribute('title')).toMatch(/identity provider/i)

    // Signing out is never gated on any of this.
    expect((screen.getByRole('menuitem', { name: 'Sign out' }) as HTMLButtonElement).disabled).toBe(false)
  })

  it('leaves changing a password available for a local password account', async () => {
    renderAppAt('/overview')
    const trigger = await screen.findByRole('button', { name: 'Account menu for admin@example.com' })
    act(() => trigger.click())
    const changePassword = await screen.findByRole('menuitem', { name: 'Change password' })
    expect((changePassword as HTMLButtonElement).disabled).toBe(false)
  })
})

