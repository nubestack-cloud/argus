import { describe, expect, it, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { ApiError } from '../api/client'

const mockSsoProviders = vi.fn()
vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return { ...actual, ssoProviders: (...args: []) => mockSsoProviders(...args) }
})

// jsdom has no matchMedia implementation, and src/test/setup.ts deliberately
// doesn't polyfill it globally (see App.test.tsx's own copy of this shim for
// the established reason). Every other test in this file keeps loginStyle at
// its default ('aperture'), so SentinelFieldLogin's own reduced-motion check
// for its particle field (`window.matchMedia(...).matches`) is never reached
// — the retry-converges test below is the first to actually mount it.
window.matchMedia =
  window.matchMedia ||
  (() => ({
    matches: false,
    addEventListener: () => {},
    removeEventListener: () => {},
  }))

// BACKLOG P3. LoginPage is small but not logic-free: an isBootstrapping
// state that (per D7j / mode G) must render a skeleton rather than the
// centred spinner it used to, an already-authenticated visitor who must be
// redirected rather than shown the form again, a requested-path redirect
// target carried through location.state, and real ApiError-vs-generic error
// rendering around the login() call. useAuth is mocked directly (as
// UsersPage/ApprovalsPage mock useAuth for their own accessToken) rather
// than mounting the real AuthProvider, since this page's own logic is what's
// under test, not AuthContext's (which AuthContext.test.tsx already covers).

const mockLogin = vi.fn()
let authState: { accessToken: string | null; isBootstrapping: boolean; signOut?: 'confirmed' | 'unconfirmed' | null }

vi.mock('../auth/useAuth', () => ({
  useAuth: () => ({
    accessToken: authState.accessToken,
    isBootstrapping: authState.isBootstrapping,
    login: mockLogin,
    signOut: authState.signOut ?? null,
  }),
}))

import { LoginPage } from './LoginPage'

function renderPage(options: { initialEntries?: Array<string | { pathname: string; state?: unknown }> } = {}) {
  return render(
    <MemoryRouter initialEntries={options.initialEntries ?? ['/login']}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/overview" element={<div>OVERVIEW SCREEN</div>} />
        <Route path="/clusters/cl_1" element={<div>REQUESTED SCREEN</div>} />
      </Routes>
    </MemoryRouter>,
  )
}

beforeEach(() => {
  mockLogin.mockReset()
  authState = { accessToken: null, isBootstrapping: false }
  mockSsoProviders.mockReset()
  mockSsoProviders.mockResolvedValue({ providers: [], loginStyle: 'aperture', version: 'test' })
})

describe('LoginPage — bootstrapping state', () => {
  // CHANGED WITH THE PORT, deliberately, and this test records the trade so
  // D7j's intent is not lost silently.
  //
  // D7j / mode G asked for a skeleton here rather than a spinner, so the
  // loading state matches the shape of what replaces it. The three ported
  // sign-in screens each open with their own entrance animation (card rise,
  // iris open, tile pop) and none has a form-shaped slot a skeleton could sit
  // in — mounting one and then remounting the real form would play that
  // entrance twice. Bootstrapping is one refresh-token call, so this renders
  // nothing at all rather than flashing a screen the viewer never needed.
  it('renders nothing while the session restore is in flight — no spinner, no half-screen', () => {
    authState = { accessToken: null, isBootstrapping: true }
    const { container } = renderPage()

    expect(screen.queryByText(/^Loading…$/i)).toBeNull()
    expect(container.querySelector('form')).toBeNull()
    expect(screen.queryByLabelText(/^Work email$/i)).toBeNull()
  })
})

describe('LoginPage — an already-authenticated visitor is redirected, not shown the form', () => {
  it('redirects to /overview by default', async () => {
    authState = { accessToken: 'already-have-a-token', isBootstrapping: false }
    renderPage()
    expect(await screen.findByText('OVERVIEW SCREEN')).toBeTruthy()
    expect(screen.queryByLabelText(/^Work email$/i)).toBeNull()
  })

  it('redirects to the originally requested path when one is carried in location.state', async () => {
    authState = { accessToken: 'already-have-a-token', isBootstrapping: false }
    renderPage({ initialEntries: [{ pathname: '/login', state: { from: { pathname: '/clusters/cl_1' } } }] })
    expect(await screen.findByText('REQUESTED SCREEN')).toBeTruthy()
  })
})

// Live QA 2026-10-11: the next person to sign in after a sign-out landed on
// the previous user's last page.
describe('LoginPage — after an explicit sign-out', () => {
  it('ignores a requested path that survived the sign-out and lands the next sign-in on /overview', async () => {
    mockLogin.mockResolvedValue(undefined)
    authState = { accessToken: null, isBootstrapping: false, signOut: 'confirmed' }
    renderPage({ initialEntries: [{ pathname: '/login', state: { from: { pathname: '/clusters/cl_1' } } }] })
    fireEvent.change(screen.getByLabelText(/^Work email$/i), { target: { value: 'bob@example.com' } })
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'pw' } })
    fireEvent.click(screen.getByRole('button', { name: /^Sign in$/i }))
    expect(await screen.findByText('OVERVIEW SCREEN')).toBeTruthy()
    expect(screen.queryByText('REQUESTED SCREEN')).toBeNull()
  })

  it('says so when the hub did not confirm the sign-out', async () => {
    authState = { accessToken: null, isBootstrapping: false, signOut: 'unconfirmed' }
    renderPage()
    expect(await screen.findByText(/didn't confirm it ended the session/)).toBeTruthy()
  })
})

describe('LoginPage — login style converges even after a failed first fetch', () => {
  // The actual bug reported live: the unauthenticated providers/style call
  // (ssoProviders) landing in a brief network gap — the same kind a tab
  // waking from idle/sleep can hit — used to fail silently with no retry,
  // so loginStyle stayed undefined (rendered the same as the 'aperture'
  // default) for the rest of that mount, even once the network recovered.
  // A plain reload "fixed" it only because it remounted the page and got a
  // fresh attempt — this asserts the SAME mount recovers on its own.
  it('retries the failed fetch and renders the real configured style once it succeeds', async () => {
    mockSsoProviders
      .mockRejectedValueOnce(new ApiError('Network error', 0, 'Could not reach the ARGUS hub API.'))
      .mockResolvedValueOnce({ providers: [], loginStyle: 'sentinel', version: 'test' })

    renderPage()

    // Aperture (the default-before-loaded / default-on-failure screen) is
    // what's up first — this is the actual symptom reported, not yet a bug
    // on its own. "Argus never blinks" is Aperture's own copy, absent from
    // every other ported screen.
    expect(await screen.findByText(/Argus never/i)).toBeTruthy()

    // The retry fires after SSO_PROVIDERS_RETRY_MS and succeeds, and THIS
    // mount — not a reload — ends up on the real configured style (Sentinel
    // here), not stuck on Aperture for the rest of its life.
    await waitFor(
      () => {
        expect(screen.queryByText(/Argus never/i)).toBeNull()
      },
      { timeout: 6_000, interval: 100 },
    )
    expect(mockSsoProviders).toHaveBeenCalledTimes(2)
  }, 8_000)
})

describe('LoginPage — the sign-in form', () => {
  it('submitting calls login with the typed credentials and then navigates to the destination', async () => {
    mockLogin.mockResolvedValue(undefined)
    renderPage()

    fireEvent.change(screen.getByLabelText(/^Work email$/i), { target: { value: 'admin@example.com' } })
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'correct-password' } })
    fireEvent.click(screen.getByRole('button', { name: /^Sign in$/i }))

    await waitFor(() => expect(mockLogin).toHaveBeenCalledWith('admin@example.com', 'correct-password'))
    expect(await screen.findByText('OVERVIEW SCREEN')).toBeTruthy()
  })

  it('shows the hub\'s own error message (message + detail) on a rejected login, and does not navigate', async () => {
    mockLogin.mockRejectedValue(new ApiError('Invalid credentials', 401, 'the email or password was wrong'))
    renderPage()

    fireEvent.change(screen.getByLabelText(/^Work email$/i), { target: { value: 'admin@example.com' } })
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'wrong-password' } })
    fireEvent.click(screen.getByRole('button', { name: /^Sign in$/i }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/Invalid credentials/)
    expect(alert.textContent).toMatch(/the email or password was wrong/)
    expect(screen.queryByText('OVERVIEW SCREEN')).toBeNull()
    expect(screen.getByLabelText(/^Work email$/i)).toBeTruthy()
  })

  it('shows a generic message, not a raw error, when login rejects with something other than ApiError', async () => {
    mockLogin.mockRejectedValue(new Error('ECONNRESET'))
    renderPage()

    fireEvent.change(screen.getByLabelText(/^Work email$/i), { target: { value: 'admin@example.com' } })
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: /^Sign in$/i }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/Something went wrong/i)
    expect(alert.textContent).not.toMatch(/ECONNRESET/)
  })

  it('disables the submit button and shows "Signing in…" only while the request is in flight', async () => {
    let resolveLogin: () => void = () => {}
    mockLogin.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          resolveLogin = resolve
        }),
    )
    renderPage()

    fireEvent.change(screen.getByLabelText(/^Work email$/i), { target: { value: 'admin@example.com' } })
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: /^Sign in$/i }))

    const submitButton = await screen.findByRole('button', { name: /Signing in…/i })
    expect(submitButton).toHaveProperty('disabled', true)

    resolveLogin()
    await waitFor(() => expect(screen.queryByRole('button', { name: /Signing in…/i })).toBeNull())
  })

  // THE BUG THIS EXISTS FOR. Each supplied design ran a staged sequence on a
  // timer — "Authenticating" / "Establishing tunnel" / "Loading 247 clusters" /
  // a success state — with a progress bar alongside. Wired to a real hub, those
  // timers knew nothing about the request: signing in from a laptop with no
  // route to Argus walked through every stage and arrived at "signed in".
  //
  // This asserts the absence of all of it, which is unusual but is exactly the
  // property that regressed: a rejected login must never show progress or
  // success, and the only in-flight text is one honest label.
  it('never shows staged progress or a success state — a rejected login only ever shows the error', async () => {
    let rejectLogin: (e: unknown) => void = () => {}
    mockLogin.mockImplementation(
      () =>
        new Promise<void>((_resolve, reject) => {
          rejectLogin = reject
        }),
    )
    renderPage()

    fireEvent.change(screen.getByLabelText(/^Work email$/i), { target: { value: 'admin@example.com' } })
    fireEvent.change(screen.getByLabelText(/^Password$/i), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: /^Sign in$/i }))

    // In flight: one label, no stages.
    await screen.findByRole('button', { name: /Signing in…/i })

    // Let the staged timings elapse. The designs' sequences would have reached
    // "Establishing tunnel" by 1600ms and a success state by 3200ms.
    await new Promise((r) => setTimeout(r, 1800))
    for (const staged of [/Authenticating/i, /Establishing tunnel/i, /Verifying device trust/i, /Loading .* clusters/i, /Welcome back ✓/i, /Signed in/i, /Fleet connected/i]) {
      expect(screen.queryByText(staged)).toBeNull()
    }

    // An ApiError, as a real hub rejection is — a plain Error is mapped to the
    // generic message on purpose (see LoginPage's handleLogin).
    rejectLogin(new ApiError('Invalid credentials', 401, 'the email or password was wrong'))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toMatch(/Invalid credentials/)
    // And the button is usable again, not stuck mid-sequence.
    expect(await screen.findByRole('button', { name: /^Sign in$/i })).toHaveProperty('disabled', false)
  })

  it('the password visibility toggle switches the input type and its own pressed state', () => {
    renderPage()
    const passwordInput = screen.getByLabelText(/^Password$/i) as HTMLInputElement
    expect(passwordInput.type).toBe('password')

    const toggle = screen.getByRole('button', { name: /^Show password$/i })
    fireEvent.click(toggle)

    expect(passwordInput.type).toBe('text')
    expect(screen.getByRole('button', { name: /^Hide password$/i })).toBeTruthy()
    expect(screen.getByRole('button', { name: /^Hide password$/i })).toHaveProperty('ariaPressed', 'true')
  })
})

describe('LoginPage — single sign-on shows only configured identity providers', () => {
  for (const loginStyle of ['aperture', 'sentinel'] as const) {
    it(`${loginStyle}: no SSO buttons or divider when the hub has no provider configured`, async () => {
      mockSsoProviders.mockResolvedValue({ providers: [], loginStyle, version: 'test' })
      renderPage()
      await screen.findByRole('button', { name: /^Sign in$/ })
      expect(screen.queryByText(/single sign-on|or continue with/i)).toBeNull()
      expect(screen.queryByRole('button', { name: /Google|Entra|SAML/i })).toBeNull()
    })

    it(`${loginStyle}: a configured provider renders as a real, enabled button`, async () => {
      mockSsoProviders.mockResolvedValue({
        providers: [{ id: 'idp_1', displayName: 'Acme SSO' }],
        loginStyle,
        version: 'test',
      })
      renderPage()
      const button = await screen.findByRole('button', { name: /Acme SSO/ })
      expect((button as HTMLButtonElement).disabled).toBe(false)
    })
  }
})
