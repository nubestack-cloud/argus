import { describe, expect, it, vi, beforeEach } from 'vitest'
import { act, render, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ApiError } from '../api/client'
import type { LoginResponse, MeResponse } from '../api/types'

// Cross-tab refresh coordination (BACKLOG G7, "Cross-tab refresh
// coordination"). AuthContext's own refresh call is single-flight only
// *within one tab* (see the comment on renewInFlightRef in AuthContext.tsx)
// because internal/authz/session.go's RotateRefreshToken takes a row lock
// and treats a second presentation of an already-rotated refresh token as
// theft, revoking the whole token family. Two browser tabs racing to renew
// the same session used to both lose it.
//
// PROJECT.md B164 moved the refresh token itself out of localStorage into an
// HttpOnly cookie, but that did not remove this race: a real browser's
// cookie jar is shared between tabs exactly the way localStorage used to be,
// so two tabs calling POST /auth/refresh at once still present the identical
// token and still hit the same server-side reuse-detection path. What these
// tests actually exercise is the coordination layer, not the cookie — POST
// /auth/refresh itself is mocked (mockRefresh), so there is no real HTTP
// request and therefore no real cookie involved either way.
//
// These tests render two independent AuthProvider instances — standing in
// for two browser tabs of the same origin — sharing the same (real, jsdom-
// global) BroadcastChannel. jsdom itself does not implement BroadcastChannel;
// what's actually exercised here is Node's own global BroadcastChannel
// (stable since Node 18, confirmed present in this project's vitest+jsdom
// setup), which really does deliver messages between the two `new
// BroadcastChannel('argus.auth.renew')` instances the two AuthProviders
// create — so the election in these tests is the real protocol talking to
// itself twice, not a mocked stand-in for it. What is NOT exercised here is a
// real separate browser tab process, page-visibility/bfcache edge cases, or
// genuine wall-clock delay — see the last test for what's covered on that
// front and its own caveat.

const mockRefresh = vi.fn<() => Promise<LoginResponse>>()
const mockSSOExchange = vi.fn<(code: string) => Promise<LoginResponse>>()
// logout is mocked so a real fetch never leaves this test at all (matching
// getMe below) — the property under test in the sign-out case is that
// AuthContext.logout() CALLS it, not what a real POST /auth/logout does
// (that is internal/api/auth_test.go's job).
const mockLogout = vi.fn<() => Promise<void>>()
// getMe is mocked in every test in this file, not just the identity ones:
// AuthContext now calls it for EVERY token it comes to hold (PROJECT.md
// B165), including the ones the rotation tests above produce, so leaving it
// unmocked would send the real fetch at a relative URL from jsdom.
const mockGetMe = vi.fn<(token: string) => Promise<MeResponse>>()

// fakeMe fills in the four Appearance/General effective-settings fields
// (PROJECT.md, 2026-10-14) with the hub's own shipped defaults, so every
// existing mockGetMe fixture below only has to name what it's actually
// testing (userId/email/authMethod) rather than restating fields no test in
// this file exercises.
function fakeMe(overrides: Pick<MeResponse, 'userId' | 'email' | 'authMethod'>): MeResponse {
  return {
    primaryColorId: 'teal',
    overviewDefaultWindowDays: 14,
    minPasswordLength: 12,
    sessionIdleTimeoutMinutes: null,
    ...overrides,
  }
}

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    refresh: (...args: []) => mockRefresh(...args),
    ssoExchange: (...args: [string]) => mockSSOExchange(...args),
    logout: (...args: []) => mockLogout(...args),
    getMe: (...args: [string]) => mockGetMe(...args),
  }
})

// Imported after the mock above so `refresh` inside AuthContext.tsx resolves
// to the mocked version.
const { AuthProvider } = await import('./AuthContext')
const { useAuth } = await import('./useAuth')

const STALE_EMAIL_KEY = 'argus.email'

type AuthSnapshot = ReturnType<typeof useAuth>

function Probe({ id, onRender }: { id: string; onRender: (id: string, value: AuthSnapshot) => void }) {
  const auth = useAuth()
  onRender(id, auth)
  return null
}

// Renders one AuthProvider standing in for one open tab. Each tab gets its
// own QueryClient, matching how a real tab has its own module instance of
// the whole app (App.tsx creates the QueryClient at module scope) —
// BroadcastChannel is the only thing a real browser actually shares across
// tabs of the same origin that these renderTab() calls also share; the
// refresh cookie itself is never touched by this test file at all (see the
// top-of-file comment).
function renderTab(id: string, onRender: (id: string, value: AuthSnapshot) => void) {
  const queryClient = new QueryClient()
  return render(
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Probe id={id} onRender={onRender} />
      </AuthProvider>
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  localStorage.clear()
  mockRefresh.mockReset()
  mockSSOExchange.mockReset()
  mockLogout.mockReset()
  mockLogout.mockResolvedValue(undefined)
  mockGetMe.mockReset()
  mockGetMe.mockResolvedValue(fakeMe({ userId: 'usr_default', email: 'default@example.com', authMethod: 'password' }))
})

describe('AuthContext cross-tab refresh coordination', () => {
  it('elects exactly one tab to call POST /auth/refresh when two tabs mount at once', async () => {
    mockRefresh.mockResolvedValue({
      accessToken: 'access-1',
      expiresIn: 900,
      mustChangePassword: false,
    })

    const latest = new Map<string, AuthSnapshot>()
    const onRender = (id: string, value: AuthSnapshot) => latest.set(id, value)

    // Both tabs mount at effectively the same instant — each tab's own mount
    // effect calls renewSession() to restore its session from whatever the
    // (shared, real-browser) cookie jar holds, which is exactly the race
    // this feature exists to resolve. Neither tab can tell from JavaScript
    // whether a session cookie even exists (it's HttpOnly), so both attempt
    // the call unconditionally — that's what makes the coordination matter
    // here rather than only when a stored token happened to be present.
    renderTab('a', onRender)
    renderTab('b', onRender)

    await waitFor(() => {
      expect(latest.get('a')?.isBootstrapping).toBe(false)
      expect(latest.get('b')?.isBootstrapping).toBe(false)
    })

    // The real bug this closes: without cross-tab coordination, both tabs
    // would have called refresh at once, the loser would have been
    // classified as token reuse server-side, and BOTH sessions would have
    // ended up revoked. Only one call happening at all is the property under
    // test — and it takes no argument any more (PROJECT.md B164: the token
    // travels in a cookie the browser attaches on its own, never a value
    // this code passes).
    expect(mockRefresh).toHaveBeenCalledTimes(1)
    expect(mockRefresh.mock.calls[0]).toEqual([])

    // Both tabs converge on the SAME session — the follower didn't just
    // avoid calling refresh, it actually ended up with a working access
    // token, which it can only have gotten from the winner's broadcast (the
    // access token only ever exists in memory, in whichever tab most
    // recently obtained one).
    expect(latest.get('a')?.accessToken).toBe('access-1')
    expect(latest.get('b')?.accessToken).toBe('access-1')
  })

  it('logs every tab out together when the winning tab finds the session already rejected', async () => {
    // Standing in for the server-side theft-detection rejection
    // (internal/authz/session.go) — from the client's point of view this is
    // indistinguishable from "expired" or "revoked" or "no cookie at all",
    // all of which end a session the same way. Shaped as the real
    // ApiError/type a genuine rejection carries (internal/api/auth.go's
    // handleRefresh, invalid-refresh-token) — not a bare Error — because
    // that type is exactly what AuthContext's round() now uses to tell a
    // real rejection apart from a transient network failure (status 0, no
    // type), which must NOT end the session.
    mockRefresh.mockRejectedValue(
      new ApiError('Refresh failed', 401, '', 'https://argus.io/errors/invalid-refresh-token'),
    )

    const latest = new Map<string, AuthSnapshot>()
    const onRender = (id: string, value: AuthSnapshot) => latest.set(id, value)

    renderTab('a', onRender)
    renderTab('b', onRender)

    await waitFor(() => {
      expect(latest.get('a')?.isBootstrapping).toBe(false)
      expect(latest.get('b')?.isBootstrapping).toBe(false)
    })

    // Still only one call: the loser deferred rather than also presenting
    // the doomed token itself.
    expect(mockRefresh).toHaveBeenCalledTimes(1)

    // Neither tab is left half-signed-in: the winner's clearSession() is
    // mirrored to the other tab by the 'result: ok:false' broadcast, so both
    // land in the same logged-out state instead of one tab being stuck.
    expect(latest.get('a')?.accessToken).toBeNull()
    expect(latest.get('b')?.accessToken).toBeNull()
  })

  it('retries rather than logging out when a renewal fails with a transient network error, not a real rejection', async () => {
    // The actual bug reported live: a tab idle/asleep long enough that its
    // renewal attempt lands in a brief network gap right as it wakes —
    // client.ts reports this as ApiError(status 0, type ''), never a real
    // answer from the hub (contrast the previous test's
    // invalid-refresh-token ApiError, which IS a real answer). Before the
    // fix, round()'s catch treated every rejection the same and logged the
    // tab out — even though the refresh cookie was perfectly valid, which a
    // plain reload moments later would have proven by succeeding. The first
    // call here stands in for that failed attempt; the second is the
    // self-triggered retry (NETWORK_RETRY_DELAY_MS later) succeeding once
    // the network is back, with no reload involved at all.
    mockRefresh
      .mockRejectedValueOnce(new ApiError('Network error', 0, 'Could not reach the ARGUS hub API.'))
      .mockResolvedValueOnce({ accessToken: 'access-recovered', expiresIn: 900, mustChangePassword: false })

    const latest = new Map<string, AuthSnapshot>()
    const onRender = (id: string, value: AuthSnapshot) => latest.set(id, value)

    renderTab('solo', onRender)

    await waitFor(() => {
      expect(latest.get('solo')?.isBootstrapping).toBe(false)
    })

    // The failed attempt must not have produced any kind of "logged out"
    // signal a real rejection would (no sign-out reason, still null rather
    // than some error state) — it's simply still working on it.
    expect(latest.get('solo')?.accessToken).toBeNull()
    expect(latest.get('solo')?.signOut).toBeNull()

    // Real wall-clock wait for the same reason the next test's does: the
    // retry is gated on NETWORK_RETRY_DELAY_MS (5s in AuthContext.tsx)
    // genuinely elapsing.
    await waitFor(
      () => {
        expect(latest.get('solo')?.accessToken).toBe('access-recovered')
      },
      { timeout: 7_000, interval: 200 },
    )
    expect(mockRefresh).toHaveBeenCalledTimes(2)
  }, 10_000) // needs more than vitest's default 5s: the retry is gated on NETWORK_RETRY_DELAY_MS (5s in AuthContext.tsx)

  it('recovers without a second concurrent refresh call when the elected tab never responds (closed mid-flight)', async () => {
    // The first call stands in for a tab that claimed leadership and then
    // vanished (closed, crashed, or its response/broadcast was lost) before
    // ever resolving — nothing in this test ever settles that promise. The
    // second call is whichever tab's lease-timeout retry recovers the
    // situation once LEASE_MS has passed with no result heard.
    let pendingResolversSeen = 0
    mockRefresh.mockImplementation(() => {
      pendingResolversSeen += 1
      if (pendingResolversSeen === 1) {
        return new Promise<LoginResponse>(() => {
          // Deliberately never resolves or rejects — simulates the leader
          // tab disappearing mid-request.
        })
      }
      return Promise.resolve({
        accessToken: 'access-recovered',
        expiresIn: 900,
        mustChangePassword: false,
      })
    })

    const latest = new Map<string, AuthSnapshot>()
    const onRender = (id: string, value: AuthSnapshot) => latest.set(id, value)

    renderTab('a', onRender)
    renderTab('b', onRender)

    // Real wall-clock wait: this is the one thing in this file that isn't
    // instant, because the recovery path is gated on LEASE_MS (8s in
    // AuthContext.tsx) genuinely elapsing for the follower waiting on the
    // vanished leader's lease — there is no fake-timers path here, since
    // the election phase this test also exercises depends on the real
    // BroadcastChannel actually delivering messages, and mixing that with
    // vi.useFakeTimers() risks stalling delivery instead of testing anything
    // real. The cost is this one test taking ~8s of real time.
    await waitFor(
      () => {
        expect(latest.get('a')?.accessToken ?? latest.get('b')?.accessToken).toBe('access-recovered')
      },
      { timeout: 12_000, interval: 200 },
    )

    // Exactly one retry, not a second race: the follower's timeout-triggered
    // re-entry into the election gate is itself gated by the same protocol,
    // so it elects a single recoverer rather than both tabs calling refresh
    // again simultaneously.
    expect(mockRefresh).toHaveBeenCalledTimes(2)
    expect(latest.get('a')?.accessToken).toBe('access-recovered')
    expect(latest.get('b')?.accessToken).toBe('access-recovered')
  }, 15_000)
})

// --- Identity: who the header names (PROJECT.md B165) ----------------------
//
// The reported defect: "after single sign-on the header can show a blank or
// the PREVIOUS user's identity." The mechanism was that AuthContext read the
// signed-in email out of localStorage, where only the PASSWORD path ever
// wrote it — from the address typed into the form. So a federated sign-in
// displayed whatever the last person to use that browser had left behind.
//
// These tests seed 'argus.email' exactly as a pre-fix build would have left
// it, because that stale value is what a real upgraded browser carries: a key
// this code no longer writes is still sitting in the storage of every browser
// that ever ran the old bundle, and a fix that only stops WRITING it would
// still read it.
describe('AuthContext identity', () => {
  it('names the account that actually signed in federated, not the email the previous user left behind', async () => {
    // Alice used this browser. Her address is still in localStorage.
    localStorage.setItem(STALE_EMAIL_KEY, 'alice@example.com')

    mockSSOExchange.mockResolvedValue({
      accessToken: 'access-bob',
      expiresIn: 900,
      mustChangePassword: false,
    })
    mockGetMe.mockResolvedValue(fakeMe({ userId: 'usr_bob', email: 'bob@example.com', authMethod: 'password' }))

    // Every email this provider ever exposed, not just the final one: the bug
    // is a wrong NAME on screen, so a version that settles on Bob after a
    // frame of Alice would still be the defect, and asserting only on the end
    // state would pass it.
    const seen: (string | null)[] = []
    const latest = new Map<string, AuthSnapshot>()
    const onRender = (id: string, value: AuthSnapshot) => {
      latest.set(id, value)
      seen.push(value.email)
    }

    renderTab('a', onRender)
    await waitFor(() => expect(latest.get('a')?.isBootstrapping).toBe(false))

    // Bob completes a federated sign-in in Alice's browser.
    await act(async () => {
      await latest.get('a')!.completeSSOLogin('one-time-handoff-code')
    })
    await waitFor(() => expect(latest.get('a')?.identityStatus).toBe('ready'))

    expect(latest.get('a')?.email).toBe('bob@example.com')
    expect(latest.get('a')?.userId).toBe('usr_bob')
    expect(seen).not.toContain('alice@example.com')

    // The identity was read for the token the exchange actually returned —
    // not for a previous session's token, which is the other way this could
    // be right by accident.
    expect(mockGetMe).toHaveBeenCalledWith('access-bob')

    // And the stale key is not resurrected: nothing writes an identity to
    // localStorage any more, so the next sign-in in this browser cannot
    // inherit Bob's address either.
    expect(localStorage.getItem(STALE_EMAIL_KEY)).toBe('alice@example.com')
  })

  it('names the signed-in account on a session restored on mount, ignoring a stale stored email', async () => {
    // A page reload, which is the other path with no sign-in response to
    // carry an identity at all. The restored session belongs to Bob; the
    // stale email is still Alice's. There is no longer anything to seed for
    // "a session exists" (PROJECT.md B164: the refresh token is an HttpOnly
    // cookie this test never touches) — the mount effect always attempts
    // POST /auth/refresh, and mockRefresh resolving is what stands in for a
    // real browser presenting a valid cookie.
    localStorage.setItem(STALE_EMAIL_KEY, 'alice@example.com')
    mockRefresh.mockResolvedValue({
      accessToken: 'access-bob-restored',
      expiresIn: 900,
      mustChangePassword: false,
    })
    mockGetMe.mockResolvedValue(fakeMe({ userId: 'usr_bob', email: 'bob@example.com', authMethod: 'password' }))

    const seen: (string | null)[] = []
    const latest = new Map<string, AuthSnapshot>()
    renderTab('a', (id, value) => {
      latest.set(id, value)
      seen.push(value.email)
    })

    await waitFor(() => expect(latest.get('a')?.identityStatus).toBe('ready'))
    expect(latest.get('a')?.email).toBe('bob@example.com')
    expect(seen).not.toContain('alice@example.com')
    expect(mockGetMe).toHaveBeenCalledWith('access-bob-restored')
  })

  it('reports the identity as unavailable, never a remembered address, when the hub cannot be asked', async () => {
    mockRefresh.mockResolvedValue({
      accessToken: 'access-restored',
      expiresIn: 900,
      mustChangePassword: false,
    })
    localStorage.setItem(STALE_EMAIL_KEY, 'alice@example.com')
    // Stands in for every way this can fail, including the one specific to
    // this product: a hub too old to have GET /users/me answers the SPA's
    // index.html with HTTP 200, which client.getMe rejects rather than
    // reading an identity out of (see its own comment).
    mockGetMe.mockRejectedValue(new Error('the hub did not return an identity'))

    const latest = new Map<string, AuthSnapshot>()
    renderTab('a', (id, value) => latest.set(id, value))

    await waitFor(() => expect(latest.get('a')?.identityStatus).toBe('unavailable'))
    // Still signed in — an unanswerable identity question does not end a
    // session — but the name is absent rather than wrong.
    expect(latest.get('a')?.accessToken).toBe('access-restored')
    expect(latest.get('a')?.email).toBeNull()
    expect(latest.get('a')?.userId).toBeNull()
  })

  it('never shows the outgoing account for even one frame when a second person signs in on the same tab', async () => {
    // The same shared-browser defect without a reload in between: Alice's
    // session is live in this tab, Bob signs in federated over the top of it.
    // This is the case a "keep the identity we already resolved while the new
    // one loads" optimisation gets wrong — it reads as a harmless way to avoid
    // a flicker and it renders Bob's session under Alice's name, which is the
    // reported bug in a shorter dress. Hence applySession's 'sign-in' kind
    // resetting the identity to pending.
    mockGetMe.mockResolvedValue(fakeMe({ userId: 'usr_alice', email: 'alice@example.com', authMethod: 'password' }))
    mockSSOExchange.mockResolvedValue({
      accessToken: 'access-alice',
      expiresIn: 900,
      mustChangePassword: false,
    })

    const latest = new Map<string, AuthSnapshot>()
    const seen: (string | null)[] = []
    renderTab('a', (id, value) => {
      latest.set(id, value)
      seen.push(value.email)
    })
    await waitFor(() => expect(latest.get('a')?.isBootstrapping).toBe(false))
    await act(async () => {
      await latest.get('a')!.completeSSOLogin('alices-code')
    })
    await waitFor(() => expect(latest.get('a')?.email).toBe('alice@example.com'))

    // Bob, on the same tab, with Alice's session still in memory.
    //
    // Bob's identity request is held open by the test rather than resolved
    // immediately, and that is what makes this assertion mean anything:
    // React batches every update inside one act() block, so a version that
    // renders Alice's name over Bob's token "only for a frame" would commit
    // no such frame here and a scan of rendered values could not see it.
    // Holding the request open puts the window the defect lives in — tokens
    // adopted, identity not yet confirmed — into the COMMITTED state, where
    // it can be asserted on directly.
    mockSSOExchange.mockResolvedValue({
      accessToken: 'access-bob',
      expiresIn: 900,
      mustChangePassword: false,
    })
    let confirmBob: (me: MeResponse) => void = () => {}
    mockGetMe.mockImplementation(
      () =>
        new Promise<MeResponse>((resolve) => {
          confirmBob = resolve
        }),
    )
    const framesBeforeBob = seen.length
    await act(async () => {
      await latest.get('a')!.completeSSOLogin('bobs-code')
    })

    // Bob's session is live and nobody is named yet. Alice must be gone
    // ALREADY, not gone once the hub answers.
    expect(latest.get('a')?.accessToken).toBe('access-bob')
    expect(latest.get('a')?.identityStatus).toBe('pending')
    expect(latest.get('a')?.email).toBeNull()
    expect(latest.get('a')?.userId).toBeNull()

    await act(async () => {
      confirmBob(fakeMe({ userId: 'usr_bob', email: 'bob@example.com', authMethod: 'password' }))
    })
    await waitFor(() => expect(latest.get('a')?.email).toBe('bob@example.com'))

    expect(seen.slice(framesBeforeBob)).not.toContain('alice@example.com')
    expect(latest.get('a')?.userId).toBe('usr_bob')
  })

  it('does not carry an identity across a sign-out, and revokes the session server-side', async () => {
    mockGetMe.mockResolvedValue(fakeMe({ userId: 'usr_alice', email: 'alice@example.com', authMethod: 'password' }))
    mockSSOExchange.mockResolvedValue({
      accessToken: 'access-alice',
      expiresIn: 900,
      mustChangePassword: false,
    })

    const latest = new Map<string, AuthSnapshot>()
    renderTab('a', (id, value) => latest.set(id, value))
    await waitFor(() => expect(latest.get('a')?.isBootstrapping).toBe(false))
    await act(async () => {
      await latest.get('a')!.completeSSOLogin('code')
    })
    await waitFor(() => expect(latest.get('a')?.email).toBe('alice@example.com'))

    await act(async () => {
      await latest.get('a')!.logout()
    })

    expect(latest.get('a')?.email).toBeNull()
    expect(latest.get('a')?.userId).toBeNull()
    // Back to 'pending', not 'unavailable': nobody is signed in, so there is
    // no identity question outstanding to have failed.
    expect(latest.get('a')?.identityStatus).toBe('pending')

    // PROJECT.md B164's actual fix: signing out used to be entirely local —
    // logout() only ever called clearSession(). It must now also call the
    // server, which is what makes a token captured before this click
    // refused afterwards (proved server-side by
    // internal/api/auth_test.go's TestLogoutRevokesRefreshTokenFamily...).
    expect(mockLogout).toHaveBeenCalledTimes(1)
    // ...and the outcome is known, not assumed.
    expect(latest.get('a')?.signOut).toBe('confirmed')
  })
})

// Live QA 2026-10-11.
describe('AuthContext — sign-out outcome, restored state, late tabs', () => {
  it('ends the local session even when the hub cannot confirm the sign-out, and says it was unconfirmed', async () => {
    mockRefresh.mockResolvedValue({ accessToken: 'access-1', expiresIn: 900, mustChangePassword: false })
    mockLogout.mockRejectedValue(new Error('network down'))
    const latest = new Map<string, AuthSnapshot>()
    renderTab('a', (id, value) => latest.set(id, value))
    await waitFor(() => expect(latest.get('a')?.accessToken).toBe('access-1'))

    await act(async () => {
      await latest.get('a')!.logout()
    })
    expect(latest.get('a')?.accessToken).toBeNull()
    expect(latest.get('a')?.signOut).toBe('unconfirmed')
  })

  it('a session restored on load keeps the must-change-password state the refresh reports', async () => {
    mockRefresh.mockResolvedValue({ accessToken: 'access-1', expiresIn: 900, mustChangePassword: true })
    const latest = new Map<string, AuthSnapshot>()
    renderTab('a', (id, value) => latest.set(id, value))
    await waitFor(() => expect(latest.get('a')?.accessToken).toBe('access-1'))
    expect(latest.get('a')?.mustChangePassword).toBe(true)
  })

  it('a tab opened while another tab\'s refresh is in flight waits for it instead of presenting the same cookie again', async () => {
    let resolveRefresh: (value: LoginResponse) => void = () => {}
    mockRefresh.mockImplementation(
      () =>
        new Promise<LoginResponse>((resolve) => {
          resolveRefresh = resolve
        }),
    )
    const latest = new Map<string, AuthSnapshot>()
    const onRender = (id: string, value: AuthSnapshot) => latest.set(id, value)
    renderTab('a', onRender)
    // Tab A has won its election and its refresh is on the wire.
    await waitFor(() => expect(mockRefresh).toHaveBeenCalledTimes(1), { timeout: 2000 })

    // Tab B opens now — after A's claim was broadcast, so the channel alone
    // would never tell it a round is in flight.
    renderTab('b', onRender)
    await new Promise((resolve) => setTimeout(resolve, 400))
    expect(mockRefresh).toHaveBeenCalledTimes(1)

    await act(async () => {
      resolveRefresh({ accessToken: 'access-a', expiresIn: 900, mustChangePassword: false })
    })
    await waitFor(() => expect(latest.get('b')?.accessToken).toBe('access-a'))
    expect(mockRefresh).toHaveBeenCalledTimes(1)
  })
})
