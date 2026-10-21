import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import {
  ApiError,
  changePassword as apiChangePassword,
  getMe as apiGetMe,
  login as apiLogin,
  logout as apiLogout,
  refresh as apiRefresh,
  ssoExchange as apiSSOExchange,
} from '../api/client'
import type { LoginResponse } from '../api/types'
import { applyAccent } from '../theme'
import { AuthContext } from './AuthContextBase'

// PROJECT.md B164: the refresh token has no client-side storage key at all
// any more. It used to be persisted here under 'argus.refreshToken' —
// localStorage, so a session survived a reload/browser restart — but a
// value a page script can WRITE is a value a page script (or anything it
// loads) can also READ, and signing out only ever cleared this key
// client-side, so a copy captured before that click stayed valid against
// the hub for the rest of its 30-day life.
//
// The token now travels ONLY as the `argus_refresh` cookie
// internal/api/auth.go's setRefreshCookie sets alongside every sign-in/
// refresh/change-password response: Secure when the connection actually
// warrants it, HttpOnly always (so this file, and anything else running in
// the page, cannot read it under any circumstance), SameSite=Lax. Nothing
// under web/src ever reads or writes it — the browser attaches it
// automatically to POST /auth/refresh and /auth/logout because
// client.ts's request() sends `credentials: 'same-origin'` and the server
// scopes the cookie's Path to /api/v1/auth. A session surviving a reload is
// now a property of that cookie jar, not of anything this component
// manages — which is also why apiRefresh/apiLogin/apiSSOExchange below no
// longer take or return a refresh token value at all.
//
// There used to be a second key here, 'argus.email', holding "the cosmetic
// display email". It is gone, and nothing should bring it back — PROJECT.md
// B165. It was written from the address typed into the password form, which
// is not an authenticated fact, and it was read back on every OTHER sign-in
// path as though it were: a federated sign-in carries no email at all, so it
// inherited whatever the last person to use that browser had left behind and
// labelled one person's session with another person's address. "Cosmetic" was
// the load-bearing mistake in that comment — on a product whose audit trail is
// the selling point, the name in the header is not decoration.
//
// Identity now comes from one place, GET /api/v1/users/me, keyed to the access
// token actually held, and is never persisted: it is re-read on every page
// load, which costs one small request and makes a wrong name structurally
// impossible rather than merely unlikely.

// --- Cross-tab refresh coordination ------------------------------------
//
// See the comment on renewInFlightRef and on `round` inside renewSession
// below for the full protocol and why it's race-free; this is just the wire
// format and constants shared by both.
const RENEW_CHANNEL_NAME = 'argus.auth.renew'

// How long a tab that just announced a claim waits for a competing, earlier
// claim to arrive before deciding it has won and it is safe to actually call
// POST /auth/refresh. BroadcastChannel delivery between same-process tabs is
// effectively immediate (well under a millisecond); this only needs to be
// comfortably larger than that plus ordinary JS scheduling jitter. It's paid
// once per renewal round (roughly every 80% of a token's lifetime, or a
// future 401-triggered attempt), not per request, so a generous margin costs
// nothing a user would ever notice.
const ELECTION_WINDOW_MS = 60

// How long a tab that finds no round currently in progress waits — purely
// listening, claiming nothing — before trusting that silence enough to
// become a claimant itself. This is a different gap than ELECTION_WINDOW_MS
// closes: two tabs whose mounts are merely a few milliseconds apart don't
// have their BroadcastChannels open at the same instant, and a message sent
// before a channel exists is not queued for it — it's simply never seen,
// however long that channel listens afterwards. So the tab that mounted
// first cannot rely on "nobody's claimed it yet" the moment its own channel
// opens; SETTLE_MS is the margin for the *other* tab's channel to exist
// before the first tab treats silence as "I'm alone" and posts a claim.
// This is exactly the two-tabs-both-restoring-at-once case the whole
// feature is for, so it has to be generous: real page loads (parse + first
// commit) essentially never differ by more than this between two tabs
// opened together, but a skew larger than SETTLE_MS is the one scenario
// this protocol cannot close (both tabs would independently conclude
// they're alone and both call refresh) — same class of residual risk as any
// BroadcastChannel-only design has no way to fully eliminate.
const SETTLE_MS = 150

// How long a tab that lost an election (or joined one already in progress)
// waits for the elected tab's result before assuming that tab died, was
// closed, or its broadcast was lost, and re-running the whole gate itself.
// Must be comfortably larger than a normal POST /auth/refresh round trip; 8s
// is generous for that while still being far smaller than the 20% lifetime
// margin applySession's proactive-renewal schedule leaves below — so even a
// full timeout-and-retry here never risks the token actually expiring out
// from under a tab.
const LEASE_MS = 8_000

// How long to wait before retrying a renewal that failed for a reason that
// is NOT a definitive "this refresh token is dead" answer — see round()'s
// catch below. Short on purpose: the usual cause is a tab/laptop that just
// woke from sleep or idle and whose network hasn't fully reconnected yet,
// which typically resolves in well under this.
const NETWORK_RETRY_DELAY_MS = 5_000

// How long signing out waits for the hub to confirm the revocation before
// ending the local session anyway and reporting it as unconfirmed.
const LOGOUT_WAIT_MS = 5_000

// How often a renewal that was deferred for being idle past
// org_settings.session_idle_timeout_minutes (PROJECT.md, 2026-10-14) checks
// again for resumed activity, rather than never trying again. Deliberately
// much shorter than any realistic idle-timeout configuration (the server
// enforces a 5-minute floor): the cost of checking every minute while
// genuinely idle is nothing, and the alternative — silently never renewing
// again until a full page reload — would make "idle timeout" look like a
// bug the moment someone returns to an unattended tab and it just sits there.
const IDLE_POLL_MS = 60_000

// One claim: "I intend to be the tab that calls POST /auth/refresh for this
// rotation." `from` is a per-tab-instance random id (stable for the tab's
// lifetime, not persisted — it only needs to be unique among tabs open right
// now), `ts` is when the claim was made, and `claimId` identifies this
// specific attempt (a tab makes a new one every round).
interface Claim {
  from: string
  claimId: string
  ts: number
}

// The only two things ever said on the channel: "I want to be leader for
// this round" and "this round is over, here's what happened." The success
// case carries the new ACCESS token only — the refresh token is never in
// this message, for the same reason it is never in this file at all
// (PROJECT.md B164): it lives in a cookie the browser already shares
// between every tab of this origin on its own, so there is nothing for a
// follower tab to adopt there. What a follower genuinely cannot get any
// other way is the new access token, which only ever existed in the
// winning tab's memory — that's the one thing this broadcast still has to
// carry.
// The 'result' message deliberately carries no identity. It used to pass the
// winning tab's display email along with the tokens, which made a rotation a
// second way for an identity to enter a tab — and a second way for it to be
// wrong. Every tab resolves its own identity from the tokens it ends up
// holding (see resolveIdentity), so a rotation only ever moves tokens.
type ChannelMessage =
  | ({ type: 'claim' } & Claim)
  | {
      type: 'result'
      claimId: string
      ok: true
      accessToken: string
      expiresIn: number
      // The account's must-change-password state as the hub reported it on
      // this rotation. Optional so a tab running an older bundle, which never
      // sent it, still parses as "unknown" and keeps what it had.
      mustChangePassword?: boolean
    }
  | { type: 'result'; claimId: string; ok: false }

// Deterministic total order over claims: earlier `ts` wins; a tie (same
// millisecond) is broken by comparing `from`. Every tab that has seen the
// same set of claims for a round reaches the identical conclusion about who
// won this way, with no further communication required to agree on it.
function isEarlierClaim(a: Claim, b: Claim): boolean {
  if (a.ts !== b.ts) return a.ts < b.ts
  return a.from < b.from
}

function randomId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  // Only reachable in a browser too old to have crypto.randomUUID at all —
  // collision odds don't matter next to the fact that browser is already
  // unsupported by the rest of the app.
  return `${Date.now()}-${Math.random().toString(36).slice(2)}`
}

// safePostMessage swallows a closed-channel error rather than letting it
// become an unhandled rejection inside round()'s async chain. A real
// AuthProvider's channel is only ever closed by its own unmount cleanup
// (below), and round() can still be mid-flight when that happens — see
// mountedRef's comment for when that's actually reachable (a permanently-
// mounted provider never triggers it; a short-lived one, mainly in tests,
// can).
// The current claim mirrored into localStorage. BroadcastChannel does not
// replay: a tab opened AFTER another tab has broadcast its claim, but before
// that tab's refresh has answered, hears nothing, waits out SETTLE_MS, claims
// for itself, and presents the same cookie the first tab already spent — the
// second presentation the hub treats as reuse. Reading the mirror on the way
// in closes that gap: the late tab sees the round in flight and waits for its
// result like any other follower. It holds no secret — a tab id, a claim id
// and a timestamp — and every read and write tolerates storage being
// unavailable, in which case the protocol is exactly what it was without it.
const LEASE_STORAGE_KEY = 'argus.auth.renew.lease'

function readStoredLease(): Claim | null {
  try {
    const raw = localStorage.getItem(LEASE_STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as Partial<Claim>
    if (typeof parsed.from !== 'string' || typeof parsed.claimId !== 'string' || typeof parsed.ts !== 'number') {
      return null
    }
    return { from: parsed.from, claimId: parsed.claimId, ts: parsed.ts }
  } catch {
    return null
  }
}

function writeStoredLease(claim: Claim | null) {
  try {
    if (claim) localStorage.setItem(LEASE_STORAGE_KEY, JSON.stringify(claim))
    else localStorage.removeItem(LEASE_STORAGE_KEY)
  } catch {
    // Storage blocked or full: the BroadcastChannel election still runs.
  }
}

function safePostMessage(channel: BroadcastChannel, msg: ChannelMessage) {
  try {
    channel.postMessage(msg)
  } catch {
    // Benign: the tab that would have received this is gone (or about to
    // be), and nothing here needs to know the send failed.
  }
}

// What applySession adopts: a sign-in/refresh response, or the same carried
// across tabs, where mustChangePassword may be absent (an older bundle's
// broadcast) — absent means "unknown, keep what you had", never false.
type SessionGrant = Omit<LoginResponse, 'mustChangePassword'> & { mustChangePassword?: boolean }

export function AuthProvider({ children }: { children: ReactNode }) {
  const [accessToken, setAccessToken] = useState<string | null>(null)
  // The signed-in account, as the hub reports it for the token currently
  // held, plus how that read is going. Never seeded from storage, never
  // carried over from a previous session, never guessed — the three states
  // are exactly what the UI has to tell apart: 'pending' (asking),
  // 'ready' (userId/email are the server's answer), 'unavailable' (the ask
  // failed, and the honest thing to show is that we do not know).
  const [identity, setIdentity] = useState<{
    status: 'pending' | 'ready' | 'unavailable'
    userId: string | null
    email: string | null
    authMethod: 'password' | 'federated' | null
  }>({ status: 'pending', userId: null, email: null, authMethod: null })
  const [mustChangePassword, setMustChangePassword] = useState(false)
  const [isBootstrapping, setIsBootstrapping] = useState(true)
  // How the last explicit sign-out in this tab ended, until the next sign-in:
  // 'confirmed' when the hub answered that the session is revoked,
  // 'unconfirmed' when it could not be reached or refused. ProtectedRoute
  // reads it so a sign-out does not hand the next person the outgoing user's
  // last page, and the sign-in screen says so when the revocation is not
  // known to have happened.
  const [signOut, setSignOut] = useState<'confirmed' | 'unconfirmed' | null>(null)
  const [signingOut, setSigningOut] = useState(false)
  // True when the session just ended because the hub's refresh endpoint
  // refused a renewal as idle-timed-out rather than for any other reason —
  // see round()'s catch below. Reset on every new sign-in (applySession's
  // 'sign-in' branch), same lifecycle as signOut above.
  const [endedForIdle, setEndedForIdle] = useState(false)
  // The Appearance/General effective settings (PROJECT.md, 2026-10-14),
  // defaulting to the hub's own shipped values until GET /users/me's real
  // answer arrives — see AuthContextBase's doc comment for why these are
  // plain values rather than gated by identityStatus the way userId/email
  // are. primaryColorId is NOT kept here: nothing else in the app needs to
  // read it reactively, so resolveIdentity applies it straight to the DOM
  // (theme.ts's applyAccent) and nothing more.
  const [effectiveSettings, setEffectiveSettings] = useState<{
    overviewDefaultWindowDays: 14 | 30
    minPasswordLength: number
    sessionIdleTimeoutMinutes: number | null
  }>({ overviewDefaultWindowDays: 14, minPasswordLength: 12, sessionIdleTimeoutMinutes: null })
  const renewTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const renewSessionRef = useRef<() => Promise<void>>(async () => {})
  // sessionIdleTimeoutMinutesRef mirrors effectiveSettings.sessionIdleTimeoutMinutes
  // (kept in sync by the effect below) so scheduleRenewalRef's setTimeout
  // callbacks — which can fire long after the render that scheduled them —
  // always read the CURRENT configured limit, not a stale closure over
  // whatever it was at schedule time.
  const sessionIdleTimeoutMinutesRef = useRef<number | null>(null)
  useEffect(() => {
    sessionIdleTimeoutMinutesRef.current = effectiveSettings.sessionIdleTimeoutMinutes
  }, [effectiveSettings.sessionIdleTimeoutMinutes])
  // The last genuine user interaction this tab observed — updated by the
  // activity-listener effect further down, read only by scheduleRenewalRef's
  // idle check. Seeded to mount time by that same effect (a freshly opened/
  // reloaded tab counts as activity, not at the epoch, so a session
  // idle-limited to e.g. 5 minutes doesn't look already-expired the instant
  // it loads) rather than here: `Date.now()` is impure, and calling it inline
  // in a useRef initializer runs it on every render even though only the
  // first result is ever kept.
  const lastActivityRef = useRef<number>(0)
  // A stable (never-reassigned) scheduling function, the same ref-holding-a-
  // function pattern renewSessionRef above uses, for the identical reason:
  // it needs to call itself from inside a setTimeout callback that may fire
  // long after this render, so it can't be a plain useCallback whose
  // identity (and closed-over values) would go stale.
  //
  // Replaces a bare `renewTimer.current = setTimeout(() => void
  // renewSessionRef.current(), delayMs)` at both of this file's two
  // scheduling call sites: when the configured idle limit has been exceeded
  // since lastActivityRef, it defers the renewal (and checks again in
  // IDLE_POLL_MS) instead of calling it — the whole point being that an
  // unattended tab stops quietly re-proving activity it doesn't have. This
  // is a CLIENT-SIDE convenience only: the actual enforcement is
  // authz.RotateRefreshTokenDetailed's own issued_at check, which refuses
  // the renewal server-side regardless of what any tab's timer does. Without
  // this gate, that server check would almost never fire in practice — the
  // 80%-of-token-lifetime proactive renewal below would keep rotating the
  // refresh token every ~12 minutes forever, re-proving the chain "active"
  // on a timer rather than on real use, no matter how long the tab had
  // actually been unattended.
  const scheduleRenewalRef = useRef((delayMs: number) => {
    clearTimeout(renewTimer.current)
    renewTimer.current = setTimeout(() => {
      const idleLimitMinutes = sessionIdleTimeoutMinutesRef.current
      if (idleLimitMinutes != null && Date.now() - lastActivityRef.current > idleLimitMinutes * 60_000) {
        scheduleRenewalRef.current(IDLE_POLL_MS)
        return
      }
      void renewSessionRef.current()
    }, delayMs)
  })
  // Tracks genuine user interaction for the idle gate above — pointer/key
  // activity, and a tab becoming visible again (covers touch-only and
  // keyboard-only sessions alike, plus the common case of switching back to
  // a tab after a while without necessarily clicking first). Deliberately
  // NOT state: this fires on essentially every interaction, and re-rendering
  // the whole provider tree on every keystroke/click for a value nothing
  // ever reads reactively would be pure waste.
  useEffect(() => {
    const markActive = () => {
      lastActivityRef.current = Date.now()
    }
    markActive() // seeds lastActivityRef to mount time — see its own comment.
    const onVisibilityChange = () => {
      if (document.visibilityState === 'visible') markActive()
    }
    window.addEventListener('pointerdown', markActive)
    window.addEventListener('keydown', markActive)
    document.addEventListener('visibilitychange', onVisibilityChange)
    return () => {
      window.removeEventListener('pointerdown', markActive)
      window.removeEventListener('keydown', markActive)
      document.removeEventListener('visibilitychange', onVisibilityChange)
    }
  }, [])
  // The app's single QueryClient is created once at module scope (App.tsx),
  // so it outlives every session in the tab — see clearSession below for why
  // that makes clearing it part of ending a session, not an optimization.
  const queryClient = useQueryClient()

  // This tab's identity for the election below. Random and in-memory only —
  // it never needs to survive a reload, only to be unique among the tabs
  // open right now.
  const tabIdRef = useRef(randomId())
  // The channel used for cross-tab election, or null when the runtime has no
  // BroadcastChannel (pre-2022 Safari). Every use below is guarded by this
  // being non-null; its absence just means this tab falls back to the
  // pre-fix, in-tab-only single-flight behavior rather than failing outright.
  const channelRef = useRef<BroadcastChannel | null>(null)
  // The best (earliest by isEarlierClaim) claim this tab has observed for
  // whatever renewal round is currently believed to be in progress, or null
  // when no round is known to be active. Updated by every 'claim' message
  // this tab ever receives — whether or not this tab itself is trying to
  // renew right now — so a tab sitting idle still stays current on who, if
  // anyone, is handling the next rotation.
  const activeLeaseRef = useRef<Claim | null>(null)
  // Set only while this tab is actually blocked inside waitForLease on one
  // specific round's outcome. `resolve` is invoked by the channel handler
  // below when the matching 'result' arrives, short-circuiting the timeout.
  const pendingRoundRef = useRef<{ claimId: string; resolve: () => void } | null>(null)
  // True until this provider unmounts. A REAL AuthProvider wraps the whole
  // app and lives for the tab's entire lifetime, so this never actually
  // flips outside a test — but renewSession() (below) always runs at least
  // one round-trip through SETTLE_MS/ELECTION_WINDOW_MS before it touches
  // the network at all (PROJECT.md B164 removed the old "no stored token,
  // return immediately" fast path that used to make this moot for a
  // never-signed-in browser), so a short-lived test render can and does
  // unmount before that finishes. Every continuation point inside round()
  // checks this before touching state or the (possibly already-closed)
  // BroadcastChannel, rather than let a late resolution throw or warn about
  // updating an unmounted component.
  const mountedRef = useRef(true)
  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
    }
  }, [])

  const clearSession = useCallback(() => {
    setAccessToken(null)
    setIdentity({ status: 'pending', userId: null, email: null, authMethod: null })
    setMustChangePassword(false)
    clearTimeout(renewTimer.current)
    // Every cached response in this tab was fetched as the user whose
    // session just ended, so it has to go with the session. Without this,
    // a super-admin signing out and a viewer signing in on the same tab
    // inside the default 5-minute gcTime got the *previous* user's data:
    // ['effective-permissions'] (whose key carries no user identity, so it
    // is a straight cache hit for whoever logs in next) made
    // useHasCapability report the super-admin's capabilities, rendering nav
    // and action controls as enabled, and ['users']/['audit-events']/
    // ['settings'] painted the previous admin's rows for a beat before the
    // viewer's 403 arrived. clear() (not invalidate) because the goal is to
    // *forget*, not to refetch: an invalidated query still serves its stale
    // data to the new user while the refetch is in flight. Also covers the
    // failed-refresh path below, which ends a session just as really as an
    // explicit sign-out does.
    queryClient.clear()
  }, [queryClient])

  // resolveIdentity asks the hub who the given access token belongs to, and is
  // the ONLY thing in this file that ever sets an identity (PROJECT.md B165).
  //
  // Called for every token this tab comes to hold — a password login, a
  // federated exchange, a session restored from storage on page load, a
  // rotation this tab performed, and a rotation it adopted from another tab —
  // because "who am I" must be a property of the token in hand, not of
  // whichever sign-in path happened to be taken or of what a previous session
  // left in this browser.
  //
  // On failure it sets 'unavailable' rather than leaving the previous value in
  // place. That is the whole point: the fallback for "we could not confirm who
  // you are" is to say so, never to show the last name we happened to know.
  const resolveIdentity = useCallback(async (token: string) => {
    try {
      const me = await apiGetMe(token)
      setIdentity({ status: 'ready', userId: me.userId, email: me.email, authMethod: me.authMethod })
      setEffectiveSettings({
        overviewDefaultWindowDays: me.overviewDefaultWindowDays,
        minPasswordLength: me.minPasswordLength,
        sessionIdleTimeoutMinutes: me.sessionIdleTimeoutMinutes,
      })
      applyAccent(me.primaryColorId)
    } catch {
      setIdentity({ status: 'unavailable', userId: null, email: null, authMethod: null })
      // effectiveSettings/the applied accent are deliberately left as they
      // were: a transient failure to re-confirm identity (the same failure
      // mode this catch has always handled) is not a reason to flip the
      // whole app's colour back to the default or forget the resolved
      // Overview/password-floor values it already had.
    }
  }, [])

  // Applies a fresh access/refresh token pair.
  //
  // `kind` says which of the two genuinely different things is happening, and
  // both differences follow from it rather than from a flag per behaviour:
  //
  //   'renewal'  — a rotation WITHIN the session this tab already has (its own
  //                80%-lifetime timer, or one adopted from another tab).
  //                handleRefresh's response always says mustChangePassword
  //                false because it doesn't carry the field's real value, so a
  //                renewal must not clear an already-true banner; and the
  //                person has not changed, so a resolved identity stays on
  //                screen instead of blanking every ~12 minutes.
  //   'sign-in'  — a new set of tokens whose holder this tab has not confirmed:
  //                a password login, a federated exchange, a password change.
  //                The response DOES carry the real mustChangePassword, and
  //                the identity resets to 'pending' until the hub answers.
  //                That reset is load-bearing rather than tidy: a federated
  //                sign-in in a tab that was already signed in as someone else
  //                must not spend even one frame labelled with the previous
  //                account (PROJECT.md B165).
  //
  // It takes no display email and never has one passed in. Applying a session
  // means adopting tokens; learning whose they are is resolveIdentity's job,
  // kicked off here (not awaited — a header that fills in a moment later is
  // better than a sign-in that blocks on a second round trip) so that every
  // path into a session goes through exactly one identity mechanism.
  const applySession = useCallback(
    (res: SessionGrant, kind: 'renewal' | 'sign-in') => {
      setAccessToken(res.accessToken)
      if (kind === 'sign-in') {
        setIdentity({ status: 'pending', userId: null, email: null, authMethod: null })
        setMustChangePassword(res.mustChangePassword === true)
        setSignOut(null)
        setEndedForIdle(false)
        // A brand new sign-in is itself activity, and matters specifically
        // for a session restored from a refresh token on page load (this IS
        // a 'sign-in'-kind call, not a 'renewal' — see this function's own
        // doc comment): without this, lastActivityRef would still read its
        // Date.now()-at-mount initial value, which for a reload long after
        // the tab was first opened could already be past the idle limit,
        // deferring the very first proactive renewal of a session someone
        // just, by definition, actively resumed.
        lastActivityRef.current = Date.now()
      } else if (typeof res.mustChangePassword === 'boolean') {
        // A renewal reports the account's real state too (handleRefresh
        // reads it from the users row), so the change-password prompt
        // raised at sign-in survives a reload instead of vanishing with it.
        // Undefined only from a cross-tab result sent by an older bundle —
        // keep what this tab already knew.
        setMustChangePassword(res.mustChangePassword)
      }
      void resolveIdentity(res.accessToken)
      // No refresh-token write here any more (PROJECT.md B164): the cookie
      // that carries it was already set by the response this res came from
      // (setRefreshCookie, internal/api/auth.go) before this ever ran — a
      // browser response's Set-Cookie header is applied to the cookie jar
      // as part of receiving the response, not by any code in this file.

      // Renew at 80% of the token's actual lifetime (whatever the server
      // says it is, not a hardcoded 15m) so an open tab never hits a bare
      // 401 from simple expiry — this is what makes the session persistent
      // for as long as the refresh token itself is valid (30 days,
      // internal/authz/session.go), not just across one page reload — UNLESS
      // this tab has gone idle past the configured limit, in which case
      // scheduleRenewalRef defers rather than renews (see its own comment).
      const delayMs = Math.max(res.expiresIn * 0.8, 5) * 1000
      scheduleRenewalRef.current(delayMs)
    },
    // resolveIdentity is itself a []-dependency useCallback, so this stays a
    // stable identity for the provider's whole life — declared rather than
    // omitted because "it happens to be stable" is exactly the reasoning that
    // rots when the other function grows a dependency.
    [resolveIdentity],
  )

  // Cross-tab session sync: applies (or ends) a session that *some* tab —
  // not necessarily this one — just obtained or gave up on, so every open
  // tab converges on the same outcome instead of the tabs that lost an
  // election being left on a stale access token until their own renewal
  // timer eventually fires and fails.
  //
  // Wired up once per tab, independent of whether this tab is currently
  // trying to renew anything itself: a tab sitting idle (its own 80%-
  // lifetime timer not due yet) still needs to pick up a rotation another
  // tab just performed, and still needs to log out the instant any tab
  // discovers the session is over — see the comment on `round` inside
  // renewSession below for the full protocol this participates in.
  useEffect(() => {
    if (typeof BroadcastChannel === 'undefined') {
      // No cross-tab coordination available at all on this browser. Leaving
      // channelRef null is what makes every guarded use below degrade to
      // the pre-fix, in-tab-only behavior instead of throwing.
      return
    }
    const channel = new BroadcastChannel(RENEW_CHANNEL_NAME)
    channel.onmessage = (event: MessageEvent) => {
      const msg = event.data as ChannelMessage
      if (msg.type === 'claim') {
        const incoming: Claim = { from: msg.from, claimId: msg.claimId, ts: msg.ts }
        if (!activeLeaseRef.current || isEarlierClaim(incoming, activeLeaseRef.current)) {
          activeLeaseRef.current = incoming
        }
        return
      }
      // A 'result' concludes whichever round made this claim, in this tab's
      // view — clear it so this tab doesn't mistake a later, unrelated
      // check for "still in progress".
      if (activeLeaseRef.current?.claimId === msg.claimId) {
        activeLeaseRef.current = null
      }
      if (msg.ok) {
        applySession(
          {
            accessToken: msg.accessToken,
            expiresIn: msg.expiresIn,
            mustChangePassword: msg.mustChangePassword,
          },
          'renewal',
        )
      } else {
        // Same "drop back to logged out" reasoning as the in-tab catch
        // below — this tab didn't make the failing call itself, but the
        // session it shares with the tab that did is over all the same.
        clearSession()
      }
      // Any result ends a wait, not only the result for the claim being
      // waited on: the session it carries has just been applied above, which
      // is all a waiting tab wanted. A tab that adopted a lease from storage
      // can be waiting on a claim that lost its election, whose own result
      // never comes — matching claim ids only would leave it waiting out the
      // whole LEASE_MS for nothing.
      if (pendingRoundRef.current) {
        const resolve = pendingRoundRef.current.resolve
        pendingRoundRef.current = null
        resolve()
      }
    }
    channelRef.current = channel
    return () => {
      channel.close()
      channelRef.current = null
    }
  }, [applySession, clearSession])

  // Resolves once the given lease's outcome is known — a matching 'result'
  // arrived (resolve(true)) — or LEASE_MS has passed since the claim was
  // made with nothing heard (resolve(false)), whichever comes first. Always
  // resolves; a caller can never be left waiting forever on a tab that died.
  const waitForLease = useCallback((lease: Claim): Promise<boolean> => {
    return new Promise<boolean>((resolve) => {
      const remainingMs = Math.max(lease.ts + LEASE_MS - Date.now(), 0)
      const timer = setTimeout(() => {
        if (pendingRoundRef.current?.claimId === lease.claimId) {
          pendingRoundRef.current = null
        }
        resolve(false)
      }, remainingMs)
      pendingRoundRef.current = {
        claimId: lease.claimId,
        resolve: () => {
          clearTimeout(timer)
          resolve(true)
        },
      }
    })
  }, [])

  // Single-flight: concurrent callers *in this tab* share one in-flight
  // POST /auth/refresh instead of each presenting the same stored refresh
  // token.
  //
  // This is load-bearing, not an optimization. Refresh tokens rotate, and
  // internal/authz/session.go's RotateRefreshToken now takes a FOR UPDATE row
  // lock, so two simultaneous refreshes with the same token no longer both
  // succeed — one wins, the other is correctly classified as token *reuse*,
  // and the reuse branch revokes the whole token family, including the
  // successor the winner just received. Both callers therefore end up logged
  // out. Two callers is not hypothetical here: the mount effect below fires
  // twice under React StrictMode in dev, and the proactive ~12-minute renewal
  // timer can land alongside it.
  //
  // Two browser tabs are two module instances with two separate refs, so
  // this guard alone can't stop a genuine two-tab race from presenting the
  // same token twice. That needed cross-tab coordination — `round` below
  // now provides it via a BroadcastChannel election — layered on *top* of
  // this ref, not in place of it: renewInFlightRef still dedups same-tab
  // callers before anything cross-tab is even consulted.
  const renewInFlightRef = useRef<Promise<void> | null>(null)

  // Renamed from the pre-B164 `renewFromStorage`: there is no longer a
  // stored token to read, so a name implying one exists would be actively
  // misleading. What this restores is whatever session the `argus_refresh`
  // cookie represents — this tab has no way to check whether that cookie
  // even exists before asking (it is HttpOnly by design), so unlike the old
  // localStorage-backed version, this ALWAYS attempts POST /auth/refresh at
  // least once, even for a browser that was never signed in at all. That is
  // a deliberate, accepted cost — see the election protocol's own comment
  // below for why skipping the election to avoid it would reopen the exact
  // multi-tab race this exists to close.
  const renewSession = useCallback(async () => {
    if (renewInFlightRef.current) {
      return renewInFlightRef.current
    }

    // The actual work, factored out as a self-recursive inner function
    // rather than having a lease-timeout retry call renewSession itself: a
    // retry needs to reuse the very `attempt` promise renewInFlightRef is
    // about to hold, not go back through the single-flight check above and
    // await that same still-pending promise forever.
    //
    // Cross-tab leader election, layered on the in-tab single-flight above,
    // and STILL necessary even though the refresh token itself now lives in
    // a cookie the browser already shares between tabs on its own — sharing
    // the value was never the problem this solves. Two tabs that each call
    // POST /auth/refresh at the same moment present the exact same cookie
    // value to internal/authz.RotateRefreshToken, which takes a FOR UPDATE
    // row lock and treats the SECOND presentation of an already-rotated
    // token as theft: one call wins and rotates it, the other reads it as
    // already-revoked and revokes the whole family in response — logging
    // BOTH tabs out. Protocol: a tab that finds no round in progress first
    // settles for SETTLE_MS (purely listening — see its comment for why
    // that's needed at all), then broadcasts a claim {from, claimId, ts}
    // and waits ELECTION_WINDOW_MS; every tab — whether or not it's
    // currently trying to renew — tracks the earliest claim it has seen for
    // the in-progress round in activeLeaseRef, via the channel.onmessage
    // handler above. After the window, a tab whose own claim is still the
    // earliest one it knows of has won and is the only tab that calls POST
    // /auth/refresh; every other tab defers and waits for that round's
    // outcome instead of racing it.
    //
    // Why this is race-free: who won is decided independently by every tab,
    // but from the *same* input (the claims made for this round) and the
    // *same* deterministic comparison (isEarlierClaim), so every tab reaches
    // the identical conclusion — there's no separate "announce the winner"
    // step to lose or reorder. The one thing that has to hold is that
    // ELECTION_WINDOW_MS is long enough for two claims made at essentially
    // the same instant to have reached every tab before any of them checks
    // its own result, which same-process BroadcastChannel delivery (sub-
    // millisecond) satisfies with a lot of room to spare. And a tab only
    // ever sees "no round in progress" (and thus starts one) when
    // activeLeaseRef is null or stale, while a winner never calls the
    // network until *after* its own window closes — so no claim or result
    // can be produced mid-window for a round nobody has started yet.
    //
    // Convergence when a tab dies or a message is lost: a follower is never
    // just parked with no exit — waitForLease always resolves, either
    // because a 'result' arrived or because LEASE_MS elapsed. A leader tab
    // closed mid-request, or whose broadcast never arrives, leaves every
    // follower's wait to time out and re-run `round()` from the top. That
    // re-run presents whatever the cookie jar holds NOW: if the dead
    // leader's request actually completed server-side before it vanished,
    // the browser is already holding the rotated cookie and this tab mints
    // its own valid pair from it (a wasted extra rotation in the rarer case
    // the leader was merely slow rather than dead, not a correctness
    // problem); if it never completed, the cookie is unchanged and this
    // retry rotates it for real. Either way the retry goes through this same
    // gate, so a burst of simultaneous timeouts among several followers
    // still elects exactly one of them rather than reintroducing the
    // multi-tab race this exists to close. And if the presented token is
    // already revoked (genuine theft-detection), apiRefresh throws,
    // clearSession() runs, and the 'result: ok:false' broadcast takes every
    // other waiting tab down with it — every tab logs out together, never
    // one tab silently stuck presenting a stale token.
    const round = async (): Promise<void> => {
      const channel = channelRef.current
      if (!channel) {
        // No BroadcastChannel support in this browser: fall back to exactly
        // the pre-fix, in-tab-only behavior.
        try {
          const res = await apiRefresh()
          if (mountedRef.current) applySession(res, 'renewal')
        } catch {
          if (mountedRef.current) clearSession()
        }
        return
      }

      // A round another tab started before this tab's channel existed is
      // invisible on the channel — see LEASE_STORAGE_KEY. Adopt it from the
      // storage mirror, before settling and again after.
      const adoptStoredLease = () => {
        if (activeLeaseRef.current) return
        const stored = readStoredLease()
        if (stored && stored.from !== tabIdRef.current && stored.ts + LEASE_MS > Date.now()) {
          activeLeaseRef.current = stored
        }
      }
      adoptStoredLease()

      if (!activeLeaseRef.current) {
        // Nobody appears to be renewing yet — but that could just mean the
        // tab that IS about to claim this round hasn't had its own channel
        // open long enough for us to have heard it. See SETTLE_MS's comment
        // for why a bare "silence so far" read isn't enough on its own here.
        await new Promise((resolve) => setTimeout(resolve, SETTLE_MS))
        // This provider may have unmounted during that wait — see
        // mountedRef's comment. Nothing past this point should touch state
        // or a channel that could already be closed.
        if (!mountedRef.current) return
        adoptStoredLease()
      }

      const existingLease = activeLeaseRef.current
      if (existingLease && existingLease.ts + LEASE_MS > Date.now()) {
        // Someone else already claimed this round — never call the network
        // ourselves while that claim is still live.
        const settled = await waitForLease(existingLease)
        if (!mountedRef.current) return
        if (!settled) {
          return round()
        }
        return
      }

      // Still nothing after settling. Announce intent and give any tab
      // whose own settle window ends at essentially the same instant a
      // chance to be heard before committing to being the one that calls
      // the network — exactly as renewInFlightRef doesn't let a same-tab
      // caller proceed on a bare "nothing in flight" read alone either.
      const myClaim: Claim = { from: tabIdRef.current, claimId: randomId(), ts: Date.now() }
      activeLeaseRef.current = myClaim
      safePostMessage(channel, { type: 'claim', ...myClaim })
      await new Promise((resolve) => setTimeout(resolve, ELECTION_WINDOW_MS))
      if (!mountedRef.current) return

      const afterWindow = activeLeaseRef.current
      if (afterWindow?.claimId !== myClaim.claimId) {
        // Some other tab's claim beat ours — or the round already finished
        // during our own window (afterWindow is then null; vanishingly
        // unlikely, since a winner only calls the network *after* its own
        // window, but there's nothing left to wait for either way).
        if (!afterWindow) return
        const settled = await waitForLease(afterWindow)
        if (!mountedRef.current) return
        if (!settled) {
          return round()
        }
        return
      }

      // We won: we're the one tab that actually talks to the server for
      // this rotation. Mirror the claim for tabs that open while it is in
      // flight (LEASE_STORAGE_KEY), and clear it once it is over.
      writeStoredLease(myClaim)
      const clearStoredLease = () => {
        if (readStoredLease()?.claimId === myClaim.claimId) writeStoredLease(null)
      }
      try {
        const res = await apiRefresh()
        activeLeaseRef.current = null
        clearStoredLease()
        if (!mountedRef.current) {
          // Still broadcast the result — a real second tab waiting on
          // waitForLease has no other way to learn this round finished —
          // but don't call applySession, which would set state on a
          // provider that's already gone.
          safePostMessage(channel, {
            type: 'result',
            claimId: myClaim.claimId,
            ok: true,
            accessToken: res.accessToken,
            expiresIn: res.expiresIn,
            mustChangePassword: res.mustChangePassword,
          })
          return
        }
        applySession(res, 'renewal')
        safePostMessage(channel, {
          type: 'result',
          claimId: myClaim.claimId,
          ok: true,
          accessToken: res.accessToken,
          expiresIn: res.expiresIn,
          mustChangePassword: res.mustChangePassword,
        })
      } catch (err) {
        activeLeaseRef.current = null
        clearStoredLease()
        // Only a DEFINITIVE answer from the hub that the refresh token
        // itself is dead (expired, revoked, or reuse-detected —
        // internal/api/auth.go's handleRefresh, type
        // invalid-refresh-token) means the session is actually over.
        // client.ts's own convention is to decide this from ApiError.type,
        // never from status/prose (see ApiError's own doc comment) — and
        // that is what tells a real rejection apart from a TRANSPORT
        // failure (offline, DNS, a tab/laptop whose network hasn't
        // reconnected yet after sleep/idle), which client.ts also reports
        // as an ApiError, with status 0 and no type at all. Treating the
        // two the same was a live bug: a tab idle long enough for the 80%-
        // lifetime timer above to fire right as it woke, before the
        // network was back, logged the user out even though the refresh
        // cookie was perfectly valid — proven by a plain reload, moments
        // later, succeeding against that same cookie.
        const refreshTokenIsDead =
          err instanceof ApiError && err.type === 'https://argus.io/errors/invalid-refresh-token'
        // Same definitive-rejection family as refreshTokenIsDead above, but
        // from authz.RotateRefreshTokenDetailed's OWN issued_at check
        // (migration 000131) rather than reuse/expiry — see
        // internal/api/auth.go's handleRefresh for why this gets a distinct
        // ApiError.type instead of reusing invalid-refresh-token: LoginPage
        // shows a different reason for the two.
        const idleTimedOut =
          err instanceof ApiError && err.type === 'https://argus.io/errors/session-idle-timeout'
        if (refreshTokenIsDead || idleTimedOut) {
          // Never surface this as an error the user has to dismiss — same
          // as any other session ending.
          if (mountedRef.current) {
            if (idleTimedOut) setEndedForIdle(true)
            clearSession()
          }
          safePostMessage(channel, { type: 'result', claimId: myClaim.claimId, ok: false })
          return
        }
        // Not definitive: leave the existing session exactly as it is —
        // broadcasting ok:false here would make every other open tab call
        // clearSession() too (see the 'result' handler above), which would
        // just reintroduce the same bug fleet-wide. Deliberately send no
        // result at all: a tab waiting on this round (waitForLease) times
        // out after LEASE_MS and re-runs the whole gate itself, the same
        // resilience path that already covers this tab dying mid-round.
        // This tab retries on its own shortly, via the same timer/ref the
        // normal 80%-lifetime schedule uses.
        if (mountedRef.current) {
          scheduleRenewalRef.current(NETWORK_RETRY_DELAY_MS)
        }
      }
    }

    const attempt = round()
    renewInFlightRef.current = attempt
    try {
      await attempt
    } finally {
      // Compared against `attempt` rather than nulled outright, so a renewal
      // that somehow started after this one settled isn't cleared out from
      // under itself.
      if (renewInFlightRef.current === attempt) {
        renewInFlightRef.current = null
      }
    }
  }, [applySession, clearSession, waitForLease])

  useEffect(() => {
    renewSessionRef.current = renewSession
  }, [renewSession])

  useEffect(() => {
    // The refresh request is the external system this effect synchronizes
    // with; bootstrapping ends only after that asynchronous request settles.
    // Guarded by mountedRef: renewSession() always runs at least one
    // SETTLE_MS/ELECTION_WINDOW_MS round-trip before touching the network
    // (see mountedRef's own comment), which a short-lived render — mainly
    // in tests — can easily outlive.
    // oxlint-disable-next-line react/set-state-in-effect
    void renewSession().finally(() => {
      if (mountedRef.current) setIsBootstrapping(false)
    })
    return () => clearTimeout(renewTimer.current)
    // Runs once on mount only — this is the actual fix for "refreshing the
    // UI loses the session": attempt to restore it from the persisted
    // refresh token before rendering anything that would redirect to /login.
  }, [renewSession])

  // login signs in with a password. Note what it does NOT do with
  // `loginEmail`: it is the address typed into the form, it is used to
  // authenticate, and it is then discarded rather than displayed. What the
  // header shows comes from the hub's answer for the resulting token — the
  // typed string is a claim, and on this path it merely happened to usually
  // be right (PROJECT.md B165).
  const login = useCallback(
    async (loginEmail: string, password: string) => {
      const res = await apiLogin({ email: loginEmail, password })
      applySession(res, 'sign-in')
    },
    [applySession],
  )

  // completeSSOLogin adopts a session from a federated login (PROJECT.md S2).
  //
  // Called once by SSOCompletePage with the single-use handoff code the OIDC
  // callback put in the redirect. It goes through the same applySession as a
  // password login, so a federated session is not a second kind of session
  // with its own renewal and storage rules to keep correct — and, since
  // B165, not a second kind of identity either.
  //
  // This is the path the bug was reported on. The browser never sees the
  // identity provider's claims, only an opaque handoff code, so there is
  // nothing here to name the account with — and the previous version filled
  // that gap from localStorage, which on a shared browser is the PREVIOUS
  // person's address. The comment it did that under claimed "the stored value
  // is refreshed by the next /me-backed render anyway"; there was no /me
  // route in this product at all, so nothing ever refreshed it and the wrong
  // name simply stayed. applySession now asks the hub who this token belongs
  // to, on this path exactly as on every other.
  const completeSSOLogin = useCallback(
    async (code: string) => {
      const res = await apiSSOExchange(code)
      applySession(res, 'sign-in')
    },
    [applySession],
  )

  const changePassword = useCallback(
    async (currentPassword: string, newPassword: string) => {
      if (!accessToken) {
        throw new Error('changePassword called with no active session')
      }
      const res = await apiChangePassword({ currentPassword, newPassword }, accessToken)
      // 'sign-in' rather than 'renewal': this response carries the real
      // mustChangePassword (now false), which is the banner this flow exists
      // to clear. The identity is re-read too — the same account, so the
      // answer is the same, and paying one request to keep ONE identity
      // mechanism beats a second path that assumes it.
      applySession(res, 'sign-in')
    },
    [accessToken, applySession],
  )

  // PROJECT.md B164: signing out used to be purely client-side — it only
  // ever called clearSession() below, so nothing server-side ever heard
  // about it, and a refresh token captured before that click stayed valid
  // against the hub for up to 30 more days. POST /auth/logout
  // (internal/api/auth.go's handleLogout) is what actually closes that gap:
  // it revokes the WHOLE rotation family the current `argus_refresh` cookie
  // belongs to, so a captured token — whether it's the one live right now
  // or an earlier link already superseded by rotation — is refused the next
  // time anything tries to use it.
  //
  // Awaited, so the outcome is known rather than assumed: the local session
  // ends either way (a "Sign out" that leaves you signed in because the hub
  // is down would be worse), but an unconfirmed revocation is reported on the
  // sign-in screen instead of being swallowed. Bounded by LOGOUT_WAIT_MS so an
  // unresponsive hub cannot hold the button; the request itself is sent with
  // keepalive (client.ts), so it still completes if this tab goes away.
  const logout = useCallback(async () => {
    setSigningOut(true)
    let outcome: 'confirmed' | 'unconfirmed' = 'unconfirmed'
    try {
      await Promise.race([
        apiLogout().then(() => {
          outcome = 'confirmed'
        }),
        new Promise((resolve) => setTimeout(resolve, LOGOUT_WAIT_MS)),
      ])
    } catch {
      // Reported through `outcome` — see above.
    }
    if (!mountedRef.current) return
    setSigningOut(false)
    setSignOut(outcome)
    clearSession()
  }, [clearSession])

  const value = useMemo(
    () => ({
      accessToken,
      userId: identity.userId,
      email: identity.email,
      authMethod: identity.authMethod,
      identityStatus: identity.status,
      mustChangePassword,
      isBootstrapping,
      login,
      completeSSOLogin,
      changePassword,
      logout,
      signingOut,
      signOut,
      overviewDefaultWindowDays: effectiveSettings.overviewDefaultWindowDays,
      minPasswordLength: effectiveSettings.minPasswordLength,
      sessionIdleTimeoutMinutes: effectiveSettings.sessionIdleTimeoutMinutes,
      endedForIdle,
    }),
    [
      accessToken,
      identity,
      mustChangePassword,
      isBootstrapping,
      login,
      completeSSOLogin,
      changePassword,
      logout,
      signingOut,
      signOut,
      effectiveSettings,
      endedForIdle,
    ],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
