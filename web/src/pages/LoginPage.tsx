import { useEffect, useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/useAuth'
import { ApiError, ssoProviders } from '../api/client'
import { SentinelFieldLogin } from './login/SentinelFieldLogin'
import { ApertureLogin } from './login/ApertureLogin'
import type { SSOProvider } from '../api/types'

// How long to wait before retrying the unauthenticated providers/style call
// below, after it fails. Short: the usual cause is the same transient
// network gap AuthContext's own renewal retry exists for (a tab/laptop just
// woken from sleep or idle), not a real, lasting outage.
const SSO_PROVIDERS_RETRY_MS = 4_000

export function LoginPage() {
  const { accessToken, isBootstrapping, login, signOut, endedForIdle } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [providers, setProviders] = useState<SSOProvider[]>([])
  // Which sign-in layout to render, from the same unauthenticated call that
  // fetches the provider list. Undefined until it lands, which `frameFor`
  // resolves to the default — so the screen is never blank waiting on a
  // branding lookup, for the same reason the provider fetch has no loading
  // state: this is the screen someone needs during an outage.
  const [loginStyle, setLoginStyle] = useState<string | undefined>(undefined)
  // This hub's version, for the screens' footers.
  const [version, setVersion] = useState<string | undefined>(undefined)

  // The identity-provider list (PROJECT.md S2). Fetched unauthenticated, and
  // every failure path deliberately degrades to "password only" rather than
  // to a broken screen: an identity provider being unreachable must never be
  // the reason nobody can sign in, which is the same argument break-glass
  // local login rests on. So there is no loading state and no error state
  // rendered here — the password form is already usable while this is in
  // flight, and showing a spinner over it would delay a login that does not
  // need this answer.
  useEffect(() => {
    let cancelled = false
    let retryTimer: ReturnType<typeof setTimeout> | undefined
    const load = () => {
      void ssoProviders()
        .then((res) => {
          if (cancelled) return
          setProviders(res.providers)
          setLoginStyle(res.loginStyle)
          setVersion(res.version)
        })
        .catch(() => {
          // Silent on screen — no spinner, no error banner; logging to the
          // console would be the only visible effect, and the screen is
          // correct without it (the password form is already usable). But
          // silent must not mean permanent: this call landing in the same
          // transient network gap a woken-from-idle tab can hit (see
          // AuthContext's own renewal retry) used to leave loginStyle stuck
          // at undefined — which the render switch below reads the same as
          // "show the default" — for the rest of this mount, so the real
          // admin-chosen style never arrived even once the network came
          // back. Retrying is what makes that converge instead.
          if (!cancelled) {
            retryTimer = setTimeout(load, SSO_PROVIDERS_RETRY_MS)
          }
        })
    }
    load()
    return () => {
      cancelled = true
      clearTimeout(retryTimer)
    }
  }, [])

  // A reason code the OIDC callback put in the URL after refusing a login.
  // Rendered from a fixed map rather than from the query string itself, so
  // nothing an identity provider said can reach the page as text.
  const ssoError = new URLSearchParams(location.search).get('ssoError')
  const ssoErrorMessage =
    ssoError === 'sso_declined'
      ? 'Sign-in was cancelled at your identity provider.'
      : ssoError === 'sso_expired'
        ? 'That sign-in attempt took too long. Please try again.'
        : ssoError
          ? 'Single sign-on failed. Please try again, or contact your administrator.'
          : null
  // A sign-out the hub did not confirm (it was unreachable, or refused): the
  // local session is over, but the server-side one may not be, and saying so
  // is the difference between a sign-out and an apparent one.
  const signOutMessage =
    signOut === 'unconfirmed'
      ? "You're signed out of this browser, but Argus didn't confirm it ended the session. Sign in and sign out again, or ask an administrator to end your sessions."
      : null
  // The hub's own refresh endpoint refused a renewal specifically as
  // idle-timed-out (Settings > General > Max session idle time, migration
  // 000131) rather than for any other reason — see AuthContext's round()
  // catch for where endedForIdle is set. Distinct from signOutMessage above:
  // that one is about an explicit sign-out the hub didn't confirm, this one
  // never involved a sign-out click at all.
  const idleMessage = endedForIdle
    ? 'You were signed out after a period of inactivity. Sign in again to continue.'
    : null
  // The page the reader was on when their session ran out. Never honoured
  // after an explicit sign-out — ProtectedRoute does not record one then, and
  // this guard covers a location state that survived from before it.
  const requestedPath =
    !signOut ? (location.state as { from?: { pathname?: string } } | null)?.from?.pathname : undefined
  const destination = requestedPath && requestedPath !== '/login' ? requestedPath : '/overview'

  // A direct visit to /login with an already-restorable (or just-restored)
  // session shouldn't force a redundant re-login — the whole point of
  // persisting the refresh token is that this page isn't where a returning
  // user should land at all. These early returns come after every hook
  // call above (Rules of Hooks — a return before them would skip some
  // hooks on this render but not others).
  if (isBootstrapping) {
    // Nothing is rendered while the session restore is in flight. The three
    // ported screens each open with their own entrance animation (card rise,
    // iris open, tile pop) and mounting one behind a skeleton and then
    // remounting it would play that entrance twice. This branch is brief — it
    // is one refresh-token call — and the alternative is a flash of a screen
    // the viewer never needed to see.
    return null
  }
  if (accessToken) {
    return <Navigate to={destination} replace />
  }

  // The real sign-in. Each screen runs the design's staged label sequence on
  // submit AND awaits this; on success the route navigates (unmounting
  // mid-sequence, which is right — nobody should sit through 5.6s of animation
  // to get into the app), on failure the screen's own error element shows what
  // the hub said and the sequence unwinds. A rejection is what each screen
  // catches, so this rethrows rather than swallowing.
  async function handleLogin(email: string, password: string) {
    try {
      await login(email, password)
      navigate(destination, { replace: true })
    } catch (err) {
      if (err instanceof ApiError) {
        throw new Error(err.detail ? `${err.message} — ${err.detail}` : err.message)
      }
      // A NETWORK failure, not a rejected credential, and worth saying so. This
      // is the case the owner hit: a laptop with no route to the hub. `fetch`
      // rejects with a TypeError there, never an ApiError, so "Something went
      // wrong" was all the screen could say about an outage it could describe
      // precisely.
      if (err instanceof TypeError) {
        throw new Error("Can't reach Argus. Check your connection, then try again.")
      }
      throw new Error('Something went wrong. Please try again.')
    }
  }

  const shared = {
    providers,
    destination,
    onLogin: handleLogin,
    ssoErrorMessage: ssoErrorMessage ?? signOutMessage ?? idleMessage,
    version,
  }

  // One of the two ported designs, chosen install-wide in
  // Settings -> Appearance. An unknown value lands on the default rather than
  // rendering nothing: the hub normalises this twice already, so a value this
  // switch does not know means a hub newer than this bundle.
  switch (loginStyle) {
    case 'sentinel':
      return <SentinelFieldLogin {...shared} />
    case 'aperture':
    default:
      return <ApertureLogin {...shared} />
  }
}
