import { useEffect, useRef, useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/useAuth'
import { ApiError } from '../api/client'
import { ArgusLogoMark } from '../components/icons'

// The landing page for a completed federated login (PROJECT.md S2).
//
// The OIDC callback (internal/api/auth_oidc.go) redirects a browser here with
// a single-use handoff code, which this page immediately trades for a real
// token pair. It exists because the callback's response is a 302 and this
// application authenticates with bearer tokens held in JavaScript — see
// internal/authz.SSOHandoffIssuer for why a code rather than a URL fragment.
//
// Nothing on this screen is a decision, so it deliberately shows no controls
// and no data: it is in flight for one round trip and then gone. The only
// state worth rendering is the failure, because a person who lands here and
// stays here needs to know why rather than watching a spinner forever.
export function SSOCompletePage() {
  const { accessToken, completeSSOLogin } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  // exchangeError is what the exchange itself reported; the missing-code case
  // is DERIVED during render rather than set in the effect, because it is a
  // property of the URL and not of anything asynchronous — setting state for
  // it would start a second render for a value already known on the first.
  const [exchangeError, setExchangeError] = useState<string | null>(null)

  const params = new URLSearchParams(location.search)
  const code = params.get('code')
  // Where to land afterwards. Sanitised on the server too
  // (internal/idp.SafeReturnTo) — this is the client-side half of the same
  // open-redirect guard, not a substitute for it: a path that names another
  // host must never become a navigation, and the server cannot stop this page
  // from following one it is handed.
  const rawReturnTo = params.get('returnTo') ?? '/overview'
  const returnTo = rawReturnTo.startsWith('/') && !rawReturnTo.startsWith('//') ? rawReturnTo : '/overview'

  // The exchange must happen exactly once. React's development StrictMode
  // mounts effects twice, and the handoff code is single-use by design, so
  // without this guard the second attempt would consume nothing and report a
  // failure for a login that actually succeeded.
  const exchanged = useRef(false)

  useEffect(() => {
    if (exchanged.current || !code) return
    exchanged.current = true

    void completeSSOLogin(code)
      .then(() => {
        navigate(returnTo, { replace: true })
      })
      .catch((err: unknown) => {
        // The server's own message, when it gave one — it is written for a
        // person and says whether the code was stale or the account is
        // disabled. ApiError extends Error, so the RFC 9457 title arrives as
        // `message`; `detail` carries the longer explanation when there is
        // one. Anything else is a network failure.
        setExchangeError(
          err instanceof ApiError
            ? err.detail || err.message || 'Could not complete sign-in.'
            : 'Could not reach the ARGUS hub to complete sign-in.',
        )
      })
  }, [code, completeSSOLogin, navigate, returnTo])

  const error =
    exchangeError ?? (code ? null : 'That sign-in link is missing its code. Please start again.')

  // Already signed in and no exchange pending: nothing to do here.
  if (accessToken && !code) {
    return <Navigate to={returnTo} replace />
  }

  return (
    <div className="centered-page">
      <div className="card auth-form">
        <div className="auth-brand">
          <ArgusLogoMark className="auth-brand-mark" size={54} />
          <div className="auth-brand-text">
            <h1 className="app-brand-wordmark">ARGUS</h1>
          </div>
        </div>

        {error ? (
          <>
            <p className="form-error" role="alert">
              {error}
            </p>
            <button type="button" onClick={() => navigate('/login', { replace: true })}>
              Back to sign in
            </button>
          </>
        ) : (
          // No skeleton and no spinner: this is one round trip, and a
          // progress indicator for something that finishes before it renders
          // is decoration. A plain, honest sentence is the whole screen.
          <p className="subtitle" role="status">
            Completing sign-in…
          </p>
        )}
      </div>
    </div>
  )
}
