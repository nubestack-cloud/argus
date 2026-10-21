import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from './useAuth'

// Simple auth guard: no access token in memory → bounce to /login.
// This is a UX convenience only, not a security boundary — the hub itself
// is the actual enforcement point for every request.
export function ProtectedRoute({ children }: { children: ReactNode }) {
  const { accessToken, isBootstrapping, signOut } = useAuth()
  const location = useLocation()

  // Don't redirect to /login while the initial silent-restore (from a
  // persisted refresh token) is still in flight — otherwise a session that
  // WOULD have been restored flashes the login page first, which is exactly
  // the "session isn't persistent" symptom this whole mechanism exists to
  // fix.
  if (isBootstrapping) {
    return <p className="centered-page">Loading…</p>
  }

  if (!accessToken) {
    // Remember where the reader was only when the session ran out under
    // them. After an explicit sign-out the next person at this browser is not
    // necessarily the same one, and landing them on the outgoing user's last
    // page (an incident, someone's settings) is wrong even though the hub
    // would still authorize what they can see.
    if (signOut) {
      return <Navigate to="/login" replace />
    }
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  return <>{children}</>
}
