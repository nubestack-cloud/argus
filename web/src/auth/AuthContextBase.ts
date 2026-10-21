import { createContext } from 'react'

export interface AuthContextValue {
  accessToken: string | null
  // Who the access token currently held authenticates as, per
  // GET /api/v1/users/me — never what was typed into a form, never what a
  // previous session left in this browser (PROJECT.md B165).
  //
  // userId and email are both null unless identityStatus is 'ready'. Consumers
  // MUST branch on identityStatus rather than treating a null email as "no
  // account": 'pending' means the answer has not arrived yet and
  // 'unavailable' means the hub could not be asked, and those two want
  // different things on screen — a placeholder versus an admission. What
  // neither may produce is a name, which is why there is no fallback value
  // here to reach for.
  userId: string | null
  email: string | null
  // How the signed-in account authenticates, or null until known. Read by the
  // account menu to decide whether changing a password is possible at all.
  authMethod: 'password' | 'federated' | null
  identityStatus: 'pending' | 'ready' | 'unavailable'
  mustChangePassword: boolean
  // The org-wide Appearance/General effective settings (PROJECT.md,
  // 2026-10-14), read from the same GET /users/me call that resolves
  // identity above. Like mustChangePassword, these are plain values rather
  // than being gated by identityStatus — they default to the hub's own
  // shipped values (14, 12, null) until the real response arrives, the same
  // direction ChangePasswordModal's own hardcoded echo used to take, and are
  // simply overwritten once it does.
  overviewDefaultWindowDays: 14 | 30
  minPasswordLength: number
  sessionIdleTimeoutMinutes: number | null
  // True when the session just ended because the hub's refresh endpoint
  // refused a renewal as idle-timed-out (ApiError.type
  // 'https://argus.io/errors/session-idle-timeout') rather than for any other
  // reason — see round()'s catch in AuthContext for where this is set.
  // LoginPage reads it once to show "signed out for inactivity" instead of a
  // generic message; AuthContext resets it to false on the next sign-in so it
  // never outlives the explanation it's for.
  endedForIdle: boolean
  isBootstrapping: boolean
  login: (email: string, password: string) => Promise<void>
  // Adopts a session from a federated login, given the single-use handoff
  // code the OIDC callback put in the redirect (PROJECT.md S2). Produces the
  // same session a password login does — see AuthContext's own comment for
  // why a federated session is deliberately not a second kind.
  completeSSOLogin: (code: string) => Promise<void>
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>
  // Ends the session: asks the hub to revoke it, waits (bounded) for the
  // answer, then clears local state whatever the answer was.
  logout: () => Promise<void>
  // True while a sign-out is waiting on the hub.
  signingOut: boolean
  // How the last explicit sign-out in this tab ended, until the next sign-in;
  // null if there has not been one. 'unconfirmed' means the hub could not be
  // reached or refused, so the server-side session may still be live.
  signOut: 'confirmed' | 'unconfirmed' | null
}

export const AuthContext = createContext<AuthContextValue | undefined>(undefined)
