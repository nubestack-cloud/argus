package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/logging"
	"argus/internal/settings"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// loginResponse deliberately no longer carries a refreshToken field
// (PROJECT.md B164). The refresh token now travels ONLY as the
// refreshCookieName cookie set alongside this body — never in JSON, never
// readable by page scripts — see setRefreshCookie's doc comment. Every
// caller that used to read res.refreshToken (web/src/auth/AuthContext.tsx)
// has to stop relying on it entirely, not just stop persisting it.
type loginResponse struct {
	AccessToken        string `json:"accessToken"`
	ExpiresIn          int    `json:"expiresIn"`
	MustChangePassword bool   `json:"mustChangePassword"`
}

// refreshCookieName is the HttpOnly cookie the refresh token now travels in
// (PROJECT.md B164), replacing the old JSON-body/localStorage token. A page
// script can never read it — that is the whole point of the fix — and
// nothing under web/src ever attempts to.
const refreshCookieName = "argus_refresh"

// refreshCookiePath scopes the cookie to exactly the endpoints that ever
// read or rotate it: /auth/login, /auth/refresh, /auth/logout and
// /auth/sso/exchange (auth_oidc.go) all live under this prefix. Nothing
// outside /api/v1/auth needs this cookie at all — the browser will never
// even attach it to, say, GET /api/v1/clusters — which is a second,
// independent narrowing on top of HttpOnly, not a substitute for it.
const refreshCookiePath = "/api/v1/auth"

// setRefreshCookie issues (or rotates) the refresh-token cookie.
//
// Secure is NOT unconditional — see isRequestSecure's doc comment for why.
// Setting it unconditionally would silently and permanently break sign-in on
// this product's own documented local deployment, which is reached over
// plain HTTP at a bare LAN address (ARGUS_TUNNEL_PUBLIC_ENDPOINT is a
// "host:8443" LAN IP, and the API/UI listener next to it is plain
// http.ListenAndServe on :8080 — cmd/hub/main.go never calls
// ListenAndServeTLS for this listener). Browsers refuse to ever send a
// Secure cookie back over a plain-HTTP connection to a non-localhost host,
// so a refresh cookie marked Secure there would present as "refresh
// mysteriously stops working after the first request," not as a misset
// flag.
//
// SameSite is Lax, not Strict: auth_oidc.go's flow ends with the identity
// broker redirecting the browser to this hub's OWN /auth/sso/callback — a
// top-level, cross-site GET navigation from the IdP's origin — and a Strict
// cookie set during an earlier same-site request is not attached to that
// navigation at all. Lax still withholds the cookie from cross-site
// POST/fetch/XHR requests, which is the CSRF-relevant case here since every
// endpoint that ever reads this cookie (login, refresh, logout, sso/exchange)
// is POST — so Lax gives the SSO callback what it needs without giving up
// meaningful CSRF protection on the endpoints that matter.
func setRefreshCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    token,
		Path:     refreshCookiePath,
		MaxAge:   int(authz.RefreshTokenTTL.Seconds()),
		HttpOnly: true,
		Secure:   isRequestSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// clearRefreshCookie ends the cookie — on logout, and on any refresh attempt
// that turned out to be invalid/expired/reused, so a browser never keeps
// presenting a token the hub has already told it is dead. Same
// Path/HttpOnly/Secure/SameSite as setRefreshCookie: a Set-Cookie with
// different attributes would create a SECOND, independent cookie rather
// than clear the first one. MaxAge<0 tells the browser to delete it
// immediately, rather than merely re-stating its existing expiry.
func clearRefreshCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     refreshCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isRequestSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

// isRequestSecure reports whether r actually arrived over TLS — directly, or
// via a reverse proxy that terminated TLS and said so — and is the ONLY
// thing that may ever turn a cookie's Secure attribute on. See
// setRefreshCookie's comment for why getting this wrong in the other
// direction (Secure when the connection is not actually secure) silently
// and permanently breaks the documented local deployment.
//
// r.TLS is set whenever THIS listener terminated TLS itself. That never
// happens for cmd/hub/main.go's API listener today (only the separate mTLS
// tunnel on its own port does), so this is always false on that path in the
// current deployment — matching Secure=false there, which is required for
// it to keep working at all.
//
// X-Forwarded-Proto is honoured for the other real case: the Helm chart's
// optional Ingress (deploy/helm/argus-hub/templates/ingress.yaml) can
// terminate TLS in front of this same plain-HTTP pod, in which case r.TLS is
// still nil here — only the browser-to-ingress hop was HTTPS — and this is
// how a TLS-terminating proxy conventionally reports that fact to its
// backend.
//
// There is no "trust this proxy" allowlist here (this codebase has none
// anywhere yet), so a request that reaches this listener directly can set
// its own X-Forwarded-Proto and claim to be secure when it is not. That
// cannot be used to steal or weaken anyone ELSE's cookie: it only affects
// the Set-Cookie this same response is about to send, over the same
// connection the forged header rode in on, and a browser that receives a
// Secure Set-Cookie over an actually-plain-HTTP response refuses to store it
// at all (RFC 6265 §5.3) — the forgery fails closed (no cookie stored) for
// the forger's own request, never open for anyone else's.
func isRequestSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// verifyPassword is the login path's one seam over authz.VerifyPassword. It
// exists so a test can OBSERVE that both of handleLogin's failure paths —
// user found with a wrong password, and user not found at all — actually
// spend an Argon2id verification (see dummyLoginPasswordHash below and
// TestHandleLoginVerifiesPasswordOnBothPaths in auth_test.go). The property
// under test is a timing equivalence, and asserting on wall-clock timings
// would be flaky in CI, so the test counts calls through this variable
// instead. Never reassigned outside tests.
var verifyPassword = authz.VerifyPassword

// dummyLoginPasswordHash is a throwaway Argon2id hash that handleLogin
// verifies the supplied password against when no user matches the submitted
// email, so that path costs the same ~100ms of Argon2id work as a real one.
//
// Generated exactly once, here at package level, for two reasons: hashing is
// deliberately expensive (paying it per request would hand an attacker a
// trivial DoS amplifier on an unauthenticated endpoint), and deriving it
// through authz.HashPassword rather than hardcoding a literal keeps it
// automatically in step with the Argon2id cost parameters in
// internal/authz/password.go — if those change, the dummy verification's cost
// changes with them and the two paths stay comparable.
//
// The plaintext is random and immediately discarded: nothing ever needs to
// verify successfully against this hash, only to spend the same work failing
// to. That also means it can never function as a working credential even if
// it somehow found its way into a users row.
var dummyLoginPasswordHash = mustDummyLoginPasswordHash()

func mustDummyLoginPasswordHash() string {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		// Unreachable short of a broken crypto/rand, and failing loudly at
		// startup is the only safe response: without this hash the
		// user-not-found path has nothing to spend equivalent work on and
		// silently degrades back into the enumeration oracle below.
		panic(fmt.Sprintf("api: generate dummy login password: %v", err))
	}
	hash, err := authz.HashPassword(base64.RawURLEncoding.EncodeToString(buf))
	if err != nil {
		panic(fmt.Sprintf("api: hash dummy login password: %v", err))
	}
	return hash
}

// handleLogin implements local-password authentication (lld/02-authz-spec.md §8).
// Not wrapped with requireAuth — there's no session yet to require — but it opens
// and scopes its own transaction for exactly the same reason every other DB access
// in this codebase does: RLS applies here too, and login isn't an exception to it.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}

	// Checked BEFORE any database work, deliberately — BACKLOG.md G7:
	// unbounded login attempts previously cost nothing beyond the (now
	// symmetric, per the dummy-hash fix below) per-request Argon2id latency.
	// Checking here, ahead of tx.Begin, means a request already over the
	// threshold costs one in-memory map lookup, not a DB round trip plus a
	// deliberately-expensive password hash — the fast path is fast precisely
	// when it's being hit hardest.
	//
	// Logged, not audited: writing an audit row needs a transaction and a
	// resolved tenant, which is exactly the DB work this check exists to
	// avoid paying for on a request already identified as abusive. The
	// trade-off is deliberate — see internal/authz.LoginRateLimiter's own
	// doc comment for what this control does and does not attempt.
	if !s.loginRateLimit.Allow(req.Email, clientIP(r)) {
		logger.WarnContext(r.Context(), "sign-in rate limit exceeded",
			slog.String("email", req.Email), slog.String("source_ip", clientIP(r)))
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(authz.LoginRateLimitWindow.Seconds())))
		writeProblem(w, http.StatusTooManyRequests, "https://argus.io/errors/rate-limited",
			"Too many login attempts", fmt.Sprintf("try again in %s", authz.LoginRateLimitWindow))
		return
	}

	ctx := r.Context()
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "beginning the sign-in transaction failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not start transaction", "")
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		logger.ErrorContext(ctx, "resolving the organisation for a sign-in failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not resolve organisation", "")
		return
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		logger.ErrorContext(ctx, "setting the request scope for a sign-in failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not set request scope", "")
		return
	}

	// recordDenied writes a "denied" audit event for this login attempt using
	// the SAME transaction opened above (already scoped by SetRequestScope) —
	// unlike requireCapability's denial case, nothing else in this
	// transaction has (or ever will) mutate anything, so there's no need to
	// open a second, separate transaction just to make the audit row durable;
	// explicitly committing THIS transaction right here is sufficient and
	// simpler. Deliberately best-effort: a failure to log a denial must never
	// be promoted into a 500 for what is, correctly, still a 401 — and must
	// never block the response either way.
	recordDenied := func() {
		// Recorded alongside the audit event, not instead of it — this is what
		// makes the NEXT attempt (whether it comes 1 second or 1 hour from now)
		// see this one when Allow is checked above.
		s.loginRateLimit.RecordFailure(req.Email, clientIP(r))
		if err := audit.RecordEvent(ctx, tx, audit.Event{
			TenantID:        tenantID,
			ActorAuthMethod: "password",
			SourceIP:        clientIP(r),
			Outcome:         audit.OutcomeDenied,
			Details:         map[string]any{"action": "login_failed", "email": req.Email},
		}); err != nil {
			logger.ErrorContext(ctx, "recording a denied sign-in in the audit log failed", logging.Err(err))
		}
		if err := tx.Commit(ctx); err != nil {
			logger.ErrorContext(ctx, "committing after a denied sign-in failed", logging.Err(err))
		}
	}

	var userID, passwordHash string
	var mustChange bool
	var generation int64
	err = tx.QueryRow(ctx,
		`SELECT id, password_hash, must_change_password, token_generation FROM users
		 WHERE lower(email) = lower($1) AND disabled_at IS NULL AND deleted_at IS NULL`,
		req.Email).Scan(&userID, &passwordHash, &mustChange, &generation)
	if err != nil || passwordHash == "" {
		// Deliberately identical response whether the user doesn't exist or the
		// password is wrong — distinguishing the two would let an attacker
		// enumerate valid emails one login attempt at a time. ActorID stays nil
		// for the same reason: no authenticated actor exists at this point, only
		// a claimed email (recorded in Details, not actor_id).
		//
		// The response BODY was always identical; the response TIME was not,
		// which made the paragraph above only half true. Returning from here
		// without ever hashing anything meant a miss cost a single indexed
		// SELECT while a hit cost that plus a full Argon2id verification
		// (~100ms) — a difference so large it needs no statistics to read off a
		// stopwatch, and therefore exactly the email-enumeration oracle this
		// path claims to close. So verify the submitted password against a
		// fixed dummy hash and discard the result: both paths now do one
		// SELECT plus one Argon2id verification before answering 401.
		//
		// Unconditional on purpose. Skipping this when req.Password is empty
		// (or short, or otherwise "obviously" not worth checking) would just
		// move the oracle to a different input rather than remove it: an
		// attacker who can pick the password picks the one that short-circuits.
		// authz.VerifyPassword is called for its cost here, not its verdict —
		// both return values are deliberately ignored.
		_, _ = verifyPassword(req.Password, dummyLoginPasswordHash)

		recordDenied()
		writeProblem(w, http.StatusUnauthorized, "https://argus.io/errors/invalid-credentials", "Invalid email or password", "")
		return
	}

	// Through the verifyPassword seam, not authz.VerifyPassword directly, so a
	// test can see that this call and the dummy one above both happen — see
	// verifyPassword's doc comment.
	valid, err := verifyPassword(req.Password, passwordHash)
	if err != nil || !valid {
		recordDenied()
		writeProblem(w, http.StatusUnauthorized, "https://argus.io/errors/invalid-credentials", "Invalid email or password", "")
		return
	}

	// Break-glass gate (PROJECT.md S2). Checked AFTER the password so this
	// never becomes an account oracle: a wrong password and a
	// correct-password-but-not-permitted attempt both spend the same Argon2id
	// verification and reach a refusal, which is the property
	// dummyLoginPasswordHash above exists to protect.
	allowedLocal, err := s.localLoginAllowedFor(ctx, tx, tenantID, userID)
	if err != nil {
		logger.ErrorContext(ctx, "resolving local-login eligibility failed", logging.ActorID(userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not complete sign-in", "")
		return
	}
	if !allowedLocal {
		recordDenied()
		logger.WarnContext(ctx, "refusing a password sign-in: an identity provider is enabled and this account does not hold super-admin",
			logging.ActorID(userID))
		writeProblem(w, http.StatusForbidden, "https://argus.io/errors/sso-required",
			"Password sign-in is disabled for this account", "Sign in through your organisation's identity provider.")
		return
	}

	accessToken, err := s.signer.IssueAccessToken(userID, generation)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not issue access token", "")
		return
	}
	refreshToken, err := authz.IssueRefreshToken(ctx, tx, tenantID, userID)
	if err != nil {
		logger.ErrorContext(ctx, "issuing a refresh token at sign-in failed", logging.ActorID(userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not issue refresh token", "")
		return
	}

	// Recorded before Commit, in the same transaction as the tokens it
	// describes, so the audit row and the successful login commit atomically
	// together — if this fails, the whole login fails (rolled back by the
	// deferred tx.Rollback above) rather than silently succeeding with no
	// audit trail.
	if err := audit.RecordEvent(ctx, tx, audit.Event{
		TenantID:        tenantID,
		ActorID:         &userID,
		ActorAuthMethod: "password",
		SourceIP:        clientIP(r),
		Outcome:         audit.OutcomeSuccess,
		// Named, so the audit list's Action column has something to show. A login
		// carries no capability — nobody exercised a permission — so without this
		// the row rendered as actor + "success" and three em dashes, while the
		// FAILED path above already set details.action and read "Login Failed".
		// A successful sign-in being the one unlabelled row was an asymmetry, not a
		// decision. No email here, unlike the failure: on success the actor_id
		// column identifies the user properly, and the failure only carries it
		// because there is no actor to point at.
		Details: map[string]any{"action": "login_succeeded"},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a successful sign-in in the audit log failed", logging.ActorID(userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		logger.ErrorContext(ctx, "committing a successful sign-in failed", logging.ActorID(userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not commit login", "")
		return
	}

	// The refresh token travels ONLY as the cookie — never in this JSON body
	// (PROJECT.md B164). Set after the commit, matching handleChangePassword's
	// existing ordering (below) and the general rule that nothing observable
	// to the client should happen before the transaction it depends on is
	// durable.
	setRefreshCookie(w, r, refreshToken)
	writeJSON(w, http.StatusOK, loginResponse{
		AccessToken:        accessToken,
		ExpiresIn:          int(authz.AccessTokenTTL.Seconds()),
		MustChangePassword: mustChange,
	})
}

// handleRefresh implements rotation-with-reuse-detection (lld/02-authz-spec.md §9.2).
//
// Audit coverage here is the mirror image of what an earlier pass shipped,
// and deliberately so:
//
//   - A routine successful refresh is NOT audited. web/src/auth/AuthContext.tsx
//     calls this endpoint on every page load (silent session restore) and
//     proactively in the background at 80% of the access token's lifetime —
//     neither is a security-relevant event any more than GET
//     /users/me/effective-permissions is; logging every one of them just
//     drowns the audit log in noise for something that isn't a new session
//     (that's handleLogin's job, and its audit calls are untouched — see
//     below), only a routine mid-session renewal.
//   - Reuse of an already-rotated token IS audited, prominently, as the one
//     case on this path that's actually worth a permanent record: someone
//     presented a refresh token that had already been exchanged for a newer
//     one, which is exactly the "stolen session token replayed" signal
//     lld/01-threat-model.md's asset table calls out ("refresh-token theft
//     is the higher-value target since it renews") and lld/02-authz-spec.md
//     §14 names as its own event, `refresh_token.reuse_detected`. "Not
//     found" and "expired" alone (no reuse detected) still get no audit row
//     either — those are just an old or unrecognized token, not a signal —
//     which is now a real, checked distinction (authz.ErrRefreshTokenReused
//     vs. authz.ErrRefreshTokenNotFound/authz.ErrRefreshTokenExpired) rather
//     than a gap this handler couldn't see past.
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	// The refresh token now arrives ONLY as the HttpOnly cookie — never a
	// JSON body field (PROJECT.md B164). A page script cannot read it to put
	// it in a body even if it wanted to; the browser attaches it
	// automatically because this route is under refreshCookiePath.
	cookie, err := r.Cookie(refreshCookieName)
	if err != nil || cookie.Value == "" {
		writeProblem(w, http.StatusUnauthorized, "https://argus.io/errors/invalid-refresh-token", "Refresh failed", "")
		return
	}

	ctx := r.Context()

	// Resolved before rotation, on its own scoped transaction — like
	// handleSSOProviders, there is no prior authenticated session here to
	// inherit scope from. A resolution failure falls back to nil (no idle
	// limit, today's exact behaviour) rather than failing the whole refresh:
	// an outage in settings resolution must not lock every signed-in session
	// out, which would be a far worse failure than briefly not enforcing an
	// idle limit.
	var idleTimeoutMinutes *int
	if settingsTx, txErr := s.db.Pool.Begin(ctx); txErr != nil {
		logger.ErrorContext(ctx, "beginning the settings transaction for a refresh failed", logging.Err(txErr))
	} else {
		func() {
			defer settingsTx.Rollback(ctx) //nolint:errcheck
			tenantID, err := data.SingleOrganisationID(ctx, settingsTx)
			if err != nil {
				logger.ErrorContext(ctx, "resolving the organisation for a refresh's idle-timeout check failed", logging.Err(err))
				return
			}
			if err := data.SetRequestScope(ctx, settingsTx, tenantID, nil); err != nil {
				logger.ErrorContext(ctx, "setting the request scope for a refresh's idle-timeout check failed", logging.Err(err))
				return
			}
			cfg, err := settings.Resolve(ctx, settingsTx)
			if err != nil {
				logger.ErrorContext(ctx, "resolving settings for a refresh's idle-timeout check failed", logging.Err(err))
				return
			}
			idleTimeoutMinutes = cfg.SessionIdleTimeoutMinutes
		}()
	}

	rotation, err := authz.RotateRefreshTokenDetailed(ctx, s.db.Pool, cookie.Value, idleTimeoutMinutes)
	newRefreshToken, userID := rotation.Token, rotation.UserID
	if err != nil {
		// Logged server-side with full detail; the client gets a generic message
		// only — RotateRefreshToken's error can wrap a raw DB error (e.g. on an
		// unexpected query failure), and that detail has no business reaching an
		// unauthenticated caller over the wire.
		logger.WarnContext(ctx, "refresh-token rotation refused", logging.Err(err))

		if errors.Is(err, authz.ErrRefreshTokenReused) {
			// Best-effort, same posture as every other audit write on this
			// path: logged loudly on failure, but never promoted into a 500
			// — the 401 below is correct either way, and the compromised
			// chain has already been revoked by RotateRefreshToken
			// regardless of whether this row lands.
			if auditErr := s.recordRefreshReuseDetected(ctx, userID, clientIP(r)); auditErr != nil {
				logger.ErrorContext(ctx, "recording a refresh-token reuse detection in the audit log failed", logging.ActorID(userID), logging.Err(auditErr))
			}
		}

		// The presented cookie just proved to be invalid, expired, or
		// (worst case) reused/revoked — clear it so the browser stops
		// re-presenting a token the hub has already declared dead, rather
		// than holding onto it for the rest of its 30-day Max-Age.
		clearRefreshCookie(w, r)

		// A distinct RFC 9457 type for the idle case, not
		// invalid-refresh-token — web/src/auth/AuthContext.tsx branches on
		// this to show "signed out for inactivity" rather than a generic
		// session-ended message, the same way it already has to branch on
		// .type rather than status/prose for every other ApiError (PROJECT.md
		// B165's convention). Still a definitive rejection either way: both
		// clear the session rather than retrying.
		if errors.Is(err, authz.ErrRefreshTokenIdle) {
			writeProblem(w, http.StatusUnauthorized, "https://argus.io/errors/session-idle-timeout", "Refresh failed", "")
			return
		}
		writeProblem(w, http.StatusUnauthorized, "https://argus.io/errors/invalid-refresh-token", "Refresh failed", "")
		return
	}

	if rotation.Graced {
		// A just-superseded token exchanged under authz.RefreshReuseGrace —
		// almost always a response the browser never received. Recorded,
		// unlike a routine refresh, because it is the one success on this
		// path that a replayed token could also produce; see
		// recordRefreshGraceExchange.
		s.recordRefreshGraceExchange(ctx, userID, clientIP(r))
	}

	generation, mustChangePassword, err := authz.CurrentSessionState(ctx, s.db.Pool, userID)
	if err != nil {
		logger.ErrorContext(ctx, "looking up the token generation during a refresh failed", logging.ActorID(userID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not issue access token", "")
		return
	}

	accessToken, err := s.signer.IssueAccessToken(userID, generation)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not issue access token", "")
		return
	}

	setRefreshCookie(w, r, newRefreshToken)
	writeJSON(w, http.StatusOK, loginResponse{
		AccessToken: accessToken,
		ExpiresIn:   int(authz.AccessTokenTTL.Seconds()),
		// The account's real state, not a constant: a session restored on
		// page load must still know it has to change its password.
		MustChangePassword: mustChangePassword,
	})
}

// handleLogout is POST /api/v1/auth/logout (PROJECT.md B164).
//
// Deliberately unauthenticated in the requireAuth sense — exactly like
// handleLogin and handleRefresh, there is no verified access token to
// require here: an access token that already expired, or one this tab never
// even held after losing it to a reload race, must still be able to end the
// session its refresh cookie represents. What authorizes this call to revoke
// anything is possessing that cookie, not a bearer token.
//
// This is the actual fix for B164's "signing out clears browser state
// without revoking it": the OLD logout (web/src/auth/AuthContext.tsx's
// clearSession) only ever cleared local state — nothing server-side ever
// heard about it, so a refresh token captured before that click stayed
// valid for the rest of its 30-day life. This revokes the token's WHOLE
// rotation family (authz.RevokeRefreshTokenFamily) — every token ever
// descended from the one this browser started the session with, not just
// whichever one happens to be current — so a captured token, live or
// already-superseded, is refused by the very next handleRefresh call:
// RotateRefreshToken finds revoked_at already set and returns
// ErrRefreshTokenReused, which is a 401 above.
//
// Always reports success to the caller (204) regardless of whether a cookie
// was even presented, or whether it was already unrecognized — logging out
// of a session that is already over is not an error condition a client
// needs to branch on. The one case that DOES fail loudly is an actual
// revocation error (a DB failure): reporting success there would tell the
// caller its captured-token exposure is closed when it might not be, so
// that path returns 500 and leaves the cookie in place rather than papering
// over it.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Detached from the request's cancellation: a sign-out sent by a tab that
	// is closing (or navigating away) hangs up as soon as the request is out,
	// and that must neither leave the session alive nor leave it ended with
	// no audit row.
	ctx := context.WithoutCancel(r.Context())
	if cookie, err := r.Cookie(refreshCookieName); err == nil && cookie.Value != "" {
		userID, revokeErr := authz.RevokeRefreshTokenFamily(ctx, s.db.Pool, cookie.Value)
		switch {
		case revokeErr == nil:
			s.recordLogout(ctx, userID, clientIP(r))
		case errors.Is(revokeErr, authz.ErrRefreshTokenNotFound):
			// Nothing to revoke — an already-expired, already-cleared, or
			// never-valid cookie. Not worth logging: this is the ordinary
			// shape of "log out of a session that's already over."
		default:
			logger.ErrorContext(ctx, "revoking the refresh token family on sign-out failed", logging.Err(revokeErr))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not sign out", "")
			return
		}
	}
	clearRefreshCookie(w, r)
	w.WriteHeader(http.StatusNoContent)
}

// recordLogout writes the audit_events row for a successful sign-out.
// Best-effort, same posture as recordRefreshReuseDetected: logged loudly on
// failure, but never promoted into an error response for a revocation that
// has already succeeded — the client's session is over either way.
func (s *Server) recordLogout(ctx context.Context, userID, sourceIP string) {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "recording a sign-out in the audit log: begin transaction failed", logging.ActorID(userID), logging.Err(err))
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		logger.ErrorContext(ctx, "recording a sign-out in the audit log: resolving the organisation failed", logging.ActorID(userID), logging.Err(err))
		return
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		logger.ErrorContext(ctx, "recording a sign-out in the audit log: set request scope failed", logging.ActorID(userID), logging.Err(err))
		return
	}

	if err := audit.RecordEvent(ctx, tx, audit.Event{
		TenantID: tenantID,
		ActorID:  &userID,
		// What authenticated this request: the refresh cookie, not a bearer
		// token. Without it the row's auth method rendered as "—", which
		// read as a sign-out by nobody in particular.
		ActorAuthMethod: refreshCookieAuthMethod,
		SourceIP:        sourceIP,
		Outcome:         audit.OutcomeSuccess,
		Details:         map[string]any{"action": "logout"},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a sign-out in the audit log: audit write failed", logging.ActorID(userID), logging.Err(err))
		return
	}
	if err := tx.Commit(ctx); err != nil {
		logger.ErrorContext(ctx, "recording a sign-out in the audit log: commit failed", logging.ActorID(userID), logging.Err(err))
	}
}

// recordRefreshReuseDetected writes the audit_events row for a detected
// refresh-token-reuse event — see handleRefresh's doc comment for why this
// is the one case on the refresh path worth a permanent record, and why the
// (now much more common) success case deliberately has no equivalent
// anymore.
//
// Like the enrollment/rotation paths, opens and scopes its own transaction:
// there is no prior authenticated session's transaction to piggyback on
// here (RotateRefreshToken already committed its own, revoking the whole
// compromised chain, before returning ErrRefreshTokenReused to this
// caller). userID comes straight from RotateRefreshToken's return value —
// the row was already scanned before the revoked_at check failed, so no
// second lookup is needed to attribute this event to an actor.
func (s *Server) recordRefreshReuseDetected(ctx context.Context, userID, sourceIP string) error {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return fmt.Errorf("set request scope: %w", err)
	}

	if err := audit.RecordEvent(ctx, tx, audit.Event{
		TenantID:        tenantID,
		ActorID:         &userID,
		ActorAuthMethod: refreshCookieAuthMethod,
		SourceIP:        sourceIP,
		Outcome:         audit.OutcomeDenied,
		Details: map[string]any{
			"event":  "refresh_token.reuse_detected",
			"reason": "presented refresh token had already been rotated (superseded by a later token); treated as a compromise signal and the entire rotation chain has been revoked",
		},
	}); err != nil {
		return fmt.Errorf("record event: %w", err)
	}
	return tx.Commit(ctx)
}

// refreshCookieAuthMethod is the audit actor_auth_method for the requests the
// argus_refresh cookie alone authenticates — sign-out and the refresh path's
// own security events.
const refreshCookieAuthMethod = "refresh_token"

// recordRefreshGraceExchange writes the audit row for a refresh that succeeded
// only under authz.RefreshReuseGrace. Best-effort like recordLogout: the
// exchange has committed, and failing the refresh now would sign out a user
// whose session is fine. Detached from the request's cancellation for the same
// reason recordLogout is.
func (s *Server) recordRefreshGraceExchange(ctx context.Context, userID, sourceIP string) {
	ctx = context.WithoutCancel(ctx)
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "recording a refresh grace exchange: begin transaction failed", logging.ActorID(userID), logging.Err(err))
		return
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		logger.ErrorContext(ctx, "recording a refresh grace exchange: resolving the organisation failed", logging.ActorID(userID), logging.Err(err))
		return
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		logger.ErrorContext(ctx, "recording a refresh grace exchange: set request scope failed", logging.ActorID(userID), logging.Err(err))
		return
	}
	if err := audit.RecordEvent(ctx, tx, audit.Event{
		TenantID:        tenantID,
		ActorID:         &userID,
		ActorAuthMethod: refreshCookieAuthMethod,
		SourceIP:        sourceIP,
		Outcome:         audit.OutcomeSuccess,
		Details: map[string]any{
			"event":  "refresh_token.grace_exchange",
			"reason": "the just-superseded refresh token was presented again before its successor was ever used, within the reuse grace window — the signature of a response the browser never received; exchanged once, and any further presentation of either token is reuse",
		},
	}); err != nil {
		logger.ErrorContext(ctx, "recording a refresh grace exchange: audit write failed", logging.ActorID(userID), logging.Err(err))
		return
	}
	if err := tx.Commit(ctx); err != nil {
		logger.ErrorContext(ctx, "recording a refresh grace exchange: commit failed", logging.ActorID(userID), logging.Err(err))
	}
}

// meResponse is the answer to "who am I", and the ONLY answer any part of
// this product should accept for that question.
//
// Deliberately small. This is not a user-profile resource — it is the
// identity the presented access token actually authenticates as, which is a
// security-relevant fact and is why it is read from the database inside the
// request's own scoped transaction rather than assembled from anything the
// caller sent.
type meResponse struct {
	UserID string `json:"userId"`
	Email  string `json:"email"`
	// AuthMethod is how this account signs in: "password" for a local
	// account, "federated" for one provisioned from an identity provider.
	//
	// Not a profile nicety — it decides whether a control the UI already
	// renders can work at all. A federated account has no password_hash (the
	// users_local_xor_federated CHECK constraint, migration 000103, makes that
	// the schema's own rule rather than a convention), so PUT
	// /users/me/password cannot succeed for one: handleChangePassword reads
	// that column into a string, a NULL fails the scan, and the caller gets a
	// 500 from a menu item that looked available. The client uses this to
	// disable that item with the reason named, rather than hiding it — the
	// disabled-not-hidden discipline lld/11 §6 requires, which also needs a
	// reason to state.
	AuthMethod string `json:"authMethod"`

	// PrimaryColorID / OverviewDefaultWindowDays / MinPasswordLength /
	// SessionIdleTimeoutMinutes are org-wide Appearance/General settings
	// (PROJECT.md, 2026-10-14) every authenticated user needs to render
	// correctly — NOT just an admin holding org:settings:write, which is why
	// they ride on this route rather than GET /api/v1/admin/settings alone.
	// Same reasoning as handleSSOProviders' LoginStyle for the pre-auth case,
	// one authentication step later: AppShell applies PrimaryColorID as soon
	// as identity resolves (web/src/theme.ts's applyAccent), OverviewPage
	// seeds its window toggle from OverviewDefaultWindowDays, and
	// ChangePasswordModal/AuthContext read the other two.
	PrimaryColorID            string `json:"primaryColorId"`
	OverviewDefaultWindowDays int    `json:"overviewDefaultWindowDays"`
	MinPasswordLength         int    `json:"minPasswordLength"`
	// SessionIdleTimeoutMinutes is null when there is no idle limit.
	SessionIdleTimeoutMinutes *int `json:"sessionIdleTimeoutMinutes"`
}

// handleMe is GET /api/v1/users/me (PROJECT.md B165).
//
// # Why this route exists at all
//
// Neither sign-in response carries the caller's identity: handleLogin and
// handleSSOExchange both return loginResponse, which is tokens and nothing
// else. The browser papered over that by remembering the email typed into the
// password form (web/src/auth/AuthContext.tsx, localStorage 'argus.email'),
// which works for exactly one of the two paths — a federated sign-in never
// sees an email, so the header either went blank or, on a shared browser,
// labelled the new session with the PREVIOUS person's address. On a product
// whose audit trail is the selling point, a screen that names the wrong
// account is not a cosmetic defect.
//
// This was chosen over adding an email to handleSSOExchange's response, which
// was the other candidate fix, because that one leaves TWO sources of truth:
// the password path would still be labelled from a string the client typed,
// the federated path from the server's record, and nothing keeps them
// agreeing. One route that both paths read after acquiring a token means the
// displayed identity is always the identity the TOKEN carries. It is also the
// only answer that is right for a session restored from a refresh token on
// page load, where there is no sign-in response to carry anything at all.
//
// A note for anyone reaching for the old `/api/v1/me` incantation: it never
// existed. An unmatched GET under /api/v1/ falls through to the SPA handler
// (static.go's catch-all "GET /") and returns index.html with HTTP 200 — with
// a garbage token, an empty token, or no token — which is why it was
// mistakable for a working auth check. This route is under the real,
// authenticated /api/v1/users/me/... family (alongside
// effective-permissions and password), so it answers 401 to an unauthenticated
// caller like every other requireAuth route. The client half deliberately
// refuses to believe an identity response that isn't JSON carrying an email,
// so a version-skewed hub that 200s HTML at it produces "unknown", never a
// wrong name.
//
// No capability check, for the same reason handleEffectivePermissions and
// handleChangePassword have none: being authenticated as yourself is always
// sufficient to learn who you are.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	var (
		email     string
		federated bool
	)
	// rc.Tx is already RLS-scoped by requireAuth, and rc.UserID comes from the
	// verified token — never from a path or query parameter, per convention 4.
	//
	// Federated-ness is read as `idp_subject IS NOT NULL` rather than by
	// checking for an absent password: that column is half of the
	// users_local_xor_federated CHECK constraint, so it is the same fact the
	// database itself enforces, and it never requires selecting a password
	// hash into this handler to find out.
	if err := rc.Tx.QueryRow(r.Context(),
		`SELECT email, idp_subject IS NOT NULL FROM users WHERE id = $1 AND deleted_at IS NULL`,
		rc.UserID).Scan(&email, &federated); err != nil {
		// requireAuth has already established that this user exists and that
		// the token's generation matches, so failing here is an internal
		// fault, not an authentication problem. Logged in full, generic to the
		// caller (convention 7).
		logger.ErrorContext(r.Context(), "loading the caller's identity failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not load your account", "")
		return
	}
	authMethod := "password"
	if federated {
		authMethod = "federated"
	}

	// Degrades the same way handleSSOProviders' login-style read does, and for
	// the identical reason: a request to learn "who am I" must not fail
	// because an unrelated settings lookup did, and rc.Tx is already the
	// RLS-scoped transaction this handler needs — no second transaction.
	primaryColorID := settings.DefaultPrimaryColorID
	overviewDefaultWindowDays := settings.OverviewDefaultWindowDaysValues[0]
	minPasswordLength := authz.MinPasswordLength
	var sessionIdleTimeoutMinutes *int
	if cfg, err := settings.Resolve(r.Context(), rc.Tx); err != nil {
		logger.ErrorContext(r.Context(), "loading settings for the caller's identity response failed; serving the fallbacks",
			logging.Err(err))
	} else {
		primaryColorID = cfg.PrimaryColorID
		overviewDefaultWindowDays = cfg.OverviewDefaultWindowDays
		minPasswordLength = cfg.MinPasswordLength
		sessionIdleTimeoutMinutes = cfg.SessionIdleTimeoutMinutes
	}

	writeJSON(w, http.StatusOK, meResponse{
		UserID:                    rc.UserID,
		Email:                     email,
		AuthMethod:                authMethod,
		PrimaryColorID:            primaryColorID,
		OverviewDefaultWindowDays: overviewDefaultWindowDays,
		MinPasswordLength:         minPasswordLength,
		SessionIdleTimeoutMinutes: sessionIdleTimeoutMinutes,
	})
}

// handleEffectivePermissions is GET /api/v1/users/me/effective-permissions
// (lld/02-authz-spec.md §6). Never cached beyond this request/response.
func (s *Server) handleEffectivePermissions(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	writeJSON(w, http.StatusOK, map[string]any{
		"userId":     rc.UserID,
		"computedAt": nowRFC3339(),
		"grants":     rc.Grants,
	})
}

type changePasswordRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// handleChangePassword is PUT /api/v1/users/me/password (lld/02-authz-spec.md
// §8). Authenticated as yourself is always sufficient to change your own
// password — no capability check, the same "no special capability needed"
// precedent handleEffectivePermissions already sets for a /users/me/... route.
//
// Verifies currentPassword against the stored hash before accepting a change
// — deliberately true even for a mustChangePassword account whose "current"
// password is the just-issued temporary one from handleCreateUser/
// handleResetPassword (internal/api/users.go): skipping that check there
// would mean anyone who ever saw that temporary password (over a shoulder, in
// a chat message it was pasted into) could set a password of their own
// choosing even after the legitimate owner already changed it once, which
// defeats the whole point of the check.
//
// On success: rotates password_hash, clears must_change_password, and bumps
// token_generation — which immediately invalidates every access token already
// issued for this user, INCLUDING the one that authenticated this very
// request (see accessTokenClaims' doc comment, internal/authz/jwt.go) — and
// revokes every outstanding refresh token (authz.RevokeAllRefreshTokens),
// again including this session's own. A brand new access/refresh token pair
// is then minted and returned in the same response (mirroring loginResponse's
// shape), so the calling browser tab swaps in the new pair and keeps working
// without a full logout/login, while every OTHER outstanding session for this
// user — one that does not receive this response — is left holding tokens
// that now fail both checks.
func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}

	ctx := r.Context()
	var currentHash string
	if err := rc.Tx.QueryRow(ctx, `SELECT password_hash FROM users WHERE id = $1`, rc.UserID).Scan(&currentHash); err != nil {
		logger.ErrorContext(ctx, "looking up the caller's current password hash failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not change password", "")
		return
	}

	valid, err := authz.VerifyPassword(req.CurrentPassword, currentHash)
	if err != nil || !valid {
		if err != nil {
			logger.ErrorContext(ctx, "verifying the caller's current password failed", logging.Err(err))
		}
		writeProblem(w, http.StatusUnauthorized, "https://argus.io/errors/invalid-credentials", "Current password is incorrect", "")
		return
	}

	// The configured floor, not the hardcoded authz.MinPasswordLength constant
	// (migration 000131) — rc.Tx is already RLS-scoped, so settings.Resolve can
	// read it directly with no new transaction. A resolution failure falls
	// back to the constant rather than failing the whole request: an operator
	// mid-change to this one field must not be able to lock out every
	// password change in the tenant.
	minPasswordLength := authz.MinPasswordLength
	if cfg, err := settings.Resolve(ctx, rc.Tx); err != nil {
		logger.ErrorContext(ctx, "resolving settings for the password-strength floor failed; using the fallback",
			slog.Int("min_password_length", minPasswordLength), logging.Err(err))
	} else {
		minPasswordLength = cfg.MinPasswordLength
	}
	if err := authz.ValidatePasswordStrength(req.NewPassword, minPasswordLength); err != nil {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/invalid-request", "New password does not meet requirements", err.Error())
		return
	}

	newHash, err := authz.HashPassword(req.NewPassword)
	if err != nil {
		logger.ErrorContext(ctx, "hashing a new password failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not change password", "")
		return
	}

	var newGeneration int64
	if err := rc.Tx.QueryRow(ctx,
		`UPDATE users SET password_hash = $1, must_change_password = false, token_generation = token_generation + 1
		 WHERE id = $2 RETURNING token_generation`,
		newHash, rc.UserID).Scan(&newGeneration); err != nil {
		logger.ErrorContext(ctx, "storing a changed password failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not change password", "")
		return
	}

	if err := authz.RevokeAllRefreshTokens(ctx, rc.Tx, rc.UserID); err != nil {
		logger.ErrorContext(ctx, "revoking refresh tokens after a password change failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not change password", "")
		return
	}

	newRefreshToken, err := authz.IssueRefreshToken(ctx, rc.Tx, rc.TenantID, rc.UserID)
	if err != nil {
		logger.ErrorContext(ctx, "issuing a refresh token after a password change failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not change password", "")
		return
	}
	newAccessToken, err := s.signer.IssueAccessToken(rc.UserID, newGeneration)
	if err != nil {
		logger.ErrorContext(ctx, "issuing an access token after a password change failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not change password", "")
		return
	}

	if err := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID:        rc.TenantID,
		ActorID:         &rc.UserID,
		ActorAuthMethod: "jwt",
		SourceIP:        clientIP(r),
		Outcome:         audit.OutcomeSuccess,
		Details:         map[string]any{"action": "change_password"}, // never the password itself, old or new
	}); err != nil {
		logger.ErrorContext(ctx, "recording a password change in the audit log failed", logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not record audit event", "")
		return
	}

	setRefreshCookie(w, r, newRefreshToken)
	writeJSON(w, http.StatusOK, loginResponse{
		AccessToken:        newAccessToken,
		ExpiresIn:          int(authz.AccessTokenTTL.Seconds()),
		MustChangePassword: false,
	})
}
