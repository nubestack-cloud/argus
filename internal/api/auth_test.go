package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/domain"
)

// TestDummyLoginPasswordHashIsAVerifiableArgon2idHash is the DB-free half of
// the login-timing regression coverage, and it guards a failure mode that is
// completely invisible from the outside: authz.VerifyPassword rejects a
// malformed hash string by RETURNING EARLY, before it does any Argon2id work
// at all (see its parse steps — unrecognized format, bad version, undecodable
// salt). So if dummyLoginPasswordHash ever stopped being a well-formed hash,
// handleLogin's user-not-found path would still "call verify" — and still
// cost nothing, silently restoring the exact enumeration oracle the call was
// added to remove, with every other test still passing.
//
// A false verdict is the expected one here: the hash is over a random,
// discarded plaintext, so nothing can verify successfully against it. What
// matters is that the verdict comes back with no error, i.e. that the full
// key derivation actually ran.
func TestDummyLoginPasswordHashIsAVerifiableArgon2idHash(t *testing.T) {
	if !strings.HasPrefix(dummyLoginPasswordHash, "$argon2id$") {
		t.Fatalf("dummyLoginPasswordHash = %q, want an $argon2id$... encoding", dummyLoginPasswordHash)
	}

	valid, err := authz.VerifyPassword("any-password-at-all", dummyLoginPasswordHash)
	if err != nil {
		t.Fatalf("VerifyPassword against the dummy hash returned err %v — an error means it bailed out during parsing without deriving a key, so the user-not-found path costs nothing and the timing oracle is back", err)
	}
	if valid {
		t.Error("VerifyPassword against the dummy hash returned true; the dummy plaintext is random and discarded, so nothing should ever verify against it")
	}

	// The empty password specifically, because that is the input an attacker
	// would reach for if the dummy verification were skipped as an
	// optimisation for "no password supplied".
	if _, err := authz.VerifyPassword("", dummyLoginPasswordHash); err != nil {
		t.Errorf("VerifyPassword(\"\", dummy) returned err %v, want a clean false — the empty password must cost the same as any other", err)
	}
}

// authTestPool connects to a real Postgres for the handleLogin test below,
// gated on ARGUS_TEST_DATABASE_URL exactly like internal/authz/session_test.go
// (see that file's doc comment for the rationale and the connection string to
// use). handleLogin's very first act is s.db.Pool.Begin, and *pgxpool.Pool is
// a concrete type with no interface to stub, so there is no honest DB-free way
// to drive this handler.
func authTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	connString := os.Getenv("ARGUS_TEST_DATABASE_URL")
	if connString == "" {
		t.Skip("ARGUS_TEST_DATABASE_URL not set; skipping DB-backed handleLogin test")
	}
	pool, err := pgxpool.New(context.Background(), connString)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// authTestUser inserts a throwaway enabled user with a real Argon2id
// password hash and cleans it up afterwards.
func authTestUser(t *testing.T, pool *pgxpool.Pool, password string) (tenantID, userID, email, passwordHash string) {
	t.Helper()
	ctx := context.Background()

	hash, err := authz.HashPassword(password)
	if err != nil {
		t.Fatalf("hash test password: %v", err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin setup transaction: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err = data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}

	userID = domain.NewID(domain.PrefixUser)
	email = userID + "@test.invalid"
	if _, err := tx.Exec(ctx,
		`INSERT INTO users (id, tenant_id, email, display_name, password_hash) VALUES ($1, $2, $3, $4, $5)`,
		userID, tenantID, email, "handleLogin test user", hash); err != nil {
		t.Fatalf("insert test user: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit setup transaction: %v", err)
	}

	t.Cleanup(func() {
		cleanupCtx := context.Background()
		tx, err := pool.Begin(cleanupCtx)
		if err != nil {
			t.Logf("cleanup: begin transaction: %v", err)
			return
		}
		defer tx.Rollback(cleanupCtx) //nolint:errcheck
		if err := data.SetRequestScope(cleanupCtx, tx, tenantID, nil); err != nil {
			t.Logf("cleanup: set request scope: %v", err)
			return
		}
		// replaced_by is self-referencing with no ON DELETE CASCADE from
		// users; clear it before deleting the rows it points at.
		if _, err := tx.Exec(cleanupCtx, `UPDATE refresh_tokens SET replaced_by = NULL WHERE user_id = $1`, userID); err != nil {
			t.Logf("cleanup: clear replaced_by: %v", err)
			return
		}
		if _, err := tx.Exec(cleanupCtx, `DELETE FROM refresh_tokens WHERE user_id = $1`, userID); err != nil {
			t.Logf("cleanup: delete refresh tokens: %v", err)
			return
		}
		if _, err := tx.Exec(cleanupCtx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
			t.Logf("cleanup: delete test user: %v", err)
			return
		}
		if err := tx.Commit(cleanupCtx); err != nil {
			t.Logf("cleanup: commit: %v", err)
		}
	})

	return tenantID, userID, email, hash
}

// TestHandleLoginVerifiesPasswordOnBothPaths is the regression test for the
// login timing oracle: handleLogin used to return from its user-not-found
// branch without ever calling authz.VerifyPassword, so a request naming a
// real account cost a full Argon2id verification (~100ms) while one naming
// an unknown address cost a single indexed SELECT. Same status, same body,
// wildly different latency — which is all an attacker needs to enumerate
// valid email addresses one request at a time, and precisely what the
// comment on that branch claimed it prevented.
//
// The property is a timing equivalence, so the obvious test is to time both
// paths — and that test would be flaky on any shared or loaded CI machine.
// Instead this observes the CAUSE rather than the effect: it swaps the
// verifyPassword seam for a recording wrapper (still delegating to the real
// implementation, so the handler's behaviour is unchanged) and asserts that
// both paths perform exactly one verification, one against the user's stored
// hash and one against dummyLoginPasswordHash. Pair it with
// TestDummyLoginPasswordHashIsAVerifiableArgon2idHash above, which is what
// establishes that the dummy verification is genuinely as expensive as the
// real one rather than an early parse failure.
func TestHandleLoginVerifiesPasswordOnBothPaths(t *testing.T) {
	pool := authTestPool(t)
	const realPassword = "correct-horse-battery-staple"
	_, _, email, passwordHash := authTestUser(t, pool, realPassword)

	signer, err := authz.NewEphemeralTokenSigner()
	if err != nil {
		t.Fatalf("token signer: %v", err)
	}
	s := &Server{db: &data.DB{Pool: pool}, signer: signer, loginRateLimit: authz.NewLoginRateLimiter()}

	type call struct{ password, hash string }
	var calls []call
	original := verifyPassword
	t.Cleanup(func() { verifyPassword = original })
	verifyPassword = func(password, hash string) (bool, error) {
		calls = append(calls, call{password, hash})
		return original(password, hash)
	}

	login := func(t *testing.T, email, password string) (int, string, []call) {
		t.Helper()
		calls = nil
		body, err := json.Marshal(loginRequest{Email: email, Password: password})
		if err != nil {
			t.Fatalf("marshal login request: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		s.handleLogin(rec, req)
		return rec.Code, rec.Body.String(), calls
	}

	// Path 1: the account exists, the password is wrong.
	wrongPasswordStatus, wrongPasswordBody, wrongPasswordCalls := login(t, email, "not-the-right-password")
	if wrongPasswordStatus != http.StatusUnauthorized {
		t.Fatalf("existing user with a wrong password: got status %d, want 401", wrongPasswordStatus)
	}
	if len(wrongPasswordCalls) != 1 {
		t.Fatalf("existing user with a wrong password: got %d password verifications, want exactly 1", len(wrongPasswordCalls))
	}
	if wrongPasswordCalls[0].hash != passwordHash {
		t.Errorf("existing user with a wrong password: verified against %q, want the user's stored hash", wrongPasswordCalls[0].hash)
	}

	// Path 2: no such account. This is the one that used to short-circuit.
	unknownStatus, unknownBody, unknownCalls := login(t, "definitely-not-a-user@test.invalid", "not-the-right-password")
	if unknownStatus != http.StatusUnauthorized {
		t.Fatalf("unknown user: got status %d, want 401", unknownStatus)
	}
	if len(unknownCalls) != 1 {
		t.Fatalf("unknown user: got %d password verifications, want exactly 1 — returning without hashing anything makes this path orders of magnitude faster than an existing user's and turns login into an email-enumeration oracle", len(unknownCalls))
	}
	if unknownCalls[0].hash != dummyLoginPasswordHash {
		t.Errorf("unknown user: verified against %q, want dummyLoginPasswordHash", unknownCalls[0].hash)
	}
	if unknownCalls[0].password != "not-the-right-password" {
		t.Errorf("unknown user: verified password %q, want the password actually submitted (verifying a constant instead would let a caller-controlled length still shift the cost)", unknownCalls[0].password)
	}

	// The empty password must not be treated as a special case worth
	// skipping the dummy verification for — that would just relocate the
	// oracle to a different input.
	_, emptyPasswordBody, emptyPasswordCalls := login(t, "definitely-not-a-user@test.invalid", "")
	if len(emptyPasswordCalls) != 1 {
		t.Errorf("unknown user with an empty password: got %d password verifications, want exactly 1", len(emptyPasswordCalls))
	}

	// And the thing the timing difference undermined in the first place:
	// the responses themselves must stay indistinguishable.
	if wrongPasswordBody != unknownBody || unknownBody != emptyPasswordBody {
		t.Errorf("response bodies differ between failure paths:\n existing user, wrong password: %s\n unknown user:                  %s\n unknown user, empty password:  %s",
			wrongPasswordBody, unknownBody, emptyPasswordBody)
	}

	// Sanity check that the seam has not been wired in a way that breaks the
	// success path — a "both paths verify" assertion is worthless if no
	// password can ever verify successfully.
	okStatus, _, okCalls := login(t, email, realPassword)
	if okStatus != http.StatusOK {
		t.Fatalf("existing user with the correct password: got status %d, want 200", okStatus)
	}
	if len(okCalls) != 1 || okCalls[0].hash != passwordHash {
		t.Errorf("existing user with the correct password: got calls %+v, want exactly one against the stored hash", okCalls)
	}
}

// TestHandleLoginSetsHTTPOnlyRefreshCookie is half of PROJECT.md B164's
// acceptance test: "a refresh token is not readable by page scripts." That
// is an HTTP attribute a browser enforces, not something a response body
// can demonstrate — so this asserts on the actual Set-Cookie header
// handleLogin sends, and also confirms the OLD contract (a refreshToken
// field in the JSON body, which is how the token used to end up in
// localStorage) is genuinely gone rather than merely unused.
func TestHandleLoginSetsHTTPOnlyRefreshCookie(t *testing.T) {
	pool := authTestPool(t)
	const password = "correct-horse-battery-staple"
	_, _, email, _ := authTestUser(t, pool, password)

	signer, err := authz.NewEphemeralTokenSigner()
	if err != nil {
		t.Fatalf("token signer: %v", err)
	}
	s := &Server{db: &data.DB{Pool: pool}, signer: signer, loginRateLimit: authz.NewLoginRateLimiter()}

	body, err := json.Marshal(loginRequest{Email: email, Password: password})
	if err != nil {
		t.Fatalf("marshal login request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	s.handleLogin(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("login: got status %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}

	var res loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("unmarshal login response: %v", err)
	}
	if res.AccessToken == "" {
		t.Error("login response carried no accessToken")
	}
	// The old field must actually be gone from the wire, not just from the
	// Go struct: a body that still happened to carry the string "refreshToken"
	// (say, echoed from an unrelated field) would be exactly the kind of thing
	// a careless revert could reintroduce without any type error catching it.
	if strings.Contains(rec.Body.String(), "refreshToken") {
		t.Errorf("login response body still mentions refreshToken; the refresh token must travel ONLY as the cookie: %s", rec.Body.String())
	}

	var refreshCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == refreshCookieName {
			refreshCookie = c
		}
	}
	if refreshCookie == nil {
		t.Fatalf("login response set no %q cookie", refreshCookieName)
	}
	if refreshCookie.Value == "" {
		t.Error("refresh cookie carries no value")
	}
	if !refreshCookie.HttpOnly {
		t.Error("refresh cookie is not HttpOnly — a page script could read it, which is exactly what B164 exists to prevent")
	}
	if refreshCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("refresh cookie SameSite = %v, want Lax — Strict would not be sent on the OIDC callback's cross-site redirect (auth_oidc.go)", refreshCookie.SameSite)
	}
	if refreshCookie.Secure {
		t.Error("refresh cookie is Secure on a request with no TLS and no X-Forwarded-Proto: this deployment is reached over plain LAN HTTP, and a Secure cookie there is silently never sent back by the browser")
	}
	if refreshCookie.Path != refreshCookiePath {
		t.Errorf("refresh cookie Path = %q, want %q", refreshCookie.Path, refreshCookiePath)
	}
}

// TestLogoutRevokesRefreshTokenFamilySoACapturedTokenIsRefused is the other
// half of PROJECT.md B164's acceptance test: "a captured token is refused
// after logout." The HttpOnly test above only proves a page SCRIPT can't
// read the cookie; it says nothing about a token that already got out by
// some other route (network capture, a pre-fix localStorage dump, a
// browser extension) — which is exactly the threat this half proves is
// actually closed, by driving the real revocation path end to end rather
// than asserting on an attribute.
func TestLogoutRevokesRefreshTokenFamilySoACapturedTokenIsRefused(t *testing.T) {
	pool := authTestPool(t)
	const password = "correct-horse-battery-staple"
	_, _, email, _ := authTestUser(t, pool, password)

	signer, err := authz.NewEphemeralTokenSigner()
	if err != nil {
		t.Fatalf("token signer: %v", err)
	}
	s := &Server{db: &data.DB{Pool: pool}, signer: signer, loginRateLimit: authz.NewLoginRateLimiter()}

	// Sign in, and capture the refresh cookie the way an attacker who read it
	// off the wire (or out of the old localStorage-backed client) would have
	// — off the Set-Cookie header itself, with no privileged access this fix
	// doesn't already assume away.
	loginBody, err := json.Marshal(loginRequest{Email: email, Password: password})
	if err != nil {
		t.Fatalf("marshal login request: %v", err)
	}
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	loginRec := httptest.NewRecorder()
	s.handleLogin(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login: got status %d, want 200 (body %s)", loginRec.Code, loginRec.Body.String())
	}
	var capturedRefreshToken string
	for _, c := range loginRec.Result().Cookies() {
		if c.Name == refreshCookieName {
			capturedRefreshToken = c.Value
		}
	}
	if capturedRefreshToken == "" {
		t.Fatalf("login response set no %q cookie to capture", refreshCookieName)
	}

	// Prove the captured token is genuinely live BEFORE logout — a refusal
	// after logout means nothing otherwise.
	preLogoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	preLogoutReq.AddCookie(&http.Cookie{Name: refreshCookieName, Value: capturedRefreshToken})
	preLogoutRec := httptest.NewRecorder()
	s.handleRefresh(preLogoutRec, preLogoutReq)
	if preLogoutRec.Code != http.StatusOK {
		t.Fatalf("refresh before logout: got status %d, want 200 (body %s) — the token must be valid before logout for the refusal below to prove anything",
			preLogoutRec.Code, preLogoutRec.Body.String())
	}
	// That call just rotated the family — RotateRefreshToken always rotates
	// on success — so capturedRefreshToken is now a superseded link in the
	// chain rather than the live token, and the browser's cookie jar holds
	// whatever this response's Set-Cookie says instead. Deliberately kept
	// this way rather than reset: it makes the assertion below prove FAMILY
	// revocation (every link, live or superseded) rather than only "the one
	// token that happened to be current."
	var currentRefreshToken string
	for _, c := range preLogoutRec.Result().Cookies() {
		if c.Name == refreshCookieName {
			currentRefreshToken = c.Value
		}
	}
	if currentRefreshToken == "" {
		t.Fatalf("refresh response set no rotated %q cookie", refreshCookieName)
	}

	// Sign out, presenting the current token — exactly what a real browser's
	// cookie jar would attach.
	logoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	logoutReq.AddCookie(&http.Cookie{Name: refreshCookieName, Value: currentRefreshToken})
	logoutRec := httptest.NewRecorder()
	s.handleLogout(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusNoContent {
		t.Fatalf("logout: got status %d, want 204 (body %s)", logoutRec.Code, logoutRec.Body.String())
	}

	// The actual proof: replay the token CAPTURED BEFORE LOGOUT (already
	// superseded by the rotation above, and now also covered by logout's
	// family-wide revocation) and confirm the hub refuses it.
	replayCapturedReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	replayCapturedReq.AddCookie(&http.Cookie{Name: refreshCookieName, Value: capturedRefreshToken})
	replayCapturedRec := httptest.NewRecorder()
	s.handleRefresh(replayCapturedRec, replayCapturedReq)
	if replayCapturedRec.Code != http.StatusUnauthorized {
		t.Fatalf("replaying the token captured before logout: got status %d, want 401 — a captured refresh token must be refused after logout (PROJECT.md B164)",
			replayCapturedRec.Code)
	}

	// And the CURRENT token — the one actually presented to log out with —
	// must be refused too. Checking this is what distinguishes FAMILY
	// revocation from single-token revocation: a fix that only revoked the
	// exact token logout happened to receive would still leave THIS one
	// looking like "the token that was already spent," and would still pass
	// the assertion above.
	replayCurrentReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	replayCurrentReq.AddCookie(&http.Cookie{Name: refreshCookieName, Value: currentRefreshToken})
	replayCurrentRec := httptest.NewRecorder()
	s.handleRefresh(replayCurrentRec, replayCurrentReq)
	if replayCurrentRec.Code != http.StatusUnauthorized {
		t.Fatalf("replaying the token presented to logout itself: got status %d, want 401", replayCurrentRec.Code)
	}
}
