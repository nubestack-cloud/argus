package api

// Session and account-lifecycle behaviour found by live QA on 2026-10-11,
// against a real RLS-forced Postgres: a restored session reports the real
// must-change-password state, sign-out and the refresh path's security events
// name how the actor authenticated, a refresh whose response was lost is
// exchanged once (and audited) instead of signing the user out as a
// compromise, and disabling or removing a user revokes their personal AI tool
// tokens in the same transaction — which re-enabling does not undo.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"argus/internal/authz"
	"argus/internal/data"
)

func sessionTestServer(t *testing.T) (*Server, string, string, string) {
	t.Helper()
	pool := authTestPool(t)
	const password = "session-lifecycle-correct-horse"
	_, userID, email, _ := authTestUser(t, pool, password)
	signer, err := authz.NewEphemeralTokenSigner()
	if err != nil {
		t.Fatalf("token signer: %v", err)
	}
	s := &Server{db: &data.DB{Pool: pool}, signer: signer, loginRateLimit: authz.NewLoginRateLimiter()}
	return s, userID, email, password
}

func refreshCookieFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == refreshCookieName && c.Value != "" {
			return c.Value
		}
	}
	t.Fatalf("response set no %q cookie", refreshCookieName)
	return ""
}

func doLogin(t *testing.T, s *Server, email, password string) (*httptest.ResponseRecorder, loginResponse) {
	t.Helper()
	body, _ := json.Marshal(loginRequest{Email: email, Password: password})
	rec := httptest.NewRecorder()
	s.handleLogin(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	var out loginResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func doRefresh(s *Server, cookie string) (*httptest.ResponseRecorder, loginResponse) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", nil)
	req.AddCookie(&http.Cookie{Name: refreshCookieName, Value: cookie})
	rec := httptest.NewRecorder()
	s.handleRefresh(rec, req)
	var out loginResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec, out
}

func TestRefreshReportsTheAccountsRealMustChangePassword(t *testing.T) {
	s, userID, email, password := sessionTestServer(t)
	execAs(t, s, `UPDATE users SET must_change_password = true WHERE id = $1`, userID)

	loginRec, login := doLogin(t, s, email, password)
	if !login.MustChangePassword {
		t.Fatal("login: mustChangePassword = false, want true")
	}
	rec, refreshed := doRefresh(s, refreshCookieFrom(t, loginRec))
	if rec.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", rec.Code, rec.Body.String())
	}
	if !refreshed.MustChangePassword {
		t.Fatal("refresh: mustChangePassword = false while the account still must change it — the prompt would vanish on reload")
	}

	execAs(t, s, `UPDATE users SET must_change_password = false WHERE id = $1`, userID)
	rec, refreshed = doRefresh(s, refreshCookieFrom(t, rec))
	if rec.Code != http.StatusOK || refreshed.MustChangePassword {
		t.Fatalf("refresh after the change: %d mustChangePassword=%v, want 200/false", rec.Code, refreshed.MustChangePassword)
	}
}

func TestLostRefreshResponseIsExchangedOnceAndAudited(t *testing.T) {
	s, userID, email, password := sessionTestServer(t)
	loginRec, _ := doLogin(t, s, email, password)
	held := refreshCookieFrom(t, loginRec)

	// The hub rotates; the response never reaches the browser.
	if rec, _ := doRefresh(s, held); rec.Code != http.StatusOK {
		t.Fatalf("first refresh: %d", rec.Code)
	}
	// The browser's next refresh presents the token it still holds.
	rec, _ := doRefresh(s, held)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-presenting the just-superseded token: %d, want 200 (grace exchange)", rec.Code)
	}
	if method, outcome, ok := auditFor(t, s, userID, "event", "refresh_token.grace_exchange"); !ok || method != refreshCookieAuthMethod || outcome != "success" {
		t.Fatalf("grace exchange audit row: ok=%v method=%q outcome=%q", ok, method, outcome)
	}
	// A third presentation is reuse: 401, cookie cleared, audited as such.
	rec, _ = doRefresh(s, held)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("third presentation: %d, want 401", rec.Code)
	}
	if method, outcome, ok := auditFor(t, s, userID, "event", "refresh_token.reuse_detected"); !ok || method != refreshCookieAuthMethod || outcome != "denied" {
		t.Fatalf("reuse audit row: ok=%v method=%q outcome=%q", ok, method, outcome)
	}
}

func TestLogoutAuditNamesTheActorAndHowTheyAuthenticated(t *testing.T) {
	s, userID, email, password := sessionTestServer(t)
	loginRec, _ := doLogin(t, s, email, password)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", nil)
	req.AddCookie(&http.Cookie{Name: refreshCookieName, Value: refreshCookieFrom(t, loginRec)})
	// A client that hangs up the moment it has sent the request must still
	// leave an audit row: the revocation commits regardless.
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	rec := httptest.NewRecorder()
	s.handleLogout(rec, req.WithContext(ctx))
	if method, outcome, ok := auditFor(t, s, userID, "action", "logout"); !ok || method != refreshCookieAuthMethod || outcome != "success" {
		t.Fatalf("logout audit row: ok=%v method=%q outcome=%q (status %d)", ok, method, outcome, rec.Code)
	}
}

func execAs(t *testing.T, s *Server, sql string, args ...any) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("scope: %v", err)
	}
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

func auditFor(t *testing.T, s *Server, userID, key, value string) (method, outcome string, ok bool) {
	t.Helper()
	ctx := context.Background()
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("org: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("scope: %v", err)
	}
	err = tx.QueryRow(ctx,
		`SELECT coalesce(actor_auth_method, ''), outcome FROM audit_events
		  WHERE actor_id = $1 AND details->>$2 = $3 ORDER BY occurred_at DESC, id DESC LIMIT 1`,
		userID, key, value).Scan(&method, &outcome)
	return method, outcome, err == nil
}

// Disabling or removing a user revokes their personal AI tool tokens in the
// same transaction, says how many in the audit row, and re-enabling leaves
// them revoked.
func TestDisableAndRemoveRevokePersonalTokens(t *testing.T) {
	f := newMCPFixture(t)
	ctx := context.Background()
	admin := f.user(t, allClusters, authz.CapUserManage, authz.CapUserRemove, authz.CapUserRead)
	holder := f.user(t, allClusters, authz.CapMCPUse, authz.CapClusterRead)
	other := f.user(t, allClusters, authz.CapMCPUse, authz.CapClusterRead)

	live := insertTokenForTest(t, f, holder, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	live2 := insertTokenForTest(t, f, holder, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	bystander := insertTokenForTest(t, f, other, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	if rec := f.rest(t, http.MethodPost, "/api/v1/users/"+holder+"/disable", f.jwt(t, admin), nil); rec.Code != http.StatusOK {
		t.Fatalf("disable: %d %s", rec.Code, rec.Body.String())
	}
	for _, tok := range []string{live, live2} {
		id, _, _ := parsePersonalToken(tok)
		if !tokenRevoked(t, f, id) {
			t.Errorf("token %s: revoked_at still NULL after its owner was disabled", id)
		}
	}
	if row := f.lastAudit(t, admin, "disable_user"); row.details["personalTokensRevoked"] != float64(2) {
		t.Errorf("disable audit personalTokensRevoked = %v, want 2", row.details["personalTokensRevoked"])
	}

	if rec := f.rest(t, http.MethodPost, "/api/v1/users/"+holder+"/enable", f.jwt(t, admin), nil); rec.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body.String())
	}
	if _, err := f.s.lookupPersonalToken(ctx, live); err != errPersonalTokenInvalid {
		t.Errorf("a token revoked by disable works again after re-enable: err = %v", err)
	}

	if _, err := f.s.lookupPersonalToken(ctx, bystander); err != nil {
		t.Fatalf("another user's token was affected: %v", err)
	}
	if rec := f.rest(t, http.MethodDelete, "/api/v1/users/"+other, f.jwt(t, admin), nil); rec.Code != http.StatusOK {
		t.Fatalf("remove: %d %s", rec.Code, rec.Body.String())
	}
	id, _, _ := parsePersonalToken(bystander)
	if !tokenRevoked(t, f, id) {
		t.Error("removed user's token: revoked_at still NULL")
	}
	if row := f.lastAudit(t, admin, "remove_user"); row.details["personalTokensRevoked"] != float64(1) {
		t.Errorf("remove audit personalTokensRevoked = %v, want 1", row.details["personalTokensRevoked"])
	}
}

func tokenRevoked(t *testing.T, f *mcpFixture, id string) bool {
	t.Helper()
	ctx := context.Background()
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, f.tenantID, nil); err != nil {
		t.Fatalf("scope: %v", err)
	}
	var revoked bool
	if err := tx.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM mcp_personal_tokens WHERE id = $1`, id).Scan(&revoked); err != nil {
		t.Fatalf("read token %s: %v", id, err)
	}
	return revoked
}
