package api

// PROJECT.md B165: GET /api/v1/users/me, the one source of truth for "who am
// I" on every sign-in path.
//
// Driven through s.requireAuth rather than by calling handleMe directly,
// because half of what is under test lives in the middleware: that the
// identity comes from the token's verified subject and from nowhere else, and
// that an unauthenticated caller gets 401 instead of something that looks
// like success. The second half is the reason this test exists at all — the
// habit of checking a token against "/api/v1/me" and reading 200 as proof
// (that path was never a route; an unmatched GET under /api/v1/ falls through
// to the SPA handler and returns index.html with 200, token or no token).
// Every positive assertion below is therefore paired with its negative
// control.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/domain"
)

func TestHandleMeNamesTheTokenHolderAndRefusesEveryoneElse(t *testing.T) {
	pool := authTestPool(t)

	// Two accounts, because the defect this route fixes is specifically about
	// two identities meeting in one browser: a federated sign-in that
	// inherited whichever email the PREVIOUS person left in localStorage.
	// Server-side, the property that makes the browser fix possible is that
	// each token names its own holder and nothing else.
	_, aliceID, aliceEmail, _ := authTestUser(t, pool, "alice-password-correct-horse")
	_, bobID, bobEmail, _ := authTestUser(t, pool, "bob-password-correct-horse")

	signer, err := authz.NewEphemeralTokenSigner()
	if err != nil {
		t.Fatalf("token signer: %v", err)
	}
	s := &Server{db: &data.DB{Pool: pool}, signer: signer}
	handler := s.requireAuth(s.handleMe)

	get := func(t *testing.T, token string) (int, meResponse) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		handler(rec, req)
		var body meResponse
		if rec.Code == http.StatusOK {
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode /users/me response %q: %v", rec.Body.String(), err)
			}
		}
		return rec.Code, body
	}

	tokenFor := func(t *testing.T, userID string) string {
		t.Helper()
		token, err := signer.IssueAccessToken(userID, currentGenerationForTest(t, pool, userID))
		if err != nil {
			t.Fatalf("issue access token for %s: %v", userID, err)
		}
		return token
	}

	// Each token names its own holder — not the other one, and not whoever
	// happened to authenticate most recently.
	for _, want := range []struct {
		name   string
		userID string
		email  string
	}{
		{"alice", aliceID, aliceEmail},
		{"bob", bobID, bobEmail},
	} {
		status, body := get(t, tokenFor(t, want.userID))
		if status != http.StatusOK {
			t.Fatalf("%s: GET /users/me returned %d, want 200", want.name, status)
		}
		if body.Email != want.email {
			t.Errorf("%s: /users/me reported email %q, want %q — the header would name the wrong account", want.name, body.Email, want.email)
		}
		if body.UserID != want.userID {
			t.Errorf("%s: /users/me reported userId %q, want %q", want.name, body.UserID, want.userID)
		}
		// Both fixtures are local password accounts (authTestUser inserts a
		// password_hash), so both must report "password". This field gates a
		// real control in the UI — the account menu disables changing a
		// password for a federated account, because there is none to change —
		// so getting it backwards would either hide a working flow or offer
		// one that answers 500.
		if body.AuthMethod != "password" {
			t.Errorf("%s: /users/me reported authMethod %q, want \"password\" for a local account", want.name, body.AuthMethod)
		}
	}

	// A federated account: no password_hash at all (the
	// users_local_xor_federated CHECK constraint), which is exactly why the
	// password control must not be offered for one.
	_, federatedID, federatedEmail := federatedTestUser(t, pool)
	status, body := get(t, tokenFor(t, federatedID))
	if status != http.StatusOK {
		t.Fatalf("federated user: GET /users/me returned %d, want 200", status)
	}
	if body.Email != federatedEmail {
		t.Errorf("federated user: /users/me reported email %q, want %q", body.Email, federatedEmail)
	}
	if body.AuthMethod != "federated" {
		t.Errorf("federated user: /users/me reported authMethod %q, want \"federated\"", body.AuthMethod)
	}

	// The negative controls. Without these the assertions above prove only
	// that some 200 came back, which is exactly the mistake that made
	// "/api/v1/me returns 200" look like a working auth check.
	for _, refused := range []struct {
		name  string
		token string
	}{
		{"no Authorization header at all", ""},
		{"a garbage token", "not-a-jwt"},
		{"an empty bearer token", " "},
	} {
		if status, body := get(t, refused.token); status != http.StatusUnauthorized {
			t.Errorf("%s: GET /users/me returned %d (%+v), want 401", refused.name, status, body)
		}
	}

	// A token signed by a DIFFERENT hub must not be accepted either — the
	// route's answer has to be bound to this signer's key, not merely to a
	// well-formed token carrying a real user id.
	other, err := authz.NewEphemeralTokenSigner()
	if err != nil {
		t.Fatalf("second token signer: %v", err)
	}
	foreign, err := other.IssueAccessToken(aliceID, currentGenerationForTest(t, pool, aliceID))
	if err != nil {
		t.Fatalf("issue foreign access token: %v", err)
	}
	if status, body := get(t, foreign); status != http.StatusUnauthorized {
		t.Errorf("a token signed by another hub returned %d (%+v), want 401", status, body)
	}
}

// currentGenerationForTest reads users.token_generation, which requireAuth
// checks the token's claim against. Read rather than assumed to be zero: a
// test user that has been through a password change would have a bumped
// generation, and a hardcoded 0 would then fail for a reason that has nothing
// to do with what is under test.
func currentGenerationForTest(t *testing.T, pool *pgxpool.Pool, userID string) int64 {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin generation read: %v", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("resolve organisation: %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatalf("set request scope: %v", err)
	}
	var generation int64
	if err := tx.QueryRow(ctx, `SELECT token_generation FROM users WHERE id = $1`, userID).Scan(&generation); err != nil {
		t.Fatalf("read token generation for %s: %v", userID, err)
	}
	return generation
}

// federatedTestUser inserts a throwaway user provisioned the way
// provisionFederatedUser (auth_oidc.go) does: an idp_issuer/idp_subject pair
// and NO password hash. authTestUser cannot be reused for this — the
// users_local_xor_federated CHECK constraint refuses a row that has both.
func federatedTestUser(t *testing.T, pool *pgxpool.Pool) (tenantID, userID, email string) {
	t.Helper()
	ctx := context.Background()

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
	email = userID + "@federated.invalid"
	if _, err := tx.Exec(ctx,
		`INSERT INTO users (id, tenant_id, email, display_name, idp_issuer, idp_subject)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		userID, tenantID, email, "handleMe federated test user",
		"https://idp.test.invalid", userID); err != nil {
		t.Fatalf("insert federated test user: %v", err)
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
		if _, err := tx.Exec(cleanupCtx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
			t.Logf("cleanup: delete federated test user: %v", err)
			return
		}
		if err := tx.Commit(cleanupCtx); err != nil {
			t.Logf("cleanup: commit: %v", err)
		}
	})

	return tenantID, userID, email
}
