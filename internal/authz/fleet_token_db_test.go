package authz

import (
	"context"
	"strings"
	"testing"
	"time"

	"argus/internal/data"
)

// A fleet token's whole life, inside one transaction that is rolled back:
// many clusters enroll with it, auto-accept is carried and signed, revocation
// stops it, and listing never shows the token itself.
func TestFleetTokenLifecycle(t *testing.T) {
	pool := permTestPool(t)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		t.Fatalf("an organisation is needed (start a hub once against this database): %v", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		t.Fatal(err)
	}

	signer := &EnrollmentSigner{key: []byte("0123456789abcdef0123456789abcdef")}
	token, id, expires, err := signer.IssueFleetToken(ctx, tx, tenantID, "usr_fleet_admin", FleetTokenRequest{Name: "eu-fleet", Days: 30, MaxRedemptions: 3, AutoAccept: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token, id+".") || expires.IsZero() {
		t.Fatalf("token %q id %q", token, id)
	}

	for i := range 3 {
		r, err := signer.Redeem(ctx, tx, token)
		if err != nil {
			t.Fatalf("redemption %d: %v", i+1, err)
		}
		if !r.AutoAccept || r.Issuer != "usr_fleet_admin" || r.TenantID != tenantID || r.TokenID != id {
			t.Fatalf("redemption %+v", r)
		}
	}
	if _, err := signer.Redeem(ctx, tx, token); err == nil {
		t.Fatal("redeemed past its cap")
	}

	// Switching auto-accept on in the database alone breaks the signature.
	plain, plainID, _, err := signer.IssueFleetToken(ctx, tx, tenantID, "usr_fleet_admin", FleetTokenRequest{Name: "manual-accept"})
	if err != nil {
		t.Fatal(err)
	}
	if r, err := signer.Redeem(ctx, tx, plain); err != nil || r.AutoAccept {
		t.Fatalf("plain token: %+v %v", r, err)
	}
	if _, err := tx.Exec(ctx, `UPDATE enrollment_tokens SET auto_accept = true WHERE token_id = $1`, plainID); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Redeem(ctx, tx, plain); err == nil {
		t.Fatal("a tampered auto-accept flag was honoured")
	}

	revoked, err := RevokeFleetToken(ctx, tx, plainID)
	if err != nil || !revoked {
		t.Fatalf("revoke: %v %v", revoked, err)
	}
	if again, _ := RevokeFleetToken(ctx, tx, plainID); again {
		t.Fatal("revoked twice")
	}

	listed, err := ListFleetTokens(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]FleetToken{}
	for _, f := range listed {
		seen[f.ID] = f
	}
	if f := seen[id]; f.Name != "eu-fleet" || f.Redemptions != 3 || f.MaxRedemptions != 3 || !f.AutoAccept || f.RevokedAt != nil {
		t.Errorf("listed %+v", f)
	}
	if f := seen[plainID]; f.RevokedAt == nil || f.MaxRedemptions != FleetTokenDefaultMaxRedemptions {
		t.Errorf("listed %+v", f)
	}
}

func TestValidateFleetToken(t *testing.T) {
	for _, tc := range []struct {
		req FleetTokenRequest
		ok  bool
	}{
		{FleetTokenRequest{Name: "fleet"}, true},
		{FleetTokenRequest{Name: "  "}, false},
		{FleetTokenRequest{Name: "fleet", Days: 366}, false},
		{FleetTokenRequest{Name: "fleet", Days: 365, MaxRedemptions: 10000}, true},
		{FleetTokenRequest{Name: "fleet", MaxRedemptions: 10001}, false},
		{FleetTokenRequest{Name: "fleet", Days: -1}, false},
	} {
		got, err := validateFleetToken(tc.req)
		if (err == nil) != tc.ok {
			t.Errorf("%+v: %v", tc.req, err)
		}
		if err == nil && (got.Days == 0 || got.MaxRedemptions == 0) {
			t.Errorf("%+v: defaults not applied: %+v", tc.req, got)
		}
	}
	// The ordinary path refuses the fleet class: a fleet token is issued
	// only through IssueFleetToken, with its own bounds.
	if _, _, err := validateEnrollmentRequest(TTLClassFleet, 5); err == nil {
		t.Error("the fleet class went through the ordinary path")
	}
}

// The hub chart's local key: registered once as a single-use, auto-accepting
// fleet token issued by the super-admin, redeemable only by presenting the
// exact key, and only by a hub that was given it.
func TestLocalEnrollmentToken(t *testing.T) {
	pool := permTestPool(t)
	ctx := context.Background()
	signer := &EnrollmentSigner{key: []byte("0123456789abcdef0123456789abcdef")}
	if err := signer.SetLocalEnrollmentKey("too-short"); err == nil {
		t.Fatal("a short key was accepted")
	}
	key := "local-test-" + strings.Repeat("k", 20) + NewOpaqueTokenForTest(t)
	if err := signer.SetLocalEnrollmentKey(key); err != nil {
		t.Fatal(err)
	}
	created, err := signer.EnsureLocalEnrollmentToken(ctx, pool)
	if err != nil || !created {
		t.Fatalf("first ensure: created=%v err=%v", created, err)
	}
	t.Cleanup(func() {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return
		}
		tenantID, _ := data.SingleOrganisationID(ctx, tx)
		_ = data.SetRequestScope(ctx, tx, tenantID, nil)
		_, _ = tx.Exec(ctx, `DELETE FROM enrollment_tokens WHERE token_id = $1`, localTokenID(key))
		_ = tx.Commit(ctx)
	})
	if again, err := signer.EnsureLocalEnrollmentToken(ctx, pool); err != nil || again {
		t.Fatalf("second ensure must be a no-op: created=%v err=%v", again, err)
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	stranger := &EnrollmentSigner{key: signer.key}
	if _, err := stranger.Redeem(ctx, tx, key); err == nil {
		t.Fatal("a hub without the local key redeemed it")
	}
	if _, err := signer.Redeem(ctx, tx, key+"x"); err == nil {
		t.Fatal("a different key was accepted")
	}
	r, err := signer.Redeem(ctx, tx, key)
	if err != nil {
		t.Fatal(err)
	}
	if !r.AutoAccept || r.Issuer == "" || r.TokenID != localTokenID(key) {
		t.Fatalf("redemption %+v", r)
	}
	if _, err := signer.Redeem(ctx, tx, key); err == nil {
		t.Fatal("the local key was redeemed twice")
	}

	listed, err := ListFleetTokens(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range listed {
		if f.ID == localTokenID(key) {
			if f.Name != LocalEnrollmentTokenName || f.MaxRedemptions != 1 || !f.AutoAccept {
				t.Fatalf("listed as %+v", f)
			}
			return
		}
	}
	t.Fatal("the local token is not listed under fleet tokens")
}

func NewOpaqueTokenForTest(t *testing.T) string {
	t.Helper()
	return strings.ReplaceAll(t.Name(), "/", "-") + "-" + time.Now().Format("150405.000000000")
}
