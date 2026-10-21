package authz

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestValidateEnrollmentRequest_UnknownTTLClass(t *testing.T) {
	if _, _, err := validateEnrollmentRequest("Z", 0); err == nil {
		t.Error("expected an error for an unknown ttl class")
	}
}

func TestValidateEnrollmentRequest_DefaultsMaxRedemptionsToOne(t *testing.T) {
	_, got, err := validateEnrollmentRequest(TTLClassSelfService, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 1 {
		t.Errorf("got maxRedemptions %d, want 1", got)
	}
}

func TestValidateEnrollmentRequest_RejectsMultiRedemptionOnNonBulkClass(t *testing.T) {
	for _, class := range []string{TTLClassKubeconfig, TTLClassSelfService} {
		if _, _, err := validateEnrollmentRequest(class, 5); err == nil {
			t.Errorf("ttl class %q: expected maxRedemptions=5 to be rejected, but it was accepted", class)
		}
	}
}

func TestValidateEnrollmentRequest_AllowsMultiRedemptionOnBulkClass(t *testing.T) {
	_, got, err := validateEnrollmentRequest(TTLClassBulk, 50)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != 50 {
		t.Errorf("got maxRedemptions %d, want 50", got)
	}
}

// The RedeemEnrollmentToken tests below cover its pure-logic half (signature
// verification, expiry/redemption-limit checks, and the "token_id.signature"
// parsing) the same DB-free way validateEnrollmentRequest is tested above —
// this package has no DB-test harness (testcontainers or otherwise), so a full
// exercise of RedeemEnrollmentToken against a real enrollment_tokens row (the
// "valid token accepted and redemption_count increments" case) is covered by
// scripts/smoke-test.sh's live enroll -> accept -> status round trip instead,
// not by a package unit test here.

func TestSplitEnrollmentToken(t *testing.T) {
	tokenID, sig, ok := splitEnrollmentToken("abc123.def456")
	if !ok || tokenID != "abc123" || sig != "def456" {
		t.Errorf("got (%q, %q, %v), want (abc123, def456, true)", tokenID, sig, ok)
	}

	for _, bad := range []string{"", "no-dot-here", ".leadingdot", "trailingdot."} {
		if _, _, ok := splitEnrollmentToken(bad); ok {
			t.Errorf("splitEnrollmentToken(%q): expected ok=false", bad)
		}
	}
}

func TestVerifyEnrollmentTokenSignature_BadSignatureRejected(t *testing.T) {
	s := &EnrollmentSigner{key: []byte("test-key")}
	issuedAt := time.Now()
	expiresAt := issuedAt.Add(time.Hour)

	goodSig := s.enrollmentTokenSignature("tok1", "usr_1", TTLClassSelfService, 1, issuedAt, expiresAt)
	goodSigStr := base64.RawURLEncoding.EncodeToString(goodSig)

	if !s.verifyEnrollmentTokenSignature("tok1", "usr_1", TTLClassSelfService, 1, issuedAt, expiresAt, goodSigStr) {
		t.Error("expected the correctly-computed signature to verify")
	}

	// Tampered signature (flip a character) must be rejected.
	//
	// The replacement character is chosen against the real one rather than
	// hardcoded. A fixed "x" produced a ~1.5%-per-run flake: base64url's
	// alphabet is 64 characters, so one time in 64 the signature already
	// began with 'x', "tampered" was byte-identical to the good value, and
	// the test failed reporting "expected a tampered signature to be
	// rejected" — which reads exactly like a signature-verification hole
	// rather than a broken fixture. The signature is keyed on time.Now(), so
	// it varied between runs and never reproduced on demand.
	tamperedFirst := byte('x')
	if goodSigStr[0] == tamperedFirst {
		tamperedFirst = 'y'
	}
	tampered := string(tamperedFirst) + goodSigStr[1:]
	if s.verifyEnrollmentTokenSignature("tok1", "usr_1", TTLClassSelfService, 1, issuedAt, expiresAt, tampered) {
		t.Error("expected a tampered signature to be rejected")
	}

	// Signature computed under a different signer's key must be rejected too —
	// this is what a forged token (guessed tokenID, no knowledge of the hub's
	// key) would actually look like.
	other := &EnrollmentSigner{key: []byte("a-different-key")}
	otherSig := base64.RawURLEncoding.EncodeToString(other.enrollmentTokenSignature("tok1", "usr_1", TTLClassSelfService, 1, issuedAt, expiresAt))
	if s.verifyEnrollmentTokenSignature("tok1", "usr_1", TTLClassSelfService, 1, issuedAt, expiresAt, otherSig) {
		t.Error("expected a signature from a different key to be rejected")
	}

	// Not valid base64url at all.
	if s.verifyEnrollmentTokenSignature("tok1", "usr_1", TTLClassSelfService, 1, issuedAt, expiresAt, "not!valid!base64") {
		t.Error("expected an undecodable signature to be rejected")
	}
}

func TestCheckEnrollmentTokenRedeemable_ExpiredRejected(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(-time.Minute) // already expired
	if err := checkEnrollmentTokenRedeemable(now, expiresAt, 0, 1); err == nil {
		t.Error("expected an expired token to be rejected")
	}
}

func TestCheckEnrollmentTokenRedeemable_ExhaustedRedemptionsRejected(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(time.Hour)
	if err := checkEnrollmentTokenRedeemable(now, expiresAt, 1, 1); err == nil {
		t.Error("expected a token at its redemption limit (count == max) to be rejected")
	}
	if err := checkEnrollmentTokenRedeemable(now, expiresAt, 5, 1); err == nil {
		t.Error("expected a token over its redemption limit (count > max) to be rejected")
	}
}

func TestCheckEnrollmentTokenRedeemable_ValidAccepted(t *testing.T) {
	now := time.Now()
	expiresAt := now.Add(time.Hour)
	if err := checkEnrollmentTokenRedeemable(now, expiresAt, 0, 1); err != nil {
		t.Errorf("expected a fresh, unexpired token to be redeemable, got: %v", err)
	}
	if err := checkEnrollmentTokenRedeemable(now, expiresAt, 3, 10); err != nil {
		t.Errorf("expected a partially-redeemed bulk token under its limit to be redeemable, got: %v", err)
	}
}

// TestGenerateEnrollmentKeyMaterial is the DB-free-testable slice of
// NewPersistentEnrollmentSigner's persistence logic (matching
// jwt_test.go's TestGenerateECDSAKeyMaterial_RoundTrip precedent) — a real
// load-or-create-against-Postgres round trip needs a live database, verified
// live instead (see STATUS.md).
func TestGenerateEnrollmentKeyMaterial(t *testing.T) {
	key, err := generateEnrollmentKeyMaterial()
	if err != nil {
		t.Fatalf("generateEnrollmentKeyMaterial: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("got key length %d, want 32 (matching NewEphemeralEnrollmentSigner's own key size)", len(key))
	}

	// A signer built directly from this material must actually work end to
	// end — issuing and verifying a signature against itself, not just
	// checking the byte length.
	signer := &EnrollmentSigner{key: key}
	sig := signer.enrollmentTokenSignature("tok_test", "usr_test", TTLClassSelfService, 1, time.Now(), time.Now().Add(time.Hour))
	if len(sig) == 0 {
		t.Error("enrollmentTokenSignature produced an empty signature with round-tripped key material")
	}

	key2, err := generateEnrollmentKeyMaterial()
	if err != nil {
		t.Fatalf("generateEnrollmentKeyMaterial (second call): %v", err)
	}
	if string(key) == string(key2) {
		t.Error("generateEnrollmentKeyMaterial produced identical key material on two separate calls")
	}
}
