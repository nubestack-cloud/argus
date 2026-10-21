package authz

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestTokenSigner_IssueAndVerify_RoundTrip(t *testing.T) {
	signer, err := NewEphemeralTokenSigner()
	if err != nil {
		t.Fatalf("NewEphemeralTokenSigner: %v", err)
	}

	token, err := signer.IssueAccessToken("usr_test123", 7)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	userID, generation, err := signer.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if userID != "usr_test123" {
		t.Errorf("got userID %q, want %q", userID, "usr_test123")
	}
	if generation != 7 {
		t.Errorf("got generation %d, want 7 (the value passed to IssueAccessToken should round-trip)", generation)
	}
}

func TestTokenSigner_RejectsTokenFromADifferentSigner(t *testing.T) {
	signerA, _ := NewEphemeralTokenSigner()
	signerB, _ := NewEphemeralTokenSigner()

	token, err := signerA.IssueAccessToken("usr_test123", 0)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	if _, _, err := signerB.VerifyAccessToken(token); err == nil {
		t.Error("VerifyAccessToken accepted a token signed by a different key — signature is not actually being checked")
	}
}

// TestTokenSigner_RejectsAlgNone is the direct test for SR-18
// (lld/01-threat-model.md): a forged token using the "none" algorithm must be
// rejected regardless of anything else about it, because "none" means there is
// no signature to forge in the first place.
func TestTokenSigner_RejectsAlgNone(t *testing.T) {
	signer, _ := NewEphemeralTokenSigner()

	claims := jwt.RegisteredClaims{
		Subject:   "usr_attacker",
		Issuer:    issuer,
		Audience:  jwt.ClaimStrings{audience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	unsigned := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	forged, err := unsigned.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("construct alg=none token: %v", err)
	}

	if _, _, err := signer.VerifyAccessToken(forged); err == nil {
		t.Error("VerifyAccessToken accepted an alg=none token — SR-18 is not enforced")
	}
}

// TestTokenSigner_RejectsWrongAudience uses same-package access to the private
// key to construct a token that is CORRECTLY signed but carries the wrong
// audience — isolating that the audience check fires independently of signature
// validity, not just as a side effect of a bad signature also being present.
func TestTokenSigner_RejectsWrongAudience(t *testing.T) {
	signer, _ := NewEphemeralTokenSigner()

	claims := jwt.RegisteredClaims{
		Subject:   "usr_test123",
		Issuer:    issuer,
		Audience:  jwt.ClaimStrings{"some-other-api"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := token.SignedString(signer.private)
	if err != nil {
		t.Fatalf("sign token with wrong audience: %v", err)
	}

	if _, _, err := signer.VerifyAccessToken(signed); err == nil {
		t.Error("VerifyAccessToken accepted a correctly-signed token with the wrong audience")
	}
}

func TestTokenSigner_RejectsExpiredToken(t *testing.T) {
	signer, _ := NewEphemeralTokenSigner()

	claims := jwt.RegisteredClaims{
		Subject:   "usr_test123",
		Issuer:    issuer,
		Audience:  jwt.ClaimStrings{audience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)), // already expired
		IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Minute)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	signed, err := token.SignedString(signer.private)
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}

	if _, _, err := signer.VerifyAccessToken(signed); err == nil {
		t.Error("VerifyAccessToken accepted an expired token")
	}
}

// TestGenerateECDSAKeyMaterial_RoundTrip is the DB-free-testable slice of
// NewPersistentTokenSigner's persistence logic: the serialization format it
// writes to (and reads back from) signing_keys.key_material. A real
// load-or-create-against-Postgres round trip needs a live database (verified
// live instead — see STATUS.md); this test covers the pure marshal/parse
// half that data.LoadOrCreateSigningKey's generate callback and
// NewPersistentTokenSigner's own x509.ParseECPrivateKey call both depend on.
func TestGenerateECDSAKeyMaterial_RoundTrip(t *testing.T) {
	der, err := generateECDSAKeyMaterial()
	if err != nil {
		t.Fatalf("generateECDSAKeyMaterial: %v", err)
	}

	priv, err := x509.ParseECPrivateKey(der)
	if err != nil {
		t.Fatalf("x509.ParseECPrivateKey: %v", err)
	}

	signer := &TokenSigner{private: priv, public: &priv.PublicKey}
	token, err := signer.IssueAccessToken("usr_test123", 0)
	if err != nil {
		t.Fatalf("IssueAccessToken with round-tripped key: %v", err)
	}
	if _, _, err := signer.VerifyAccessToken(token); err != nil {
		t.Errorf("VerifyAccessToken with round-tripped key: %v", err)
	}

	// Two calls must never produce the same key material — a persistence bug
	// that always "loaded" a fixed key rather than actually generating fresh
	// entropy would be a much worse regression than the ephemeral-restart gap
	// this feature exists to fix.
	der2, err := generateECDSAKeyMaterial()
	if err != nil {
		t.Fatalf("generateECDSAKeyMaterial (second call): %v", err)
	}
	if string(der) == string(der2) {
		t.Error("generateECDSAKeyMaterial produced identical key material on two separate calls")
	}
}
