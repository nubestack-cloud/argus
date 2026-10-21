package gateway

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"
)

// TestDevCARootMaterial_RoundTrip is the DB-free-testable slice of
// NewPersistentDevCA's persistence logic: the serialize/parse pair backing
// signing_keys.key_material for purpose='dev_ca_root'. A real
// load-or-create-against-Postgres round trip needs a live database, and so
// does the actual cross-restart TLS-handshake claim (an agent's persisted
// root cert still verifying a freshly-issued leaf after the hub restarts) —
// both verified live instead (see STATUS.md). This test covers the pure
// marshal/parse half, plus proves the reconstructed CA is actually
// functional (can sign a leaf that verifies against its own root pool), not
// just that parsing doesn't error.
func TestDevCARootMaterial_RoundTrip(t *testing.T) {
	material, err := generateDevCARootMaterial()
	if err != nil {
		t.Fatalf("generateDevCARootMaterial: %v", err)
	}

	key, cert, certPEM, err := parseDevCARootMaterial(material)
	if err != nil {
		t.Fatalf("parseDevCARootMaterial: %v", err)
	}
	if key == nil || cert == nil || len(certPEM) == 0 {
		t.Fatal("parseDevCARootMaterial returned a nil/empty component")
	}
	if !cert.IsCA {
		t.Error("parsed certificate is not marked as a CA")
	}
	if !cert.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Error("parsed certificate's public key does not match the parsed private key")
	}

	ca := &DevCA{cert: cert, certPEM: certPEM, key: key}

	// A fresh leaf, signed by the reconstructed CA, must verify against that
	// same CA's own root pool — the property a restarted hub actually
	// depends on for both directions of the mTLS handshake.
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "devca-roundtrip-test"},
	}, leafKey)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	leafPEM, _, err := ca.SignCSR(csrPEM, time.Hour)
	if err != nil {
		t.Fatalf("SignCSR with round-tripped CA: %v", err)
	}

	block, _ := pem.Decode([]byte(leafPEM))
	if block == nil {
		t.Fatal("SignCSR did not return a decodable PEM certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse issued leaf certificate: %v", err)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     ca.ClientCAPool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("leaf certificate issued by the round-tripped CA did not verify against its own root pool: %v", err)
	}
}

// TestGenerateDevCARootMaterial_NeverRepeats guards against a persistence
// bug that always "loaded" a fixed root rather than generating fresh entropy
// — matching the same guard added for the JWT/enrollment key generators.
func TestGenerateDevCARootMaterial_NeverRepeats(t *testing.T) {
	a, err := generateDevCARootMaterial()
	if err != nil {
		t.Fatalf("generateDevCARootMaterial: %v", err)
	}
	b, err := generateDevCARootMaterial()
	if err != nil {
		t.Fatalf("generateDevCARootMaterial (second call): %v", err)
	}
	if string(a) == string(b) {
		t.Error("generateDevCARootMaterial produced identical material on two separate calls")
	}
}
