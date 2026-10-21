// Package gateway implements the hub's Agent Gateway: the mTLS tunnel listener
// agents connect to after enrollment (lld/03-agent-protocol.md §3, §6), and the
// dev-only CA that issues the certificates on both sides of that handshake.
package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"argus/internal/data"
)

// rootCAValidity is the dev root's own lifetime — long, since (unlike a leaf
// cert) nothing in this MVP ever renews it; a restart replaces it entirely
// (see NewEphemeralDevCA's warning).
const rootCAValidity = 10 * 365 * 24 * time.Hour

// DevCA is a self-signed root CA used to issue both the gateway's own TLS
// server certificate and every cluster's leaf certificate, standing in for
// lld/03-agent-protocol.md §3's real two-tier Root -> per-shard Intermediate
// PKI. There is exactly one tier here, not two, and no HSM/offline signing
// ceremony — a deliberate MVP simplification, not an oversight; see STATUS.md
// and this document's addendum.
type DevCA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     *ecdsa.PrivateKey
}

// NewEphemeralDevCA generates a fresh, self-signed ECDSA P-256 root CA on
// every call. Follows the exact same convention as
// authz.NewEphemeralTokenSigner/NewEphemeralEnrollmentSigner: not persisted,
// so a hub restart invalidates every certificate this CA ever issued —
// the gateway's own server cert AND every enrolled cluster's leaf cert. This
// is a known, accepted Phase 0 gap (STATUS.md), not something to fix here by
// adding persistence — that's deployment-design's job once there's a real
// deployment target and KMS-backed secret store (lld/03-agent-protocol.md §3).
func NewEphemeralDevCA() (*DevCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate dev CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ARGUS Dev Root CA (ephemeral)"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(rootCAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign dev CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse dev CA cert: %w", err)
	}

	logger.Warn("using an ephemeral, non-persisted dev CA: every certificate it issues (this gateway's own TLS server cert AND every enrolled cluster's leaf cert) is invalidated on restart. Not a production configuration: a hub with a database persists its CA instead.")

	return &DevCA{
		cert:    cert,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:     key,
	}, nil
}

// signingKeyPurposeDevCARoot is this CA's row key in the signing_keys table
// (internal/migrations/000016_signing_keys.up.sql).
const signingKeyPurposeDevCARoot = "dev_ca_root"

// NewPersistentDevCA loads the dev CA root persisted in Postgres
// (signing_keys, purpose='dev_ca_root') if one exists, or generates a fresh
// self-signed root exactly like NewEphemeralDevCA and persists it if not —
// same shape and rationale as authz.NewPersistentTokenSigner/
// authz.NewPersistentEnrollmentSigner (see internal/authz/jwt.go's doc
// comment for the full explanation of the loaded/generated distinction, the
// deliberate non-KMS tradeoff, and data.LoadOrCreateSigningKey's concurrency
// handling).
//
// Only the root's own key+certificate is persisted here — leaf certificates
// (SignCSR, IssueServerCert) stay exactly as ephemeral-per-call as they
// already were; that's correct by design (a leaf's whole point is to be
// reissued whenever needed), not a gap this function needs to close.
//
// Persisting the root's CERTIFICATE, not just its private key, matters for a
// subtle reason worth stating explicitly: an agent that enrolled before a
// restart has already persisted the CA's root certificate PEM
// (internal/agent's own "generates its own key + CSR, persists
// key/cert/CA/fingerprint" flow, per STATUS.md) as its literal trust anchor.
// If this function reconstructed a brand-new self-signed certificate object
// from the same key on every restart (new serial number, new NotBefore/
// NotAfter) rather than reloading the exact original certificate bytes,
// whether that would still verify against what the agent already has on
// disk would depend on x509 verification internals not comparing serial
// numbers — true in Go's current stdlib behavior, but not something worth
// relying on implicitly. Loading back the identical, byte-for-byte original
// root certificate sidesteps the question entirely.
func NewPersistentDevCA(ctx context.Context, pool *pgxpool.Pool) (ca *DevCA, loaded bool, err error) {
	material, loaded, err := data.LoadOrCreateSigningKey(ctx, pool, signingKeyPurposeDevCARoot, generateDevCARootMaterial)
	if err != nil {
		return nil, false, fmt.Errorf("load or create dev CA root: %w", err)
	}
	key, cert, certPEM, err := parseDevCARootMaterial(material)
	if err != nil {
		return nil, false, fmt.Errorf("parse persisted dev CA root: %w", err)
	}
	return &DevCA{cert: cert, certPEM: certPEM, key: key}, loaded, nil
}

// generateDevCARootMaterial generates a fresh self-signed ECDSA P-256 root
// CA — the same generation NewEphemeralDevCA performs inline — and
// serializes both the private key and the resulting self-signed certificate
// via serializeDevCARootMaterial, so parseDevCARootMaterial can reconstruct
// the identical *x509.Certificate object (not merely an equivalent one) on
// every future load.
func generateDevCARootMaterial() ([]byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate dev CA key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ARGUS Dev Root CA (persistent)"},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(rootCAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign dev CA cert: %w", err)
	}

	return serializeDevCARootMaterial(key, der)
}

// serializeDevCARootMaterial packs a private key and its self-signed
// certificate DER into the single []byte signing_keys.key_material can hold
// — two concatenated PEM blocks (an "EC PRIVATE KEY" block, then a
// "CERTIFICATE" block), matching this file's existing PEM-based conventions
// (RootCertPEM, IssueServerCert's certPEM/keyPEM) rather than introducing a
// new encoding scheme (gob, protobuf, ...) for one table.
func serializeDevCARootMaterial(key *ecdsa.PrivateKey, certDER []byte) ([]byte, error) {
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal dev CA key: %w", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return nil, fmt.Errorf("encode dev CA key PEM: %w", err)
	}
	if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return nil, fmt.Errorf("encode dev CA cert PEM: %w", err)
	}
	return buf.Bytes(), nil
}

// parseDevCARootMaterial is serializeDevCARootMaterial's inverse: given the
// two-PEM-block byte string stored in signing_keys.key_material, reconstructs
// the private key, the parsed certificate, and the certificate's own PEM
// encoding (the exact bytes RootCertPEM hands back to an enrolling agent —
// recomputed from the decoded block rather than re-slicing the input, so it's
// correct regardless of whether the key block or the cert block came first
// on disk).
func parseDevCARootMaterial(material []byte) (key *ecdsa.PrivateKey, cert *x509.Certificate, certPEM []byte, err error) {
	keyBlock, rest := pem.Decode(material)
	if keyBlock == nil || keyBlock.Type != "EC PRIVATE KEY" {
		return nil, nil, nil, fmt.Errorf("malformed dev CA root material: expected an EC PRIVATE KEY PEM block first")
	}
	key, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse dev CA private key: %w", err)
	}

	certBlock, _ := pem.Decode(rest)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, nil, nil, fmt.Errorf("malformed dev CA root material: expected a CERTIFICATE PEM block second")
	}
	cert, err = x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse dev CA certificate: %w", err)
	}

	return key, cert, pem.EncodeToMemory(certBlock), nil
}

// RootCertPEM returns the CA's own certificate, PEM-encoded — this is the
// `caPem` handed back to an agent at enroll-status time so it can verify the
// gateway's TLS server certificate.
func (ca *DevCA) RootCertPEM() []byte {
	return ca.certPEM
}

// SignCSR parses and validates a submitted CSR (checking its self-signature,
// per PKCS#10) and issues a leaf certificate for it, signed by this CA. serial
// is the issued cert's serial number as a decimal string — this is the same
// value the gateway later reads back off the peer certificate during the mTLS
// handshake (internal/gateway/server.go) to identify which cluster connected,
// so the two must agree exactly.
func (ca *DevCA) SignCSR(csrPEM []byte, validity time.Duration) (certPEM string, serial string, err error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return "", "", fmt.Errorf("invalid CSR: not a PEM-encoded CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", "", fmt.Errorf("CSR signature invalid: %w", err)
	}

	serialNum, err := randomSerial()
	if err != nil {
		return "", "", err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNum,
		Subject:      csr.Subject,
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return "", "", fmt.Errorf("sign leaf certificate: %w", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), serialNum.String(), nil
}

// IssueServerCert generates a fresh key pair and issues a server certificate
// for it — the gateway's own TLS identity, signed by the same root the agent
// was handed at enrollment (RootCertPEM), so the agent's TLS chain verification
// against that root succeeds.
func (ca *DevCA) IssueServerCert(sans []string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate server key: %w", err)
	}

	serialNum, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNum,
		Subject:      pkix.Name{CommonName: "argus-hub-gateway"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, san := range sans {
		if ip := net.ParseIP(san); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign server certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal server key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	return certPEM, keyPEM, nil
}

// ClientCAPool returns a pool containing just this CA's own root cert, for
// tls.Config.ClientCAs — every agent's leaf cert must chain to this root to
// pass the gateway's mTLS handshake.
func (ca *DevCA) ClientCAPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	return pool
}

// randomSerial generates a random 128-bit positive serial number — large
// enough that collision is not a practical concern for this CA's expected
// issuance volume, and a decimal string of it is what SignCSR/IssueServerCert
// return and what the gateway matches back against clusters.cert_serial.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial, nil
}
