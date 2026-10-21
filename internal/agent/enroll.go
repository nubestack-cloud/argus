// Package agent implements the spoke (in-cluster) side of
// lld/03-agent-protocol.md: generating the agent's own key/CSR, best-effort
// cluster fact-gathering, and the enroll -> poll -> tunnel -> heartbeat loop
// described in §5-§8 of that document (scoped down to this repo's MVP
// transport, internal/tunnel/protocol.go).
package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
)

// GenerateKeyAndCSR creates a fresh ECDSA P-256 key and a PKCS#10 certificate
// signing request with the given CommonName (per lld/03-agent-protocol.md
// §5's EnrollRequest.csr field), returning both PEM-encoded.
//
// commonName is the agent's choice — this implementation uses the cluster
// fingerprint, matching what's also sent as EnrollRequest.cluster_fingerprint,
// so the leaf cert's identity and the enrollment record's identity always
// agree.
func GenerateKeyAndCSR(commonName string) (keyPEM, csrPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

	return keyPEM, csrPEM, nil
}
