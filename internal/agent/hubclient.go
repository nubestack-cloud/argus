package agent

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
)

// NewHubHTTPClient returns the client the agent uses for its HTTPS calls to
// Config.HubAPIURL — enrollment and the enroll-status poll, which are the
// only hub calls not carried by the mTLS tunnel (the tunnel pins the CA the
// hub hands back at enrollment, so it never consults a system pool).
//
// caFile empty returns http.DefaultClient, exactly the behaviour before this
// option existed: the system trust roots in the agent image.
//
// caFile set APPENDS that PEM bundle to the system pool rather than
// replacing it. A hub behind a private CA then verifies, and a hub whose
// ingress certificate later moves to a public CA keeps verifying too, so the
// option cannot strand an agent on a certificate change. The bundle must
// contain at least one certificate: an unreadable file or one with no PEM
// certificate in it is an error rather than a silent fall-back to system
// roots, because that fall-back would surface much later as an x509 failure
// against a hub the operator believes they configured trust for
// (deploy/helm/argus-agent hub.caBundle / hub.caSecretRef).
func NewHubHTTPClient(caFile string) (*http.Client, error) {
	if caFile == "" {
		return http.DefaultClient, nil
	}
	tlsConfig, err := hubTLSConfig(caFile)
	if err != nil {
		return nil, err
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("http.DefaultTransport is not an *http.Transport")
	}
	// Clone keeps the default dialer, timeouts and ProxyFromEnvironment, so
	// an agent behind an HTTPS_PROXY behaves as it did with DefaultClient.
	tr := base.Clone()
	tr.TLSClientConfig = tlsConfig
	return &http.Client{Transport: tr}, nil
}

// hubTLSConfig is how the agent trusts the hub's public HTTPS address: the
// system roots, plus the hub CA bundle when one is given. Nil means the
// system roots alone. Enrollment and the WebSocket tunnel both use it.
func hubTLSConfig(caFile string) (*tls.Config, error) {
	if caFile == "" {
		return nil, nil
	}
	pemBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read hub CA bundle %s: %w", caFile, err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		// No readable system pool (not the case in the distroless image,
		// which ships one): the bundle alone is still a usable trust set.
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("hub CA bundle " + caFile + " contains no PEM certificate")
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}
