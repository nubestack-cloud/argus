package agent

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeServerCA writes the httptest TLS server's self-signed certificate as
// a PEM bundle — standing in for a private CA that no system pool contains.
func writeServerCA(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hub-ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func enrollTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/clusters/enroll" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"clusterId":"cl_test","status":"pendingApproval","pollToken":"pt"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Without a bundle the agent keeps the old behaviour — system roots only —
// so a hub behind a private CA is refused as an unknown authority. That is
// the failure hub.caBundle exists to fix.
func TestHubHTTPClientWithoutBundleRejectsPrivateCA(t *testing.T) {
	srv := enrollTestServer(t)
	client, err := NewHubHTTPClient("")
	if err != nil {
		t.Fatal(err)
	}
	if client != http.DefaultClient {
		t.Errorf("empty caFile should return http.DefaultClient unchanged")
	}
	_, _, _, err = postEnroll(context.Background(), Config{HubAPIURL: srv.URL, Token: "tok"}, client, "fp", "csr")
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("postEnroll against a private-CA hub with system roots only: err = %v, want an x509 certificate error", err)
	}
}

// With the bundle, enrollment goes through the same postEnroll the agent
// runs — proving the client is the one actually used, not just built.
func TestHubHTTPClientWithBundleTrustsPrivateCA(t *testing.T) {
	srv := enrollTestServer(t)
	client, err := NewHubHTTPClient(writeServerCA(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	clusterID, pollToken, _, err := postEnroll(context.Background(), Config{HubAPIURL: srv.URL, Token: "tok"}, client, "fp", "csr")
	if err != nil {
		t.Fatalf("postEnroll with the hub's CA bundle: %v", err)
	}
	if clusterID != "cl_test" || pollToken != "pt" {
		t.Errorf("postEnroll = (%q, %q), want (cl_test, pt)", clusterID, pollToken)
	}
}

// The bundle is appended to the system pool, never a replacement for it: a
// hub whose certificate later moves to a public CA must keep verifying.
func TestHubHTTPClientAppendsToSystemPool(t *testing.T) {
	srv := enrollTestServer(t)
	caFile := writeServerCA(t, srv)
	client, err := NewHubHTTPClient(caFile)
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil || tr.TLSClientConfig.RootCAs == nil {
		t.Fatalf("client has no custom RootCAs: %#v", client.Transport)
	}
	if tr.Proxy == nil {
		t.Errorf("transport dropped ProxyFromEnvironment; an agent behind HTTPS_PROXY would stop reaching the hub")
	}

	system, err := x509.SystemCertPool()
	if err != nil {
		t.Skipf("no system cert pool on this machine: %v", err)
	}
	pemBytes, _ := os.ReadFile(caFile)
	want := system.Clone()
	want.AppendCertsFromPEM(pemBytes)
	if !tr.TLSClientConfig.RootCAs.Equal(want) {
		t.Errorf("RootCAs is not system pool + bundle")
	}
	bundleOnly := x509.NewCertPool()
	bundleOnly.AppendCertsFromPEM(pemBytes)
	if !system.Equal(x509.NewCertPool()) && tr.TLSClientConfig.RootCAs.Equal(bundleOnly) {
		t.Errorf("RootCAs holds only the bundle; the system roots were replaced, not appended to")
	}
}

// A configured bundle that cannot be used is an error, never a silent
// fall-back to system roots.
func TestHubHTTPClientRejectsUnusableBundle(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "not-pem.txt")
	if err := os.WriteFile(notPEM, []byte("this is not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing file": filepath.Join(dir, "absent.pem"),
		"no PEM cert":  notPEM,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewHubHTTPClient(path); err == nil {
				t.Errorf("NewHubHTTPClient(%s) succeeded, want an error", name)
			}
		})
	}
}

// A hub that is still starting (installed in the same release as this agent)
// is retried, not treated as fatal; the auto-accept status is passed back.
func TestPostEnrollRetriesAHubThatIsNotReadyYet(t *testing.T) {
	defer func(d time.Duration) { enrollRetryInitial = d }(enrollRetryInitial)
	enrollRetryInitial = 10 * time.Millisecond
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"clusterId":"cl_local","status":"accepted","pollToken":"pt"}`))
	}))
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	id, _, status, err := postEnroll(ctx, Config{HubAPIURL: srv.URL, Token: "tok"}, http.DefaultClient, "fp", "csr")
	if err != nil || id != "cl_local" || status != "accepted" || calls != 3 {
		t.Fatalf("postEnroll = %q %q %v after %d calls", id, status, err, calls)
	}
}

// A hub that answers and refuses is final.
func TestPostEnrollDoesNotRetryARefusal(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadRequest)
	}))
	t.Cleanup(srv.Close)
	if _, _, _, err := postEnroll(context.Background(), Config{HubAPIURL: srv.URL, Token: "tok"}, http.DefaultClient, "fp", "csr"); err == nil || calls != 1 {
		t.Fatalf("err=%v after %d calls", err, calls)
	}
}
