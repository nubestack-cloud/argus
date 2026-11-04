package agent

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// OpenShift's Thanos querier authenticates by this agent's own projected
// ServiceAccount token. The token is rotated in place, so the client must
// read the file per request, not once at start-up.
func TestExternalMetricsBearerTokenFileIsReadPerRequest(t *testing.T) {
	var gotAuth string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
	}))
	defer srv.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "service-ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	tok := filepath.Join(dir, "token")
	if err := os.WriteFile(tok, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARGUS_METRICS_EXTERNAL_URL", srv.URL)
	t.Setenv("ARGUS_METRICS_EXTERNAL_CA_FILE", ca)
	t.Setenv("ARGUS_METRICS_EXTERNAL_BEARER_TOKEN_FILE", tok)
	c, err := newExternalMetricsClientFromEnv()
	if err != nil || c == nil {
		t.Fatalf("client: %v", err)
	}
	if _, err := c.Get(context.Background(), "api/v1/query", map[string]string{"query": "vector(1)"}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer first" {
		t.Fatalf("Authorization = %q, want the token file's contents, trimmed", gotAuth)
	}
	if err := os.WriteFile(tok, []byte("rotated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background(), "api/v1/query", map[string]string{"query": "vector(1)"}); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer rotated" {
		t.Fatalf("Authorization = %q after rotation; a token read once at start-up expires", gotAuth)
	}
}

// The token is this agent's Kubernetes identity: never over plain http.
func TestExternalMetricsBearerTokenRequiresHTTPS(t *testing.T) {
	t.Setenv("ARGUS_METRICS_EXTERNAL_URL", "http://thanos-querier.openshift-monitoring.svc:9091")
	t.Setenv("ARGUS_METRICS_EXTERNAL_BEARER_TOKEN_FILE", "/var/run/secrets/kubernetes.io/serviceaccount/token")
	if c, err := newExternalMetricsClientFromEnv(); err == nil || c != nil {
		t.Fatalf("a bearer token over http:// must be refused, got client=%v err=%v", c, err)
	}
}
