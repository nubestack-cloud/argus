package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExternalMetricsClient(t *testing.T) {
	var gotPath, gotLabel, gotTenant, gotAuth string
	enforcing := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotLabel = r.URL.Path, r.URL.Query().Get("extra_label")
		gotTenant, gotAuth = r.Header.Get("X-Scope-OrgID"), r.Header.Get("Authorization")
		if gotAuth != "Bearer s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// An enforcing backend (VictoriaMetrics, prom-label-proxy) has nothing
		// outside the label; plain Prometheus answers as if it were not sent.
		if strings.Contains(r.URL.Query().Get("query"), "!=") && enforcing {
			_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[]}}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"3"]}]}}`))
	}))
	defer srv.Close()
	headers := filepath.Join(t.TempDir(), "headers")
	if err := os.WriteFile(headers, []byte("# tenant and token\nX-Scope-OrgID: prod-eu\nAuthorization: Bearer s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ARGUS_METRICS_EXTERNAL_URL", srv.URL+"/prometheus")
	t.Setenv("ARGUS_METRICS_EXTERNAL_HEADERS_FILE", headers)
	t.Setenv("ARGUS_METRICS_EXTERNAL_EXTRA_LABEL", "cluster=prod-eu")
	c, err := newExternalMetricsClientFromEnv()
	if err != nil || c == nil {
		t.Fatalf("client: %v", err)
	}
	m := externalMetricsAuthority(context.Background(), c)
	if !m.Checked || !m.Allowed || !m.External || !m.ScopedByLabel {
		t.Fatalf("authority = %+v", m)
	}
	if gotPath != "/prometheus/api/v1/query" || gotLabel != "cluster=prod-eu" || gotTenant != "prod-eu" {
		t.Fatalf("request: path=%q extra_label=%q tenant=%q", gotPath, gotLabel, gotTenant)
	}
	// The same label on an endpoint that ignores it is reported as ignored,
	// never as scoped.
	enforcing = false
	if m := externalMetricsAuthority(context.Background(), c); m.ScopedByLabel || !m.LabelIgnored {
		t.Fatalf("an ignored label must not read as scoped: %+v", m)
	}
	// A refused credential is reported, never read as "allowed".
	c.headers.Set("Authorization", "Bearer wrong")
	if m := externalMetricsAuthority(context.Background(), c); m.Allowed || m.Error == "" {
		t.Fatalf("a 401 must not count as allowed: %+v", m)
	}
}
