package llm

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"argus/internal/outbound"
	"argus/internal/settings"
)

// TestNewCLIInvestigator_ClientReachesLoopbackButRefusesMetadata proves the
// CLI-runner caller (mcpURL/settings.CLIRunnerURL, lld/01-threat-model.md
// B12 — a sixth outbound caller alongside the five named in T9, admin-
// configurable via PUT /api/v1/admin/settings the same way the other five
// are) adopted internal/outbound, and that its legitimate need to reach a
// same-deployment sidecar/Service address (this package's own tests
// already dial httptest servers on 127.0.0.1 via CLIRunnerURL) does not
// also open the one unconditional exception: cloud metadata.
func TestNewCLIInvestigator_ClientReachesLoopbackButRefusesMetadata(t *testing.T) {
	c := NewCLIInvestigator(&fakeMinter{}, []string{"get_events"}, "http://mcp/mcp", fixedConfig(settings.Config{}), nil)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if resp, err := c.client.Get(srv.URL); err != nil {
		t.Fatalf("expected the CLI-runner client to reach a loopback runner, got: %v", err)
	} else {
		resp.Body.Close()
	}

	if _, err := c.client.Get("http://169.254.169.254/latest/meta-data/"); err == nil || !outbound.IsRefusal(err) {
		t.Fatalf("expected the CLI-runner client to refuse cloud metadata even though it allows private destinations, got: %v", err)
	}
}
