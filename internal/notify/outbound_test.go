package notify

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"argus/internal/outbound"
)

// TestNewWebhookNotifier_ReachesPrivateButRefusesMetadata proves the
// notification-webhook caller (lld/01-threat-model.md T15/B8) adopted
// internal/outbound's hardened transport, using NewWebhookNotifier's real
// construction path, and that its deliberate allowance for a private
// destination — ARGUS is self-hosted and commonly has no public endpoint;
// an internal alerting/chat receiver on the operator's own LAN is the
// expected case, see NewWebhookNotifier's own comment — does not also open
// the one unconditional exception: cloud metadata.
func TestNewWebhookNotifier_ReachesPrivateButRefusesMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewWebhookNotifier(nil)

	// A LAN-internal receiver (this test server is on 127.0.0.1, standing
	// in for "an internal alerting endpoint, a LAN Mattermost, or a
	// corporate proxy") must be reachable.
	if err := n.post(t.Context(), srv.URL, []byte(`{}`)); err != nil {
		t.Fatalf("expected the webhook client to reach a private/loopback receiver, got: %v", err)
	}

	// Cloud metadata must be refused unconditionally, even though this
	// caller's policy allows private destinations.
	err := n.post(t.Context(), "http://169.254.169.254/hook", []byte(`{}`))
	if err == nil {
		t.Fatal("expected the webhook client to refuse a cloud metadata target")
	}
	if !outbound.IsRefusal(err) {
		t.Fatalf("expected a stated outbound refusal reason, got: %v", err)
	}
}
