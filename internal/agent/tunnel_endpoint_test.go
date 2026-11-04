package agent

import "testing"

// The hub chart gives its own (embedded) agent the in-cluster tunnel address
// through ARGUS_TUNNEL_ENDPOINT. A freshly enrolled agent used to ignore it in
// favour of the hub's advertised public URL until its first restart.
func TestEffectiveTunnelEndpointPrefersConfiguredOverride(t *testing.T) {
	const inCluster = "ws://argus-hub.argus-system.svc:8080/api/v1/agent/tunnel"
	const advertised = "wss://argus.apps.example.com/api/v1/agent/tunnel"
	if got := effectiveTunnelEndpoint(inCluster, advertised); got != inCluster {
		t.Fatalf("got %q, want the configured override %q", got, inCluster)
	}
	if got := effectiveTunnelEndpoint("  ", advertised); got != advertised {
		t.Fatalf("got %q, want the advertised endpoint when nothing is configured", got)
	}
	if got := effectiveTunnelEndpoint("", ""); got != "" {
		t.Fatalf("got %q, want empty when neither is known", got)
	}
}
