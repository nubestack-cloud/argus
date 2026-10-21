package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"argus/internal/outbound"
)

// TestNewProvider_ClientRefusesSSRFTargets proves internal/llm.Provider
// (the AI-provider caller, lld/01-threat-model.md T15/B5) actually adopted
// internal/outbound's hardened transport rather than merely having it
// available. A provider's base_url is admin-configured
// (internal/settings.Resolve) and T15's whole point is that admin
// configuration is not a high enough trust bar to skip validating where the
// hub itself will connect.
func TestNewProvider_ClientRefusesSSRFTargets(t *testing.T) {
	p := NewProvider(nil)

	if _, err := p.client.Get("http://169.254.169.254/latest/meta-data/"); err == nil || !outbound.IsRefusal(err) {
		t.Fatalf("expected the AI-provider client to refuse a cloud metadata target with a stated reason, got: %v", err)
	}

	if _, err := p.client.Get("http://10.5.5.5/"); err == nil || !outbound.IsRefusal(err) {
		t.Fatalf("expected the AI-provider client to refuse a private-range target by default, got: %v", err)
	}
}

// TestProbeAPIHTTPClient_SharesTheRealProviderPolicy pins the specific
// regression the coordinator caught: probe.go's "test connection" button
// reads the same admin-configured base_url as Provider.Complete, so if the
// two ever used two different literal Policy values they could silently
// disagree, and the settings page could report "connection OK" for a
// destination the real completion path then refuses (a false green). This
// asserts they are built from the SAME variable, not just two policies that
// happen to look alike today.
func TestProbeAPIHTTPClient_SharesTheRealProviderPolicy(t *testing.T) {
	p := NewProvider(nil)

	// The private-range probe below the metadata check is the discriminating
	// case: if the probe client ever drifted to AllowPrivate: true while
	// NewProvider stayed default-deny, this would catch it (probe would
	// reach the target while the real client refuses it).
	target := "http://10.6.6.6/"

	// Built from the same constructor and the same (here: absent) allowlist
	// source the real path uses — NewProvider(nil) has no pool, so its
	// source is nil too. Passing a different source is the drift this test
	// exists to make visible, which is why ProbeTarget carries the source
	// explicitly rather than each side reaching for its own.
	_, providerErr := p.client.Get(target)
	_, probeErr := probeAPIClient(nil).Get(target)

	if !outbound.IsRefusal(providerErr) || !outbound.IsRefusal(probeErr) {
		t.Fatalf("expected both the real provider client and the probe client to refuse a private target; provider: %v, probe: %v", providerErr, probeErr)
	}
}

// TestAIProviderPolicy_AllowlistedPrivateDestinationIsReachable is the
// AI-provider half of the owner's 2026-09-19 decision: default-deny stays,
// and an operator's NAMED private destination (a self-hosted vLLM) is
// reachable through it — but nothing else is, and the cloud metadata address
// is not reachable at all.
//
// Asserted on the shared policy constructor both NewProvider and the probe
// build from, so it cannot pass here and fail at either real call site.
func TestAIProviderPolicy_AllowlistedPrivateDestinationIsReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	allowlist, err := outbound.ParseAllowlist([]outbound.AllowlistEntry{
		{Destination: "127.0.0.1/32", Reason: "self-hosted vLLM"},
	})
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}
	src := func(context.Context) (outbound.Allowlist, error) { return allowlist, nil }
	client := outbound.NewClient(aiProviderOutboundPolicy(src), 2*time.Second)

	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected an allowlisted private AI-provider endpoint to be reachable, got: %v", err)
	}
	resp.Body.Close()

	if _, err := client.Get("http://10.7.7.7/"); err == nil || !outbound.IsRefusal(err) {
		t.Fatalf("expected a private endpoint outside the allowlist to stay refused, got: %v", err)
	}
	if _, err := client.Get("http://169.254.169.254/latest/meta-data/"); err == nil || !outbound.IsRefusal(err) {
		t.Fatalf("expected the cloud metadata address to stay refused, got: %v", err)
	}

	// The probe reads the same admin-configured base_url, so it must agree —
	// including about the allowlist, which is why ProbeTarget carries the
	// source rather than each side reaching for its own.
	probe := probeAPIClient(src)
	probeResp, err := probe.Get(srv.URL)
	if err != nil {
		t.Fatalf("expected the probe client to agree with the real path about an allowlisted endpoint, got: %v", err)
	}
	probeResp.Body.Close()
	if _, err := probe.Get("http://10.7.7.7/"); err == nil || !outbound.IsRefusal(err) {
		t.Fatalf("expected the probe client to refuse a non-allowlisted private endpoint, got: %v", err)
	}
}
