package idp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"argus/internal/outbound"
)

// TestDiscover_ReachesLoopbackButRefusesMetadata proves the OIDC-discovery
// caller (lld/01-threat-model.md T15) adopted internal/outbound, and that
// its documented, deliberate exception for a self-hosted broker (Dex,
// commonly on localhost:5556 in this project's own dev stack — see the
// FIX-AND-IMPLEMENT-PROMPT's critical trap note) does not also open the one
// unconditional exception: cloud metadata.
func TestDiscover_ReachesLoopbackButRefusesMetadata(t *testing.T) {
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/auth",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/keys",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	issuer = srv.URL

	// A Dex-like self-hosted broker on loopback must still be discoverable
	// — this is the exact shape of this project's own dev stack (Dex on
	// localhost:5556) and the CRITICAL TRAP this fix must not break.
	if _, err := Discover(context.Background(), Config{
		Issuer: issuer, ClientID: "argus", RedirectURI: "http://hub/callback",
	}); err != nil {
		t.Fatalf("expected discovery against a loopback issuer to succeed, got: %v", err)
	}

	// A metadata-hostname issuer must be refused unconditionally, even
	// though this caller's policy allows private/loopback destinations.
	_, err := Discover(context.Background(), Config{
		Issuer: "http://metadata.google.internal/computeMetadata/v1", ClientID: "argus", RedirectURI: "http://hub/callback",
	})
	if err == nil {
		t.Fatal("expected discovery against a cloud-metadata issuer to fail")
	}
	if !outbound.IsRefusal(err) {
		t.Fatalf("expected a stated outbound refusal reason, got: %v", err)
	}
}
