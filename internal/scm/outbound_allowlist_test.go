package scm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"argus/internal/outbound"
)

// The repository clients' egress posture (lld/01-threat-model.md T15/B7).
//
// Default-deny for private destinations stays; the only way past it is the
// operator's named allowlist (migration 000115, owner decision 2026-09-19).
// These tests assert BOTH halves on the real client() constructor, because
// the failure mode that matters is silent in either direction: a dropped
// allowlist field makes a legitimately-configured internal GHES unreachable
// with no code change visible anywhere, and an accidental AllowPrivate makes
// every private address reachable with no configuration visible anywhere.

func TestGitHubClient_DefaultRefusesPrivateDestinations(t *testing.T) {
	g := &GitHub{}
	if _, err := g.client().Get("http://10.11.12.13/"); err == nil || !outbound.IsRefusal(err) {
		t.Fatalf("expected the GitHub client to refuse a private destination by default, got: %v", err)
	}
	if _, err := g.client().Get("http://169.254.169.254/latest/meta-data/"); err == nil || !outbound.IsRefusal(err) {
		t.Fatalf("expected the GitHub client to refuse the cloud metadata address, got: %v", err)
	}
}

func TestGitLabClient_DefaultRefusesPrivateDestinations(t *testing.T) {
	g := &GitLab{}
	if _, err := g.client().Get("http://10.11.12.13/"); err == nil || !outbound.IsRefusal(err) {
		t.Fatalf("expected the GitLab client to refuse a private destination by default, got: %v", err)
	}
}

// TestGitHubClient_AllowlistedPrivateDestinationIsReachable proves the field
// is actually wired into the Policy rather than merely declared — without
// this, ProviderFor could set it and client() ignore it, and nothing would
// look wrong until a real internal GHES refused to answer.
func TestGitHubClient_AllowlistedPrivateDestinationIsReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	allowlist, err := outbound.ParseAllowlist([]outbound.AllowlistEntry{
		{Destination: "127.0.0.1/32", Reason: "internal GitHub Enterprise Server"},
	})
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}
	g := &GitHub{PrivateDestinations: func(context.Context) (outbound.Allowlist, error) { return allowlist, nil }}

	resp, err := g.client().Get(srv.URL)
	if err != nil {
		t.Fatalf("expected an allowlisted private destination to be reachable, got: %v", err)
	}
	resp.Body.Close()

	// ...and only that one. A second private address is still refused with
	// the same allowlist in place.
	if _, err := g.client().Get("http://10.11.12.13/"); err == nil || !outbound.IsRefusal(err) {
		t.Fatalf("expected a private destination outside the allowlist to stay refused, got: %v", err)
	}
	// The unconditional refusal is unaffected by any of this.
	if _, err := g.client().Get("http://169.254.169.254/latest/meta-data/"); err == nil || !outbound.IsRefusal(err) {
		t.Fatalf("expected the cloud metadata address to stay refused with an allowlist configured, got: %v", err)
	}
}

func TestGitLabClient_AllowlistedPrivateDestinationIsReachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	allowlist, err := outbound.ParseAllowlist([]outbound.AllowlistEntry{
		{Destination: "127.0.0.0/8", Reason: "internal GitLab CE"},
	})
	if err != nil {
		t.Fatalf("ParseAllowlist: %v", err)
	}
	g := &GitLab{PrivateDestinations: func(context.Context) (outbound.Allowlist, error) { return allowlist, nil }}

	resp, err := g.client().Get(srv.URL)
	if err != nil {
		t.Fatalf("expected an allowlisted private destination to be reachable, got: %v", err)
	}
	resp.Body.Close()
}
