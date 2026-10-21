package api

import (
	"strings"
	"testing"
)

// TestValidateProviderInputRejectsUnsafeIssuers pins the two issuer rules that
// have real consequences, plus the one that causes the most confusing failure.
func TestValidateProviderInputRejectsUnsafeIssuers(t *testing.T) {
	base := func(issuer string) *saveIdentityProviderRequest {
		return &saveIdentityProviderRequest{
			DisplayName: "Acme SSO",
			Issuer:      issuer,
			ClientID:    "argus",
			RedirectURI: "https://argus.example.com/api/v1/auth/sso/callback",
		}
	}

	rejected := map[string]string{
		// An http issuer sends ID tokens and the client secret in clear.
		"http://idp.example.com": "http",
		// Compared byte-for-byte against the discovery document's own issuer
		// by go-oidc, so a trailing slash is a silent, opaque mismatch. This
		// is the single most common misconfiguration and the least obvious.
		"https://idp.example.com/": "slash",
		"idp.example.com":          "absolute",
		"":                         "required",
	}
	for issuer, want := range rejected {
		detail := validateProviderInput(base(issuer))
		if detail == "" {
			t.Errorf("issuer %q was accepted; expected a rejection mentioning %q", issuer, want)
			continue
		}
		if !strings.Contains(strings.ToLower(detail), want) {
			t.Errorf("issuer %q rejected with %q, which does not mention %q — the message has to tell an operator what to fix",
				issuer, detail, want)
		}
	}

	accepted := []string{
		"https://idp.example.com",
		"https://idp.example.com/realms/argus",
		// http is permitted for localhost only, because that is how a local
		// Dex or Keycloak is exercised on a developer machine.
		"http://localhost:5556/dex",
		"http://127.0.0.1:5556",
	}
	for _, issuer := range accepted {
		if detail := validateProviderInput(base(issuer)); detail != "" {
			t.Errorf("issuer %q was rejected with %q, but it is valid", issuer, detail)
		}
	}
}

func TestValidateProviderInputRequiresTheFieldsAnIdPNeeds(t *testing.T) {
	full := saveIdentityProviderRequest{
		DisplayName: "Acme SSO",
		Issuer:      "https://idp.example.com",
		ClientID:    "argus",
		RedirectURI: "https://argus.example.com/api/v1/auth/sso/callback",
	}
	if detail := validateProviderInput(&full); detail != "" {
		t.Fatalf("a complete configuration was rejected: %s", detail)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*saveIdentityProviderRequest)
		want   string
	}{
		{"no display name", func(r *saveIdentityProviderRequest) { r.DisplayName = "  " }, "displayname"},
		{"no client id", func(r *saveIdentityProviderRequest) { r.ClientID = "" }, "clientid"},
		{"no redirect uri", func(r *saveIdentityProviderRequest) { r.RedirectURI = "" }, "redirecturi"},
		// A relative redirect_uri cannot be registered at an IdP and would
		// fail there with an opaque error rather than here with a clear one.
		{"relative redirect uri", func(r *saveIdentityProviderRequest) { r.RedirectURI = "/callback" }, "absolute"},
	} {
		req := full
		tc.mutate(&req)
		detail := validateProviderInput(&req)
		if detail == "" {
			t.Errorf("%s: accepted, expected a rejection", tc.name)
			continue
		}
		if !strings.Contains(strings.ToLower(strings.ReplaceAll(detail, " ", "")), tc.want) {
			t.Errorf("%s: rejected with %q, which does not mention %q", tc.name, detail, tc.want)
		}
	}
}
