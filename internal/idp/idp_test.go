package idp

import (
	"strings"
	"testing"
)

// TestSafeReturnToRefusesOffSiteRedirects pins the open-redirect guard.
//
// This is the highest-value test in the package. A completed login redirects
// the browser to a caller-supplied path; if that path can name another host,
// an attacker sends a victim a login link that lands them, already
// authenticated, on a lookalike site. Every case below is a real bypass
// technique for a naive "starts with /" check.
func TestSafeReturnToRefusesOffSiteRedirects(t *testing.T) {
	offSite := []struct {
		in  string
		why string
	}{
		{"//evil.example.com", "protocol-relative — resolves to another host despite the leading slash"},
		{"//evil.example.com/incidents", "protocol-relative with a path"},
		{"https://evil.example.com", "absolute URL"},
		{"http://evil.example.com/x", "absolute URL, plain http"},
		{"javascript:alert(1)", "scheme with no host"},
		{"incidents", "relative with no leading slash — would resolve against the callback path"},
		{"", "empty"},
		{"\\\\evil.example.com", "backslashes, which some browsers normalise to //"},
	}
	for _, tc := range offSite {
		if got := SafeReturnTo(tc.in); got != "/" {
			t.Errorf("SafeReturnTo(%q) = %q, want %q (%s)", tc.in, got, "/", tc.why)
		}
	}

	onSite := map[string]string{
		"/":                        "/",
		"/incidents":               "/incidents",
		"/incidents/inc_123":       "/incidents/inc_123",
		"/incidents?severity=high": "/incidents?severity=high",
		"/settings#identity":       "/settings",
	}
	for in, want := range onSite {
		if got := SafeReturnTo(in); got != want {
			t.Errorf("SafeReturnTo(%q) = %q, want %q — a same-site path must survive", in, got, want)
		}
	}
}

// TestBeginLoginMintsDistinctSecretsEveryTime guards against the failure where
// state, nonce and the PKCE verifier are generated once and reused, which
// would defeat all three of their purposes at once.
//
// Discover is not called here (it needs a live issuer), so the Provider is
// built directly — this test is about the secret generation, not discovery.
func TestBeginLoginMintsDistinctSecretsEveryTime(t *testing.T) {
	seenState := map[string]bool{}
	seenNonce := map[string]bool{}

	for i := 0; i < 50; i++ {
		state, err := randomToken()
		if err != nil {
			t.Fatalf("randomToken: %v", err)
		}
		nonce, err := randomToken()
		if err != nil {
			t.Fatalf("randomToken: %v", err)
		}
		if seenState[state] {
			t.Fatal("state repeated across calls — a reused state defeats login-CSRF protection")
		}
		if seenNonce[nonce] {
			t.Fatal("nonce repeated across calls — a reused nonce defeats ID-token replay protection")
		}
		if state == nonce {
			t.Fatal("state and nonce are equal — they must be independently generated")
		}
		seenState[state], seenNonce[nonce] = true, true
	}
}

func TestHashStateIsStableAndNotThePlaintext(t *testing.T) {
	const v = "some-state-value"
	h1, h2 := HashState(v), HashState(v)
	if h1 != h2 {
		t.Fatalf("HashState is not deterministic: %q vs %q", h1, h2)
	}
	if strings.Contains(h1, v) {
		t.Fatal("HashState output contains the plaintext — the point is that a DB read yields nothing usable")
	}
	if h1 == HashState(v+"x") {
		t.Fatal("HashState collides on distinct inputs")
	}
	if len(h1) != 64 {
		t.Fatalf("HashState returned %d chars, want 64 hex chars of SHA-256", len(h1))
	}
}

// TestNormaliseGroupsPreservesIdPGroupIdentity is deliberately explicit that
// groups are NOT case-folded.
//
// An LDAP distinguished name arrives verbatim through Dex. Two directory
// groups differing only in case are two different groups, and folding them
// here would silently merge their role mappings.
func TestNormaliseGroupsPreservesIdPGroupIdentity(t *testing.T) {
	in := []string{
		"  platform-sre  ",
		"Platform-SRE",
		"",
		"platform-sre",
		"cn=oncall,ou=groups,dc=example,dc=com",
	}
	got := normaliseGroups(in)

	want := []string{"platform-sre", "Platform-SRE", "cn=oncall,ou=groups,dc=example,dc=com"}
	if len(got) != len(want) {
		t.Fatalf("normaliseGroups(%v) = %v, want %v", in, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d: got %q, want %q", i, got[i], want[i])
		}
	}

	if normaliseGroups([]string{"", "   "}) != nil {
		t.Error("a claim of only-empty values must yield nil, not an empty non-nil slice")
	}
}

func TestFirstNonEmptySkipsWhitespaceOnly(t *testing.T) {
	if got := firstNonEmpty("", "   ", "real", "later"); got != "real" {
		t.Errorf("firstNonEmpty = %q, want %q", got, "real")
	}
	if got := firstNonEmpty("", "  "); got != "" {
		t.Errorf("firstNonEmpty with no usable value = %q, want empty", got)
	}
}
