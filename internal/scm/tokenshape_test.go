package scm

import "strings"
import "testing"

// TestClassicTokenRefusal covers the guardrail docs/USER_GUIDE.md §3 promised and
// the code did not implement until WORKLOG §187. The refusals and the
// deliberate ACCEPTANCES matter equally: refusing a GitHub App installation
// token, or an unfamiliar Enterprise Server format, would lock out credentials
// that are correctly scoped.
func TestClassicTokenRefusal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		token    string
		refuse   bool
		mentions string
	}{
		// Refused: reach is the whole account and cannot be sized.
		{"classic PAT", "ghp_" + strings.Repeat("A", 36), true, "classic personal access token"},
		{"OAuth app token", "gho_" + strings.Repeat("B", 36), true, "OAuth app token"},
		{"user-to-server token", "ghu_" + strings.Repeat("C", 36), true, "user-to-server"},
		{"refresh token", "ghr_" + strings.Repeat("D", 36), true, "refresh token"},
		{"pre-2021 40-hex classic", strings.Repeat("a1b2", 10), true, "hexadecimal"},

		// Accepted: fine-grained, which is what the guide asks for.
		{"fine-grained PAT", "github_pat_" + strings.Repeat("E", 60), false, ""},
		// Accepted deliberately: an App installation token is scoped to an
		// installation's granted permissions, so its reach CAN be sized. The
		// guide's objection does not apply to it.
		{"App installation token", "ghs_" + strings.Repeat("F", 36), false, ""},
		// Accepted deliberately: Enterprise Server has shipped several formats,
		// and a prefix table written against github.com must not lock out a
		// self-hosted operator on an older release.
		{"unrecognised shape", "enterprise-opaque-credential-value", false, ""},
		{"empty is handled elsewhere", "", false, ""},
		// A 40-character token that is NOT hex is not the classic format.
		{"40 chars but not hex", strings.Repeat("z", 40), false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassicTokenRefusal(tc.token)
			if tc.refuse && got == "" {
				t.Fatalf("token %q was accepted; it should be refused", tc.name)
			}
			if !tc.refuse && got != "" {
				t.Fatalf("token %q was refused (%s); it should be accepted", tc.name, got)
			}
			if tc.mentions != "" && !strings.Contains(got, tc.mentions) {
				t.Errorf("refusal does not say what the credential is — expected it to mention %q, got: %s", tc.mentions, got)
			}
			if tc.refuse && !strings.Contains(got, "fine-grained") {
				t.Errorf("a refusal must say what to do instead, and this one does not name a fine-grained token: %s", got)
			}
		})
	}
}

// The token this repository is actually tested with must not be refused, or the
// live GitOps tests would start failing on their own credential.
func TestClassicTokenRefusalAcceptsTheFineGrainedFormatInUse(t *testing.T) {
	if got := ClassicTokenRefusal("github_pat_11ABCDEFG0abcdefghijk_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"); got != "" {
		t.Errorf("a fine-grained token was refused: %s", got)
	}
}
