package scm

import (
	"context"
	"testing"

	"argus/internal/outbound"
)

// TestGitHubGitLab_DefaultClientRefusesSSRFTargets proves the repositories
// caller (lld/01-threat-model.md T6/T15/SR-9 — a RepositoryBinding's
// admin-configured BaseURL, self-hosted GHES/GitLab included) adopted
// internal/outbound's hardened transport for its real, non-test client
// path: GitHub/GitLab with no HTTPClient injected, which is exactly how
// internal/scm/store.go constructs both providers in production
// (store.go's resolve, lines building &GitHub{...}/&GitLab{...} with no
// HTTPClient field set).
func TestGitHubGitLab_DefaultClientRefusesSSRFTargets(t *testing.T) {
	ctx := context.Background()

	gh := &GitHub{BaseURL: "http://169.254.169.254", Token: "t"}
	if _, err := gh.ReadFile(ctx, Repo{Owner: "o", Name: "n"}, "main", "f.yaml"); err == nil || !outbound.IsRefusal(err) {
		t.Fatalf("expected GitHub's default client to refuse a metadata BaseURL, got: %v", err)
	}

	gl := &GitLab{BaseURL: "http://10.9.9.9", Token: "t"}
	if _, err := gl.ReadFile(ctx, Repo{Owner: "o", Name: "n"}, "main", "f.yaml"); err == nil || !outbound.IsRefusal(err) {
		t.Fatalf("expected GitLab's default client to refuse a private-range BaseURL, got: %v", err)
	}
}
