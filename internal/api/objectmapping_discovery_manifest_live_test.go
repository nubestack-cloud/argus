package api

// TestDiscoverManifestLink_Live proves BACKLOG.md F30's plain-manifest
// discovery against a REAL registered repository containing REAL plain YAML
// manifests — no Helm chart, no Kustomize overlay, and (unlike the Helm-mode
// discoverRepositoryLink) no render sandbox involved at all: parsing a
// checked-out file directly IS the proof (discoverManifestLink's own doc
// comment explains why no sandbox is needed). Gated exactly like this
// repo's other live GitOps tests (internal/gitops/live_test.go,
// internal/api/repository_locate_live_test.go): network-dependent, so
// skipped unless ARGUS_GITOPS_LIVE=1. Also needs ARGUS_TEST_DATABASE_URL,
// gated by helmLinkTestPool (objectmapping_link_endpoints_db_test.go) — a
// real repository_bindings row is registered and read back through it.
//
// Fixture: the repository ARGUS_GITOPS_REPO names (MEMORY.md's
// project-gitops-test-infra, the same repo repository_locate_live_test.go
// already uses) — apps/nolimits/deployment.yaml declares a bare Deployment
// named "nolimits" in namespace "argus-gitops-rke2", and apps/web/deployment.yaml
// declares a ConfigMap AND a Deployment named "web" in the SAME file. No
// Chart.yaml or kustomization.yaml exists anywhere in the repository: this
// is a real plain-manifest object, not a fixture built to resemble one.
//
// Run:
//
//	ARGUS_GITOPS_LIVE=1 ARGUS_GITOPS_TOKEN="$(cat ~/argus-test-token)" \
//	ARGUS_TEST_DATABASE_URL="postgres://argus_app:dev-local-password@127.0.0.1:5432/argus?sslmode=disable" \
//	  go test ./internal/api/ -run TestDiscoverManifestLink_Live -v
import (
	"os"
	"testing"

	"argus/internal/repotools"
	"argus/internal/scm"
	"argus/internal/secretbox"
)

func TestDiscoverManifestLink_Live(t *testing.T) {
	if os.Getenv("ARGUS_GITOPS_LIVE") != "1" {
		t.Skip("set ARGUS_GITOPS_LIVE=1 (ARGUS_GITOPS_TOKEN) to run this network-dependent live proof")
	}
	token := os.Getenv("ARGUS_GITOPS_TOKEN")
	if token == "" {
		t.Skip("ARGUS_GITOPS_TOKEN is required")
	}

	pool := helmLinkTestPool(t) // also gates/skips on ARGUS_TEST_DATABASE_URL
	ctx, tx, tenantID := helmLinkTx(t, pool)
	// helmLinkTx's own t.Cleanup rolls this transaction back — the binding
	// registered below is never committed, so this test leaves nothing
	// behind for the real tenant.

	kek, err := secretbox.GenerateLocalKEK()
	if err != nil {
		t.Fatalf("GenerateLocalKEK: %v", err)
	}
	keeper, err := secretbox.NewLocalKeeper(kek)
	if err != nil {
		t.Fatalf("NewLocalKeeper: %v", err)
	}
	store := scm.NewStore(keeper)

	repoURL := liveRepoURL(t)
	if _, err := store.SaveBinding(ctx, tx, tenantID, scm.Binding{
		Provider: "github", URL: repoURL,
	}, []byte(token)); err != nil {
		t.Fatalf("SaveBinding: %v", err)
	}

	s := &Server{scmStore: store, checkouts: repotools.NewCheckouts()}

	t.Run("finds a plain manifest object with no Helm chart or Kustomize overlay in the repository", func(t *testing.T) {
		result := s.discoverManifestLink(ctx, tx, "apps/v1/Deployment", "argus-gitops-rke2", "nolimits")
		if result.Status != "proven" {
			t.Fatalf("Status = %q (degraded=%q), want proven — candidates=%+v", result.Status, result.Degraded, result.Candidates)
		}
		if len(result.Candidates) != 1 || result.Candidates[0].ChartPath != "apps/nolimits/deployment.yaml" {
			t.Fatalf("Candidates = %+v, want exactly apps/nolimits/deployment.yaml", result.Candidates)
		}
		if result.Candidates[0].RepoURL != repoURL {
			t.Errorf("RepoURL = %q, want %q", result.Candidates[0].RepoURL, repoURL)
		}
	})

	t.Run("finds the right object out of a multi-document file", func(t *testing.T) {
		result := s.discoverManifestLink(ctx, tx, "apps/v1/Deployment", "argus-gitops-rke2", "web")
		if result.Status != "proven" {
			t.Fatalf("Status = %q (degraded=%q), want proven", result.Status, result.Degraded)
		}
		if len(result.Candidates) != 1 || result.Candidates[0].ChartPath != "apps/web/deployment.yaml" {
			t.Fatalf("Candidates = %+v, want exactly apps/web/deployment.yaml", result.Candidates)
		}
	})

	t.Run("an object nothing declares is a real none, not a guess", func(t *testing.T) {
		result := s.discoverManifestLink(ctx, tx, "apps/v1/Deployment", "argus-gitops-rke2", "does-not-exist-at-all")
		if result.Status != "none" {
			t.Fatalf("Status = %q (degraded=%q), want none", result.Status, result.Degraded)
		}
	})
}
