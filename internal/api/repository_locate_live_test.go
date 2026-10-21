package api

import (
	"context"
	"os"
	"strings"
	"testing"

	"argus/internal/gitops"
	"argus/internal/scm"
)

// TestLocateObjectFileLive proves ARGUS can find, for itself, which file defines
// an object — the capability that turns the pull-request route from
// "human names the file" into something an analysis could drive.
//
// Gated like the other live GitOps tests:
//
//	ARGUS_GITOPS_LIVE=1 ARGUS_GITOPS_TOKEN=$(cat ~/argus-test-token) \
//	  ARGUS_GITOPS_REVISION=<what Argo reports synced> \
//	  go test ./internal/api/ -run TestLocateObjectFileLive -v
func TestLocateObjectFileLive(t *testing.T) {
	if os.Getenv("ARGUS_GITOPS_LIVE") != "1" {
		t.Skip("set ARGUS_GITOPS_LIVE=1 to run the network-dependent clone")
	}
	token := os.Getenv("ARGUS_GITOPS_TOKEN")
	revision := os.Getenv("ARGUS_GITOPS_REVISION")
	if token == "" || revision == "" {
		t.Skip("ARGUS_GITOPS_TOKEN and ARGUS_GITOPS_REVISION are required")
	}
	provider := &scm.GitHub{Token: token, UserAgent: "argus-locate-live-test"}
	binding := scm.Binding{Host: "github.com"}
	repoURL := liveRepoURL(t)

	t.Run("finds the single file that declares the object", func(t *testing.T) {
		got, err := locateObjectFile(context.Background(), provider, binding, repoURL, revision, "apps/nolimits",
			gitops.ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "argus-gitops-rke2", Name: "nolimits"})
		if err != nil {
			t.Fatalf("locateObjectFile: %v", err)
		}
		if got.Path != "apps/nolimits/deployment.yaml" {
			t.Errorf("Path = %q, want apps/nolimits/deployment.yaml", got.Path)
		}
		t.Logf("located %s (doc %d) after reading %d yaml file(s)", got.Path, got.DocIndex, got.FilesScanned)
	})

	t.Run("finds the right document in a multi-document file", func(t *testing.T) {
		// apps/web/deployment.yaml holds a ConfigMap AND a Deployment, so the
		// document index is the interesting part: a fix aimed at the Deployment
		// must not be applied to the ConfigMap that shares its file.
		got, err := locateObjectFile(context.Background(), provider, binding, repoURL, revision, "apps/web",
			gitops.ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "argus-gitops-rke2", Name: "web"})
		if err != nil {
			t.Fatalf("locateObjectFile: %v", err)
		}
		if got.Path != "apps/web/deployment.yaml" {
			t.Errorf("Path = %q", got.Path)
		}
		if got.DocIndex != 1 {
			t.Errorf("DocIndex = %d, want 1 — the Deployment is the second document, after the ConfigMap", got.DocIndex)
		}
	})

	t.Run("refuses rather than guessing when the object is not declared there", func(t *testing.T) {
		// A real and interesting state: the object exists in the cluster but is
		// rendered by a chart rather than written out. Widening the search would
		// turn "not here" into "something with this name elsewhere".
		_, err := locateObjectFile(context.Background(), provider, binding, repoURL, revision, "apps/nolimits",
			gitops.ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "argus-gitops-rke2", Name: "does-not-exist"})
		if err == nil {
			t.Fatal("an absent object was reported as located")
		}
		// Asserted on the message, not merely on err != nil. The first run of
		// this test passed while the clone itself was failing for an unrelated
		// reason — "an error occurred" is satisfied by any bug upstream of the
		// behaviour under test.
		if !strings.Contains(err.Error(), "does-not-exist") || !strings.Contains(err.Error(), "none defines it") {
			t.Errorf("refusal does not describe the search that failed: %v", err)
		}
		t.Logf("refusal: %v", err)
	})

	t.Run("refuses without a pinned revision", func(t *testing.T) {
		// Searching a moving branch finds a file whose content is not what is
		// running, which is the same rule ProposeChanges enforces.
		if _, err := locateObjectFile(context.Background(), provider, binding, repoURL, "", "apps/nolimits",
			gitops.ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "argus-gitops-rke2", Name: "nolimits"}); err == nil {
			t.Fatal("an unpinned search was allowed")
		}
	})
}
