package gitops

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStageB_LiveEndToEnd clones the REAL repo at the exact commit ARGUS
// resolved live (WORKLOG §121) and locates the source file for the real
// Deployment. Network-dependent, so skipped unless ARGUS_GITOPS_LIVE=1.
func TestStageB_LiveEndToEnd(t *testing.T) {
	if os.Getenv("ARGUS_GITOPS_LIVE") != "1" {
		t.Skip("set ARGUS_GITOPS_LIVE=1 to run the network-dependent live clone")
	}
	dir := filepath.Join(t.TempDir(), "clone")
	repo, err := Clone(t.Context(), CloneOptions{
		RepoURL:      "https://github.com/argoproj/argocd-example-apps.git",
		Revision:     "8088f4c0d970abb09e250248cc97e35623447cb5",
		Dir:          dir,
		SparsePaths:  []string{"guestbook"},
		AllowedHosts: []string{"github.com"},
	})
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	head, err := HeadCommit(repo)
	if err != nil {
		t.Fatalf("HeadCommit: %v", err)
	}
	t.Logf("cloned, HEAD = %s", head)

	// Scoped to the Application's own spec.source.path, exactly as milestone 2.0 reports it.
	res, err := LocateIn(dir, "guestbook", ObjectRef{
		APIVersion: "apps/v1", Kind: "Deployment",
		Namespace: "argus-e2e-rke2", Name: "guestbook-ui",
	})
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	t.Logf("scanned %d yaml files, found %d location(s)", res.FilesScanned, len(res.Locations))
	if len(res.Locations) == 0 {
		t.Fatal("did not find the Deployment's source file in the real repo")
	}
	for _, l := range res.Locations {
		t.Logf("  -> %s (doc %d, line %d)", l.Path, l.DocIndex, l.Line)
		// The file the editor would be seeded with, and the document within it
		// that declares this object — the only two questions discovery answers
		// now that a change is a whole-file edit rather than a field path.
		content, err := os.ReadFile(filepath.Join(dir, l.Path))
		if err != nil {
			t.Fatalf("read located file: %v", err)
		}
		doc, err := SoleDocumentFor(content, ObjectRef{
			APIVersion: "apps/v1", Kind: "Deployment",
			Namespace: "argus-e2e-rke2", Name: "guestbook-ui",
		}, l.Path)
		if err != nil {
			t.Fatalf("SoleDocumentFor: %v", err)
		}
		t.Logf("     declares the object in document %d of %d bytes", doc, len(content))
	}
}
