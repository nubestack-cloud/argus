package gitops

import (
	"os"
	"path/filepath"
	"testing"
)

// writeRepo materialises a fake repo tree from path->content pairs.
func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

// The exact shape of the repo ARGUS is already pointed at live: Argo CD's
// example-apps guestbook directory, whose manifests declare no namespace (it
// comes from the Application's destination instead).
const guestbookDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: guestbook-ui
spec:
  replicas: 1
  template:
    spec:
      containers:
      - image: gcr.io/heptio-images/ks-guestbook-demo:0.2
        name: guestbook-ui
        ports:
        - containerPort: 80
`

const guestbookService = `apiVersion: v1
kind: Service
metadata:
  name: guestbook-ui
spec:
  ports:
  - port: 80
    targetPort: 80
  selector:
    app: guestbook-ui
`

func TestLocate_FindsDeploymentInRealRepoShape(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"guestbook/guestbook-ui-deployment.yaml": guestbookDeployment,
		"guestbook/guestbook-ui-svc.yaml":        guestbookService,
		"README.md":                              "not yaml",
	})

	res, err := Locate(root, ObjectRef{
		APIVersion: "apps/v1", Kind: "Deployment",
		Namespace: "argus-e2e-rke2", Name: "guestbook-ui",
	})
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if len(res.Locations) != 1 {
		t.Fatalf("got %d locations, want 1: %+v", len(res.Locations), res.Locations)
	}
	if res.Locations[0].Path != "guestbook/guestbook-ui-deployment.yaml" {
		t.Errorf("Path = %q", res.Locations[0].Path)
	}
	// The Service shares the object's NAME. Matching on name alone would have
	// returned both, and an edit to the Service would be a silent wrong fix.
	if res.FilesScanned != 2 {
		t.Errorf("FilesScanned = %d, want 2 (both YAML files parsed, README skipped)", res.FilesScanned)
	}
}

// TestLocate_NamespacelessManifestMatches is the case that decides whether this
// works on real GitOps repos at all: manifests overwhelmingly omit the
// namespace, because it is supplied at apply time by the Argo Application's
// destination or a Flux targetNamespace. Requiring it to match would fail to
// find the source file for most real objects.
func TestLocate_NamespacelessManifestMatches(t *testing.T) {
	root := writeRepo(t, map[string]string{"d.yaml": guestbookDeployment})
	res, err := Locate(root, ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "anything-at-all", Name: "guestbook-ui"})
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if len(res.Locations) != 1 {
		t.Fatalf("a manifest with no namespace must match a live object in any namespace; got %d", len(res.Locations))
	}
}

// But an explicit namespace in the manifest is honoured — there the repo is
// unambiguous about where the object goes.
func TestLocate_ExplicitNamespaceMustMatch(t *testing.T) {
	manifest := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: production
`
	root := writeRepo(t, map[string]string{"d.yaml": manifest})
	if res, _ := Locate(root, ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "staging", Name: "web"}); len(res.Locations) != 0 {
		t.Errorf("a manifest pinned to production must not match a staging object")
	}
	if res, _ := Locate(root, ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "production", Name: "web"}); len(res.Locations) != 1 {
		t.Errorf("the matching namespace should match")
	}
}

// TestLocate_MultiDocumentFileReportsDocIndex — multi-document files are the
// norm in GitOps repos, so the file alone is not a precise enough answer to
// edit from.
func TestLocate_MultiDocumentFileReportsDocIndex(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"all.yaml": guestbookService + "---\n" + guestbookDeployment,
	})
	res, err := Locate(root, ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Name: "guestbook-ui"})
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if len(res.Locations) != 1 {
		t.Fatalf("got %d locations, want 1", len(res.Locations))
	}
	if res.Locations[0].DocIndex != 1 {
		t.Errorf("DocIndex = %d, want 1 (the Deployment is the second document)", res.Locations[0].DocIndex)
	}
	if res.Locations[0].Line <= 1 {
		t.Errorf("Line = %d, want the line the second document starts on", res.Locations[0].Line)
	}
}

// TestLocate_ReportsEveryMatch: a base plus an overlay legitimately define the
// same object. Returning one silently would mean editing the wrong file about
// as often as the right one.
func TestLocate_ReportsEveryMatch(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"base/d.yaml":          guestbookDeployment,
		"overlays/prod/d.yaml": guestbookDeployment,
	})
	res, err := Locate(root, ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Name: "guestbook-ui"})
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if len(res.Locations) != 2 {
		t.Fatalf("got %d locations, want both — an ambiguous answer must be visible, not resolved by guessing", len(res.Locations))
	}
}

// TestLocate_ApiVersionMatchesAcrossVersionBump: a repo pinned at apps/v1beta2
// still defines the object the cluster now serves as apps/v1. Refusing to match
// would make the source unfindable exactly when someone needs to update it.
func TestLocate_ApiVersionMatchesAcrossVersionBump(t *testing.T) {
	root := writeRepo(t, map[string]string{"d.yaml": `apiVersion: apps/v1beta2
kind: Deployment
metadata:
  name: web
`})
	res, _ := Locate(root, ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Name: "web"})
	if len(res.Locations) != 1 {
		t.Errorf("want a match across an apiVersion bump within the same group; got %d", len(res.Locations))
	}
}

// But a genuinely different API GROUP must not match — same Kind name in a
// different group is a different object.
func TestLocate_DifferentApiGroupDoesNotMatch(t *testing.T) {
	root := writeRepo(t, map[string]string{"x.yaml": `apiVersion: example.com/v1
kind: Deployment
metadata:
  name: web
`})
	res, _ := Locate(root, ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Name: "web"})
	if len(res.Locations) != 0 {
		t.Errorf("a Deployment in example.com must not match apps/v1; got %d", len(res.Locations))
	}
}

func TestLocate_SkipsGitDirAndSymlinks(t *testing.T) {
	root := writeRepo(t, map[string]string{
		".git/objects/x.yaml": guestbookDeployment,
		"real.yaml":           guestbookService,
	})
	// A symlink pointing outside the tree must never be read.
	outside := filepath.Join(t.TempDir(), "secret.yaml")
	if err := os.WriteFile(outside, []byte(guestbookDeployment), 0o644); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link.yaml")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	res, err := Locate(root, ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Name: "guestbook-ui"})
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if len(res.Locations) != 0 {
		t.Errorf("found %+v — .git contents and symlinked-outside files must not be read", res.Locations)
	}
}

func TestLocate_BrokenYAMLDoesNotHideOtherFiles(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"broken.yaml": "{{ this is a helm template, not valid yaml }}}\n",
		"good.yaml":   guestbookDeployment,
	})
	res, err := Locate(root, ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Name: "guestbook-ui"})
	if err != nil {
		t.Fatalf("Locate: %v", err)
	}
	if len(res.Locations) != 1 {
		t.Errorf("one unparseable file must not make other files' objects unlocatable; got %d", len(res.Locations))
	}
}

func TestLocateIn_ScopingResolvesTheRealAmbiguity(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"guestbook/guestbook-ui-deployment.yaml":           guestbookDeployment,
		"kustomize-guestbook/guestbook-ui-deployment.yaml": guestbookDeployment,
	})
	ref := ObjectRef{APIVersion: "apps/v1", Kind: "Deployment", Name: "guestbook-ui"}

	if all, _ := Locate(root, ref); len(all.Locations) != 2 {
		t.Fatalf("unscoped should find both definitions; got %d", len(all.Locations))
	}
	scoped, err := LocateIn(root, "guestbook", ref)
	if err != nil {
		t.Fatalf("LocateIn: %v", err)
	}
	if len(scoped.Locations) != 1 {
		t.Fatalf("scoping to the Application's path should find exactly one; got %d", len(scoped.Locations))
	}
	// Path must remain REPOSITORY-root-relative even though the walk was
	// scoped, or it is not usable for editing or citation.
	if scoped.Locations[0].Path != "guestbook/guestbook-ui-deployment.yaml" {
		t.Errorf("Path = %q, want it relative to the repo root, not the subdir", scoped.Locations[0].Path)
	}
}

// A controller-reported path that escapes the repo is refused, not clamped —
// the value comes from a cluster object, so silently correcting a traversal
// attempt would hide it.
func TestLocateIn_RefusesPathTraversal(t *testing.T) {
	root := writeRepo(t, map[string]string{"d.yaml": guestbookDeployment})
	for _, bad := range []string{"../..", "guestbook/../../etc", "/etc"} {
		if _, err := LocateIn(root, bad, ObjectRef{Kind: "Deployment", Name: "guestbook-ui"}); err == nil {
			t.Errorf("LocateIn(subdir=%q) = nil error, want a refusal", bad)
		}
	}
}

// A path that does not exist at this revision is reported, NOT silently widened
// back to the whole repo — which would reintroduce the ambiguity scoping exists
// to remove.
func TestLocateIn_MissingPathIsReportedNotWidened(t *testing.T) {
	root := writeRepo(t, map[string]string{"guestbook/d.yaml": guestbookDeployment})
	_, err := LocateIn(root, "does-not-exist", ObjectRef{Kind: "Deployment", Name: "guestbook-ui"})
	if err == nil {
		t.Error("a path absent at this revision must be reported, not quietly widened to a whole-repo search")
	}
}
