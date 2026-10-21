package render

import (
	"strings"
	"testing"
)

// These are exactly what BACKLOG.md F26 asks be unit-testable without a
// cluster or a renderer: given two already-rendered manifest sets, correctly
// tell "no effective change" apart from "real change". No helm/kustomize
// binary, no Kubernetes API, nothing but two byte slices in and a Result out.

func TestCompareManifests_IdenticalRendersAreNotEffective(t *testing.T) {
	manifest := `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: cache
  namespace: argus-gitops-rke2
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: cache
        image: busybox:1.36
`
	res, err := CompareManifests("helm", []byte(manifest), []byte(manifest))
	if err != nil {
		t.Fatalf("CompareManifests: %v", err)
	}
	if res.Effective {
		t.Fatalf("identical renders must not be Effective, got %+v", res)
	}
	if res.ObjectsTotal != 1 {
		t.Fatalf("expected 1 object compared, got %d", res.ObjectsTotal)
	}
	if len(res.Changed) != 0 {
		t.Fatalf("expected no changed objects, got %v", res.Changed)
	}
	if !strings.Contains(res.Summary, "does not change") {
		t.Fatalf("summary should say the edit does not change anything, got %q", res.Summary)
	}
}

// This is the values-file-precedence shape in miniature: the SOURCE differs
// (that's a given — a proposal only exists because a file changed) but the
// two RENDERS are what actually matters, and here they still agree — exactly
// what happens when an edit lands in a values file a later one overrides.
func TestCompareManifests_SameFinalValueDespiteDifferentSource(t *testing.T) {
	original := `
apiVersion: apps/v1
kind: Deployment
metadata: {name: cache, namespace: ns}
spec: {replicas: 3}
`
	// Different key ORDER and an added comment-equivalent field ordering only
	// — still the same object once decoded. Proves the comparison is
	// semantic, not textual.
	proposed := `
apiVersion: apps/v1
kind: Deployment
spec: {replicas: 3}
metadata: {namespace: ns, name: cache}
`
	res, err := CompareManifests("helm", []byte(original), []byte(proposed))
	if err != nil {
		t.Fatalf("CompareManifests: %v", err)
	}
	if res.Effective {
		t.Fatalf("reordered-but-equal YAML must not read as an effective change, got %+v", res)
	}
}

func TestCompareManifests_ChangedFieldIsEffective(t *testing.T) {
	original := `
apiVersion: apps/v1
kind: Deployment
metadata: {name: cache, namespace: ns}
spec: {replicas: 3}
`
	proposed := `
apiVersion: apps/v1
kind: Deployment
metadata: {name: cache, namespace: ns}
spec: {replicas: 5}
`
	res, err := CompareManifests("helm", []byte(original), []byte(proposed))
	if err != nil {
		t.Fatalf("CompareManifests: %v", err)
	}
	if !res.Effective {
		t.Fatalf("a genuinely different replica count must be Effective")
	}
	if len(res.Changed) != 1 {
		t.Fatalf("expected exactly 1 changed object, got %v", res.Changed)
	}
	if res.Changed[0].Status != "changed" {
		t.Fatalf("expected status 'changed', got %q", res.Changed[0].Status)
	}
	want := "spec.replicas: 3 -> 5"
	if len(res.Changed[0].FieldDiffs) != 1 || res.Changed[0].FieldDiffs[0] != want {
		t.Fatalf("expected field diff %q, got %v", want, res.Changed[0].FieldDiffs)
	}
	if !strings.Contains(res.Summary, "changes what the cluster would run") {
		t.Fatalf("summary should say the edit changes the cluster, got %q", res.Summary)
	}
}

func TestCompareManifests_AddedAndRemovedObjects(t *testing.T) {
	original := `
apiVersion: v1
kind: ConfigMap
metadata: {name: a, namespace: ns}
data: {k: v}
`
	proposed := `
apiVersion: v1
kind: ConfigMap
metadata: {name: b, namespace: ns}
data: {k: v}
`
	res, err := CompareManifests("kustomize", []byte(original), []byte(proposed))
	if err != nil {
		t.Fatalf("CompareManifests: %v", err)
	}
	if !res.Effective {
		t.Fatalf("swapping one object for another must be Effective")
	}
	if len(res.Changed) != 2 {
		t.Fatalf("expected 2 diffs (one added, one removed), got %v", res.Changed)
	}
	statuses := map[string]int{}
	for _, d := range res.Changed {
		statuses[d.Status]++
	}
	if statuses["added"] != 1 || statuses["removed"] != 1 {
		t.Fatalf("expected one added and one removed, got %v", statuses)
	}
}

func TestCompareManifests_MultiDocumentAndEmptyDocuments(t *testing.T) {
	// Helm's own idiom: `---` separators with nothing between some of them
	// (an `if` block that didn't fire for this render).
	original := `
---
apiVersion: v1
kind: ConfigMap
metadata: {name: a, namespace: ns}
data: {k: "1"}
---
---
apiVersion: v1
kind: ConfigMap
metadata: {name: b, namespace: ns}
data: {k: "2"}
`
	proposed := `
---
apiVersion: v1
kind: ConfigMap
metadata: {name: a, namespace: ns}
data: {k: "1"}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: b, namespace: ns}
data: {k: "9"}
`
	res, err := CompareManifests("helm", []byte(original), []byte(proposed))
	if err != nil {
		t.Fatalf("CompareManifests: %v", err)
	}
	if res.ObjectsTotal != 2 {
		t.Fatalf("expected 2 objects (empty documents skipped), got %d", res.ObjectsTotal)
	}
	if !res.Effective || len(res.Changed) != 1 {
		t.Fatalf("expected exactly one changed object, got %+v", res)
	}
}

func TestCompareManifests_NoObjectsIsDegradedNotClean(t *testing.T) {
	res, err := CompareManifests("helm", []byte(""), []byte(""))
	if err != nil {
		t.Fatalf("CompareManifests: %v", err)
	}
	if res.Effective {
		t.Fatalf("no objects at all cannot be 'effective'")
	}
	if !strings.Contains(res.Summary, "not a clean verification") {
		t.Fatalf("an empty render must be flagged as degraded, not reported as a clean 'no change', got %q", res.Summary)
	}
}

func TestCompareManifests_MalformedRenderIsAnError(t *testing.T) {
	_, err := CompareManifests("helm", []byte("not: valid: yaml: at: all: ["), []byte(""))
	if err == nil {
		t.Fatalf("expected an error for a render that doesn't parse as YAML")
	}
}

func TestDetectKind(t *testing.T) {
	cases := []struct {
		name string
		tree map[string][]byte
		want Kind
	}{
		{"helm chart", map[string][]byte{"Chart.yaml": []byte("x"), "values.yaml": []byte("x")}, KindHelm},
		{"kustomize overlay", map[string][]byte{"kustomization.yaml": []byte("x")}, KindKustomize},
		{"kustomize yml", map[string][]byte{"kustomization.yml": []byte("x")}, KindKustomize},
		{"plain yaml, no renderer", map[string][]byte{"deployment.yaml": []byte("x")}, KindUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DetectKind(tc.tree); got != tc.want {
				t.Fatalf("DetectKind() = %q, want %q", got, tc.want)
			}
		})
	}
}
