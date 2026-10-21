package render

import (
	"strings"
	"testing"
)

// TestParseManifests_ToleratesADuplicateMappingKey is the regression test
// for the 2026-09-09 live bug (BACKLOG.md F30's own live verification): a
// real, currently-`helm install`-able chart's Ingress template set the same
// annotation key twice (once directly, once via a merged block), and
// ParseManifests refused to parse the whole render because yaml.v3's own
// map-target decode path rejects a repeated mapping key — a stricter rule
// than real Kubernetes tooling (kubectl/helm, via sigs.k8s.io/yaml) applies,
// which tolerates it with last-value-wins, the same as JSON. A parser
// stricter than the cluster it is standing in for produces a false
// "could not verify" on a chart real operators deploy every day.
func TestParseManifests_ToleratesADuplicateMappingKey(t *testing.T) {
	manifest := `
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: farmreport
  namespace: apps
  annotations:
    nginx.ingress.kubernetes.io/configuration-snippet: "first value"
    nginx.ingress.kubernetes.io/configuration-snippet: "second value"
spec:
  rules: []
`
	objs, err := ParseManifests([]byte(manifest))
	if err != nil {
		t.Fatalf("ParseManifests returned an error for a duplicate-key document real cluster tooling accepts: %v", err)
	}
	if len(objs) != 1 {
		t.Fatalf("got %d objects, want 1", len(objs))
	}
	meta, _ := objs[0].Data["metadata"].(map[string]any)
	ann, _ := meta["annotations"].(map[string]any)
	if got := ann["nginx.ingress.kubernetes.io/configuration-snippet"]; got != "second value" {
		t.Fatalf("annotation = %v, want the LAST value (%q) — matches real Kubernetes YAML/JSON tooling's last-value-wins semantics", got, "second value")
	}
}

// TestParseManifests_StillRejectsGenuinelyBrokenYAML — the duplicate-key
// tolerance above must not widen into swallowing actual syntax errors.
func TestParseManifests_StillRejectsGenuinelyBrokenYAML(t *testing.T) {
	_, err := ParseManifests([]byte("not: valid: yaml: at: all: ["))
	if err == nil {
		t.Fatal("expected an error for a document that is not valid YAML at all")
	}
	if !strings.Contains(err.Error(), "decode document") {
		t.Fatalf("error = %v, want it to name which document failed", err)
	}
}

// TestParseManifests_DuplicateKeyInsideANestedList — the same tolerance
// must apply at any nesting depth, not just the top-level document map,
// since the live bug's duplicate was inside metadata.annotations, itself
// nested under a list of documents.
func TestParseManifests_DuplicateKeyInsideANestedList(t *testing.T) {
	manifest := `
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
  namespace: default
data:
  items:
    - key: a
      key: b
`
	objs, err := ParseManifests([]byte(manifest))
	if err != nil {
		t.Fatalf("ParseManifests returned an error for a duplicate key nested inside a list: %v", err)
	}
	if len(objs) != 1 {
		t.Fatalf("got %d objects, want 1", len(objs))
	}
}
