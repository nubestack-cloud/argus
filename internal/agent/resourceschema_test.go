package agent

import (
	"reflect"
	"sort"
	"testing"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// realisticDeploymentGVDoc is a trimmed but structurally real OpenAPI v3
// GroupVersion document (apis/apps/v1), captured live against this project's
// own rke2 test cluster (`kubectl get --raw '/openapi/v3/apis/apps/v1'`) and
// cut down to the one definition this test needs — the exact shape
// topLevelFieldsFromGVDoc must parse correctly.
func realisticDeploymentGVDoc() map[string]any {
	return map[string]any{
		"components": map[string]any{
			"schemas": map[string]any{
				"io.k8s.api.apps.v1.Deployment": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"apiVersion": map[string]any{"type": "string"},
						"kind":       map[string]any{"type": "string"},
						"metadata":   map[string]any{},
						"spec":       map[string]any{},
						"status":     map[string]any{},
					},
					"x-kubernetes-group-version-kind": []any{
						map[string]any{"group": "apps", "version": "v1", "kind": "Deployment"},
					},
				},
				// A sibling definition in the SAME document with no
				// x-kubernetes-group-version-kind tag at all (DeploymentSpec,
				// DeploymentStrategy, etc. in the real document) — must be
				// silently skipped, not mistaken for a match.
				"io.k8s.api.apps.v1.DeploymentSpec": map[string]any{
					"type":       "object",
					"properties": map[string]any{"replicas": map[string]any{"type": "integer"}},
				},
			},
		},
	}
}

func TestTopLevelFieldsFromGVDoc_MatchesByGVKTagNotByName(t *testing.T) {
	fields, found := topLevelFieldsFromGVDoc(realisticDeploymentGVDoc(), schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"})
	if !found {
		t.Fatal("expected Deployment's schema to be found")
	}
	sort.Strings(fields)
	want := []string{"apiVersion", "kind", "metadata", "spec", "status"}
	sort.Strings(want)
	if !reflect.DeepEqual(fields, want) {
		t.Errorf("fields = %v, want %v", fields, want)
	}
}

// TestTopLevelFieldsFromGVDoc_RejectsAFieldRealDefectShape is B147's own
// regression test at the pure-function level: confirms the exact check that
// would have caught the live defect — a document proposing a top-level
// "syncPolicy" key, which is not one of Deployment's own schema properties,
// is NOT present in the returned field list, so a caller comparing the
// proposed document's own keys against this list correctly flags it as
// unknown.
func TestTopLevelFieldsFromGVDoc_RejectsAFieldRealDefectShape(t *testing.T) {
	fields, found := topLevelFieldsFromGVDoc(realisticDeploymentGVDoc(), schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"})
	if !found {
		t.Fatal("expected Deployment's schema to be found")
	}
	for _, f := range fields {
		if f == "syncPolicy" {
			t.Fatal("syncPolicy must not appear in Deployment's own schema fields — it belongs to the Argo CD Application resource, not a Deployment (PROJECT.md B147)")
		}
	}
}

func TestTopLevelFieldsFromGVDoc_UnknownKind_NotFound(t *testing.T) {
	_, found := topLevelFieldsFromGVDoc(realisticDeploymentGVDoc(), schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "StatefulSet"})
	if found {
		t.Error("expected StatefulSet to be reported not-found in a document that only defines Deployment")
	}
}

func TestTopLevelFieldsFromGVDoc_WrongGroupOrVersion_NotFound(t *testing.T) {
	for _, gvk := range []schema.GroupVersionKind{
		{Group: "extensions", Version: "v1", Kind: "Deployment"}, // wrong group
		{Group: "apps", Version: "v1beta1", Kind: "Deployment"},  // wrong version
	} {
		if _, found := topLevelFieldsFromGVDoc(realisticDeploymentGVDoc(), gvk); found {
			t.Errorf("gvk %+v: expected not-found for a group/version mismatch", gvk)
		}
	}
}

func TestTopLevelFieldsFromGVDoc_EmptyOrMalformedDoc_NotFound(t *testing.T) {
	for name, doc := range map[string]map[string]any{
		"nil doc":            nil,
		"empty doc":          {},
		"components missing": {"foo": "bar"},
		"schemas not a map":  {"components": map[string]any{"schemas": "not-a-map"}},
	} {
		t.Run(name, func(t *testing.T) {
			fields, found := topLevelFieldsFromGVDoc(doc, schema.GroupVersionKind{Group: "apps", Version: "v1", Kind: "Deployment"})
			if found || fields != nil {
				t.Errorf("expected not-found/nil for a malformed document, got fields=%v found=%v", fields, found)
			}
		})
	}
}
