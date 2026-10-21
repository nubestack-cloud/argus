package agent

import (
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// PROJECT.md IN7: never healthy is told apart from healthy before, and the
// owner that would undo a direct change is named.
func TestStateFacts(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	deploy := func(transition string) *unstructured.Unstructured {
		return &unstructured.Unstructured{Object: map[string]any{
			"kind": "Deployment",
			"metadata": map[string]any{"name": "web", "namespace": "shop", "creationTimestamp": "2026-10-14T10:00:00Z",
				"annotations": map[string]any{"meta.helm.sh/release-name": "web", "meta.helm.sh/release-namespace": "shop"}},
			"status": map[string]any{"conditions": []any{map[string]any{"type": "Available", "status": "False", "lastTransitionTime": transition}}},
		}}
	}
	never := strings.Join(stateFacts(deploy("2026-10-14T10:00:30Z"), now), " ")
	if !strings.Contains(never, "never been healthy") || !strings.Contains(never, "Helm release shop/web") {
		t.Errorf("deployed broken: %q", never)
	}
	later := strings.Join(stateFacts(deploy("2026-10-14T11:30:00Z"), now), " ")
	if !strings.Contains(later, "healthy before") || strings.Contains(later, "never") {
		t.Errorf("broke after a healthy start: %q", later)
	}
}
