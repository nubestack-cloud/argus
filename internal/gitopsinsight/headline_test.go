package gitopsinsight

import (
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestHeadlineFor(t *testing.T) {
	fixedNow := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name      string
		obj       map[string]any
		now       time.Time
		want      string
		wantCause string
		stuck     bool
	}{
		{
			name: "argo sync failed and stopped retrying",
			obj: map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata": map[string]any{"name": "a"},
				"status": map[string]any{"sync": map[string]any{"status": "OutOfSync"}, "operationState": map[string]any{
					"phase": "Failed", "message": `namespaces "billing" not found (retried 5 times).` + "\nlong rendered diff"}}},
			want:      `The last sync failed and Argo CD stopped retrying after 5 attempts: namespaces "billing" not found (retried 5 times).`,
			wantCause: "namespace that does not exist",
			stuck:     true,
		},
		{
			name: "argo healthy and synced says nothing",
			obj: map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata": map[string]any{"name": "a"},
				"status": map[string]any{"sync": map[string]any{"status": "Synced"}, "health": map[string]any{"status": "Healthy"}}},
			want: "",
		},
		{
			name: "argo degraded names the managed objects",
			obj: map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata": map[string]any{"name": "a"},
				"status": map[string]any{"sync": map[string]any{"status": "Synced"}, "health": map[string]any{"status": "Degraded"},
					"resources": []any{map[string]any{"kind": "Deployment", "name": "api", "health": map[string]any{"status": "Degraded"}}}}},
			want: "Degraded: 1 managed object is not healthy (Deployment api).",
		},
		{
			name: "flux stalled",
			obj: map[string]any{"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization", "metadata": map[string]any{"name": "k"},
				"status": map[string]any{"conditions": []any{
					map[string]any{"type": "Stalled", "status": "True", "reason": "BuildFailed", "message": "kustomization path not found"}}}},
			want:      "Stalled — Flux has stopped retrying (BuildFailed): kustomization path not found",
			wantCause: "path exists in the source",
			stuck:     true,
		},
		{
			name: "terminating leads",
			obj: map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "Application",
				"metadata": map[string]any{"name": "a", "deletionTimestamp": "2026-10-11T00:00:00Z", "finalizers": []any{"resources-finalizer.argocd.argoproj.io"}},
				"status":   map[string]any{"sync": map[string]any{"status": "Synced"}, "health": map[string]any{"status": "Healthy"}}},
			want: "Being deleted; waiting on finalizers resources-finalizer.argocd.argoproj.io.",
		},
		// PG1 (2026-10-13 parity review), shape 1: last sync succeeded, auto-sync
		// is on, reconciledAt is recent, and it is out of sync again — something
		// keeps re-mutating the objects after every apply.
		{
			name: "argo stuck in a drift loop",
			obj: map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata": map[string]any{"name": "a"},
				"status": map[string]any{
					"sync":           map[string]any{"status": "OutOfSync"},
					"operationState": map[string]any{"phase": "Succeeded"},
					"reconciledAt":   "2026-10-13T11:58:00Z",
					"resources":      []any{map[string]any{"kind": "Deployment", "name": "api", "status": "OutOfSync"}},
				},
				"spec": map[string]any{"syncPolicy": map[string]any{"automated": map[string]any{"selfHeal": true}}}},
			now:       fixedNow,
			want:      "Stuck in a drift loop: the last sync succeeded and auto-sync is on, but it is out of sync again: 1 of 1 managed objects out of sync (Deployment api).",
			wantCause: "mutating webhook",
		},
		// PG1, shape 1 negative: the same OutOfSync/Succeeded/Auto shape, but
		// reconciledAt is stale — Argo has not actually looked recently, so this
		// must read as ordinary drift, not a stuck loop no amount of staring at
		// stale data could support.
		{
			name: "argo out of sync but reconcile is stale, not a stuck loop",
			obj: map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata": map[string]any{"name": "a"},
				"status": map[string]any{
					"sync":           map[string]any{"status": "OutOfSync"},
					"operationState": map[string]any{"phase": "Succeeded"},
					"reconciledAt":   "2026-10-13T01:00:00Z",
				},
				"spec": map[string]any{"syncPolicy": map[string]any{"automated": map[string]any{}}}},
			now:  fixedNow,
			want: "Live state differs from Git.",
		},
		// PG1, shape 2: drift with auto-sync off reads as its own headline, not
		// a generic "differs from Git" with the reason buried in a cause.
		{
			name: "argo manual drift",
			obj: map[string]any{"apiVersion": "argoproj.io/v1alpha1", "kind": "Application", "metadata": map[string]any{"name": "a"},
				"status": map[string]any{
					"sync":      map[string]any{"status": "OutOfSync"},
					"resources": []any{map[string]any{"kind": "Deployment", "name": "api", "status": "OutOfSync"}},
				}},
			now:       fixedNow,
			want:      "Drift with auto-sync off: nothing will reconcile until someone syncs: 1 of 1 managed objects out of sync (Deployment api).",
			wantCause: "spec.syncPolicy.automated",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obj := &unstructured.Unstructured{Object: tc.obj}
			now := tc.now
			if now.IsZero() {
				now = time.Now()
			}
			h := HeadlineFor(obj, Summarize(obj), now)
			if h.Text != tc.want {
				t.Errorf("headline = %q\nwant      %q", h.Text, tc.want)
			}
			if tc.wantCause != "" && !strings.Contains(strings.Join(h.Causes, " "), tc.wantCause) {
				t.Errorf("causes = %v, want one mentioning %q", h.Causes, tc.wantCause)
			}
			if h.Stuck != tc.stuck {
				t.Errorf("stuck = %v, want %v", h.Stuck, tc.stuck)
			}
		})
	}
}

func TestHeadlineIsCapped(t *testing.T) {
	obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "kustomize.toolkit.fluxcd.io/v1", "kind": "Kustomization",
		"metadata": map[string]any{"name": "k"},
		"status":   map[string]any{"conditions": []any{map[string]any{"type": "Ready", "status": "False", "message": strings.Repeat("x", 2000)}}}}}
	if h := HeadlineFor(obj, Summarize(obj), time.Now()); len([]rune(h.Text)) > MaxHeadlineRunes+1 {
		t.Errorf("headline is %d runes, over the cap", len([]rune(h.Text)))
	}
}
