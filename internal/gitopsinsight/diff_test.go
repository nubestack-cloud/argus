package gitopsinsight

import (
	"fmt"
	"slices"
	"testing"
)

func paths(entries []DriftEntry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Path
	}
	return out
}

// DiffObjects compares declared intent only: spec and the like, labels and
// annotations, and nothing the server writes.
func TestDiffObjectsScope(t *testing.T) {
	desired := map[string]any{
		"apiVersion": "apps/v1",
		"metadata": map[string]any{
			"name": "web", "uid": "u-1", "resourceVersion": "811", "generation": int64(3),
			"labels":      map[string]any{"tier": "frontend"},
			"annotations": map[string]any{"owner": "payments"},
		},
		"spec":   map[string]any{"replicas": int64(3), "paused": false},
		"status": map[string]any{"readyReplicas": int64(3)},
	}
	live := map[string]any{
		"apiVersion": "apps/v1",
		"metadata": map[string]any{
			"name": "web", "uid": "u-1", "resourceVersion": "9042", "generation": int64(9),
			"managedFields": []any{map[string]any{"manager": "kubectl"}},
			"labels":        map[string]any{"tier": "edge"},
			"annotations":   map[string]any{"owner": "payments", "deployment.kubernetes.io/revision": "4"},
		},
		"spec":   map[string]any{"replicas": int64(5), "paused": false},
		"status": map[string]any{"readyReplicas": int64(1)},
	}
	entries, truncated := DiffObjects(desired, live)
	want := []string{"metadata.annotations.deployment.kubernetes.io/revision", "metadata.labels.tier", "spec.replicas"}
	if !slices.Equal(paths(entries), want) || truncated {
		t.Fatalf("paths = %v (truncated %v), want %v", paths(entries), truncated, want)
	}
	if e := entries[2]; e.Op != DriftOpChanged || e.Desired != "3" || e.Live != "5" {
		t.Errorf("replicas = %+v", e)
	}
	if e := entries[0]; e.Op != DriftOpAdded || e.Live != `"4"` || e.Desired != "" {
		t.Errorf("annotation = %+v", e)
	}
}

// Sorted before it is cut, so which entries survive is the same every time;
// truncation is reported only when something was dropped.
func TestDiffObjectsSortsThenCaps(t *testing.T) {
	want, have := map[string]any{}, map[string]any{}
	for i := 119; i >= 0; i-- {
		want[fmt.Sprintf("f%03d", i)] = i
		have[fmt.Sprintf("f%03d", i)] = -i - 1
	}
	entries, truncated := DiffObjects(map[string]any{"spec": want}, map[string]any{"spec": have})
	if !truncated || len(entries) != DriftEntryCap || entries[0].Path != "spec.f000" || entries[DriftEntryCap-1].Path != fmt.Sprintf("spec.f%03d", DriftEntryCap-1) {
		t.Fatalf("truncated=%v len=%d first=%s last=%s", truncated, len(entries), entries[0].Path, entries[len(entries)-1].Path)
	}
	if !slices.IsSortedFunc(entries, func(a, b DriftEntry) int { return map[bool]int{true: -1, false: 1}[a.Path < b.Path] }) {
		t.Error("not sorted")
	}
	if _, truncated := DiffObjects(map[string]any{"spec": map[string]any{"x": 1}}, map[string]any{"spec": map[string]any{"x": 2}}); truncated {
		t.Error("one entry reported as truncated")
	}
}

func TestFilterIgnoredPaths(t *testing.T) {
	entries := []DriftEntry{
		{Path: "spec.replicas"}, {Path: "spec.replicasMax"},
		{Path: "spec.template.spec.containers.[0].image"}, {Path: "spec.template.spec.containers.[1].image"},
		{Path: "metadata.annotations.example.com/team"}, {Path: "spec.selector.matchLabels.app"},
	}
	for _, c := range []struct {
		pointers []string
		left     []string
	}{
		// Whole segments only: replicas does not take replicasMax.
		{[]string{"/spec/replicas"}, []string{"spec.replicasMax", "spec.template.spec.containers.[0].image", "spec.template.spec.containers.[1].image", "metadata.annotations.example.com/team", "spec.selector.matchLabels.app"}},
		{[]string{"/spec/replic"}, paths(entries)},
		// A parent takes everything beneath it; an index pointer takes that
		// element; ~1 in a pointer is a "/" in the key.
		{[]string{"/spec/template", "/metadata/annotations/example.com~1team", " ", ""}, []string{"spec.replicas", "spec.replicasMax", "spec.selector.matchLabels.app"}},
		{[]string{"/spec/template/spec/containers/1/image"}, []string{"spec.replicas", "spec.replicasMax", "spec.template.spec.containers.[0].image", "metadata.annotations.example.com/team", "spec.selector.matchLabels.app"}},
		{nil, paths(entries)},
	} {
		before := slices.Clone(entries)
		if got := paths(filterIgnoredPaths(entries, c.pointers)); !slices.Equal(got, c.left) {
			t.Errorf("%v: left %v, want %v", c.pointers, got, c.left)
		}
		if !slices.Equal(entries, before) {
			t.Fatalf("%v: the input was modified", c.pointers)
		}
	}
}
