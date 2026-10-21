package api

import (
	"testing"

	"argus/internal/render"
)

func TestLooksLikeValuesFile(t *testing.T) {
	cases := map[string]bool{
		"values.yaml":      true,
		"values.yml":       true,
		"values-prod.yaml": true,
		"values-dev.yml":   true,
		"Chart.yaml":       false,
		"deployment.yaml":  false,
		"values.txt":       false,
		"my-values.yaml":   false, // does not START with "values" — deliberately narrow, see the function's own doc comment
	}
	for name, want := range cases {
		if got := looksLikeValuesFile(name); got != want {
			t.Errorf("looksLikeValuesFile(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestChartNameFrom(t *testing.T) {
	if got := chartNameFrom([]byte("name: shop-apps\nversion: 1.0.0\n")); got != "shop-apps" {
		t.Errorf("chartNameFrom = %q, want shop-apps", got)
	}
	// Unreadable content must not be an error a caller has to handle — it
	// just never sorts first (orderChartsByNameAlignment's own contract).
	if got := chartNameFrom([]byte("not: valid: yaml: at: all: :::")); got != "" {
		t.Errorf("chartNameFrom(malformed) = %q, want empty", got)
	}
}

func TestOrderChartsByNameAlignment(t *testing.T) {
	charts := []chartCandidate{
		{dir: "charts/unrelated", name: "unrelated"},
		{dir: "charts/shop-apps", name: "shop-apps"},
		{dir: "charts/results", name: ""}, // name absent, but the directory itself aligns
	}
	orderChartsByNameAlignment(charts, "shop-apps")
	if charts[0].dir != "charts/shop-apps" {
		t.Fatalf("orderChartsByNameAlignment did not sort the name-aligned chart first: %+v", charts)
	}

	charts2 := []chartCandidate{
		{dir: "charts/unrelated", name: "unrelated"},
		{dir: "charts/results", name: ""},
	}
	orderChartsByNameAlignment(charts2, "results")
	if charts2[0].dir != "charts/results" {
		t.Fatalf("orderChartsByNameAlignment did not sort the DIRECTORY-aligned chart first when Chart.yaml has no name: %+v", charts2)
	}

	// Every candidate is still present regardless of order — ordering is a
	// cost optimisation, never a filter.
	if len(charts) != 3 || len(charts2) != 2 {
		t.Fatal("orderChartsByNameAlignment must never drop a candidate")
	}
}

func TestSubtree(t *testing.T) {
	tree := map[string][]byte{
		"charts/shop-apps/Chart.yaml":  []byte("name: shop-apps"),
		"charts/shop-apps/values.yaml": []byte("replicas: 1"),
		"charts/other/Chart.yaml":      []byte("name: other"),
		"envs/prod/values.yaml":        []byte("replicas: 3"),
	}
	sub := subtree(tree, "charts/shop-apps")
	if len(sub) != 2 {
		t.Fatalf("subtree(charts/shop-apps) = %v, want exactly the 2 entries under that prefix", sub)
	}
	if _, ok := sub["Chart.yaml"]; !ok {
		t.Error("subtree did not strip the prefix from Chart.yaml's own key")
	}
	if _, ok := sub["values.yaml"]; !ok {
		t.Error("subtree did not strip the prefix from values.yaml's own key")
	}

	// A chart at the repository root ("" prefix) is the whole tree, verbatim.
	root := subtree(tree, "")
	if len(root) != len(tree) {
		t.Fatalf("subtree(\"\") = %d entries, want all %d", len(root), len(tree))
	}
}

func TestWithExtraFile(t *testing.T) {
	original := map[string][]byte{"Chart.yaml": []byte("name: x")}
	extended := withExtraFile(original, "_argus_discovery_values_prod.yaml", []byte("replicas: 3"))
	if len(original) != 1 {
		t.Fatal("withExtraFile mutated the original tree")
	}
	if len(extended) != 2 || string(extended["_argus_discovery_values_prod.yaml"]) != "replicas: 3" {
		t.Fatalf("extended = %v, want the original entry plus the new one", extended)
	}
}

func TestObjectAppearsIn(t *testing.T) {
	objs := []render.Object{
		{APIVersion: "apps/v1", Kind: "Deployment", Namespace: "shop", Name: "shop-apps-api"},
		{APIVersion: "v1", Kind: "Service", Namespace: "shop", Name: "shop-apps-api"},
	}
	if !objectAppearsIn(objs, "apps/v1/Deployment", "shop", "shop-apps-api") {
		t.Error("objectAppearsIn did not find the real match")
	}
	if objectAppearsIn(objs, "apps/v1/Deployment", "shop", "some-other-name") {
		t.Error("objectAppearsIn matched on the wrong name")
	}
	if objectAppearsIn(objs, "apps/v1/StatefulSet", "shop", "shop-apps-api") {
		t.Error("objectAppearsIn matched on the wrong kind — a render producing a DIFFERENT kind at the same name/namespace is not a match")
	}
	if objectAppearsIn(objs, "apps/v1/Deployment", "other-namespace", "shop-apps-api") {
		t.Error("objectAppearsIn matched on the wrong namespace")
	}
}

// discoverRepositoryLink's degraded-without-a-sandbox path is the one part
// of the orchestration this file can prove with no database and no render
// sandbox at all — every other path (a real registered repository, a real
// checkout, a real render) is proven live against lab-dev instead, per this
// task's own standing rules; a mocked *sandbox.Runner would only prove this
// file agrees with its own mock.
func TestDiscoverRepositoryLink_NoSandboxConfiguredDegradesHonestly(t *testing.T) {
	s := &Server{}
	result := s.discoverRepositoryLink(nil, nil, "shop-apps", "shop", "apps/v1/Deployment", "shop", "shop-apps-api")
	if result.Status != "degraded" {
		t.Fatalf("Status = %q, want degraded", result.Status)
	}
	if result.Degraded == "" {
		t.Fatal("Degraded reason is empty")
	}
	if len(result.Candidates) != 0 {
		t.Fatalf("Candidates = %v, want none — nothing was attempted", result.Candidates)
	}
}

// TestClassifyDiscovery_ARenderFailureNeverBecomesNone is the regression
// test for the 2026-09-09 live bug: a genuine render failure on one
// candidate must never be silently absorbed into "none" just because some
// OTHER, unrelated candidate rendered cleanly and simply didn't match.
func TestClassifyDiscovery_ARenderFailureNeverBecomesNone(t *testing.T) {
	status, degraded := classifyDiscovery(0, true, true, true)
	if status != "degraded" {
		t.Fatalf("status = %q, want %q — a render failure mixed with an unrelated success must not read as a verified negative", status, "degraded")
	}
	if degraded == "" {
		t.Fatal("degraded reason is empty — the operator needs to know a render did not complete, not just that the status is degraded")
	}
}

func TestClassifyDiscovery_CleanNoMatchIsNone(t *testing.T) {
	status, _ := classifyDiscovery(0, true, true, false)
	if status != "none" {
		t.Fatalf("status = %q, want %q — every render completed cleanly and none matched, which is a real negative", status, "none")
	}
}

func TestClassifyDiscovery_NoChartsFoundAnywhereIsDegraded(t *testing.T) {
	status, degraded := classifyDiscovery(0, false, false, false)
	if status != "degraded" || degraded == "" {
		t.Fatalf("status=%q degraded=%q, want degraded with a reason", status, degraded)
	}
}

func TestClassifyDiscovery_EveryAttemptFailedIsDegraded(t *testing.T) {
	status, degraded := classifyDiscovery(0, true, false, true)
	if status != "degraded" || degraded == "" {
		t.Fatalf("status=%q degraded=%q, want degraded with a reason", status, degraded)
	}
}

func TestClassifyDiscovery_OneProvenWinsRegardlessOfOtherFailures(t *testing.T) {
	status, _ := classifyDiscovery(1, true, true, true)
	if status != "proven" {
		t.Fatalf("status = %q, want %q — one proof stands even if another candidate failed to render", status, "proven")
	}
}

func TestClassifyDiscovery_TwoProvenIsAmbiguousRegardlessOfOtherFailures(t *testing.T) {
	status, _ := classifyDiscovery(2, true, true, true)
	if status != "ambiguous" {
		t.Fatalf("status = %q, want %q", status, "ambiguous")
	}
}
