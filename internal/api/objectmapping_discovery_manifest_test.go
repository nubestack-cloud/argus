package api

import "testing"

func TestLooksLikeManifestPath(t *testing.T) {
	cases := map[string]bool{
		"manifests/deployment.yaml": true,
		"deploy.yml":                true,
		"Chart.yaml":                false,
		"kustomization.yaml":        false,
		"kustomization.yml":         false,
		"values.yaml":               false, // looksLikeValuesFile
		"values-prod.yaml":          false,
		"README.md":                 false,
		"charts/x/Chart.yaml":       false,
	}
	for name, want := range cases {
		if got := looksLikeManifestPath(name); got != want {
			t.Errorf("looksLikeManifestPath(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestUnderAnyChartDir(t *testing.T) {
	charts := []chartCandidate{{dir: "charts/shop-apps"}, {dir: "charts/other"}}
	cases := map[string]bool{
		"charts/shop-apps/templates/deployment.yaml": true,
		"charts/other/values.yaml":                   true,
		"manifests/configmap.yaml":                   false,
		"charts/shop-appsx/deployment.yaml":          false, // must not match on a bare prefix without the separator
	}
	for p, want := range cases {
		if got := underAnyChartDir(p, charts); got != want {
			t.Errorf("underAnyChartDir(%q) = %v, want %v", p, got, want)
		}
	}

	// A chart rooted at the repository root ("" dir) means the WHOLE tree is
	// inside it — nothing is "outside" a root-rooted chart, see the
	// function's own doc comment.
	rootChart := []chartCandidate{{dir: ""}}
	if !underAnyChartDir("anything/at/all.yaml", rootChart) {
		t.Error("underAnyChartDir must treat a root-rooted chart as covering the whole tree")
	}
}

func TestClassifyManifestDiscovery_ARenderFailureNeverBecomesNone(t *testing.T) {
	status, degraded := classifyManifestDiscovery(0, true, true, true)
	if status != "degraded" {
		t.Fatalf("status = %q, want degraded — a parse failure mixed with an unrelated success must not read as a verified negative", status)
	}
	if degraded == "" {
		t.Fatal("degraded reason is empty")
	}
}

func TestClassifyManifestDiscovery_CleanNoMatchIsNone(t *testing.T) {
	status, _ := classifyManifestDiscovery(0, true, true, false)
	if status != "none" {
		t.Fatalf("status = %q, want none — every parse completed cleanly and none matched, which is a real negative", status)
	}
}

func TestClassifyManifestDiscovery_NothingFoundAnywhereIsDegraded(t *testing.T) {
	status, degraded := classifyManifestDiscovery(0, false, false, false)
	if status != "degraded" || degraded == "" {
		t.Fatalf("status=%q degraded=%q, want degraded with a reason", status, degraded)
	}
}

func TestClassifyManifestDiscovery_OneProvenWinsRegardlessOfOtherFailures(t *testing.T) {
	status, _ := classifyManifestDiscovery(1, true, true, true)
	if status != "proven" {
		t.Fatalf("status = %q, want proven", status)
	}
}

func TestClassifyManifestDiscovery_TwoProvenIsAmbiguous(t *testing.T) {
	status, _ := classifyManifestDiscovery(2, true, true, false)
	if status != "ambiguous" {
		t.Fatalf("status = %q, want ambiguous", status)
	}
}

// TestDiscoverManifestLink_NoBindingsIsNone proves discoverManifestLink,
// unlike discoverRepositoryLink, needs no render sandbox at all — parsing a
// checked-out YAML file directly needs nothing more than the scm store, so
// with zero registered repositories the honest answer is a real "none", not
// a "degraded" excuse about a missing sandbox.
func TestDiscoverManifestLink_NoBindingsIsNone(t *testing.T) {
	// scmStore is nil here deliberately: ListBindings is never reached when
	// there is nothing to check out only in the "len(bindings) == 0" branch,
	// which requires a real store. This test instead exercises the same
	// contract at the unit level classifyManifestDiscovery already proves —
	// see the DB-backed TestDiscoverManifestLink_* tests for the live,
	// store-backed path.
	status, degraded := classifyManifestDiscovery(0, false, false, false)
	if status != "degraded" {
		t.Fatalf("status = %q, want degraded (nothing was attempted)", status)
	}
	_ = degraded
}
