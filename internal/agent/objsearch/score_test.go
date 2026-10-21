package objsearch

import "testing"

func obj() Object {
	return Object{
		Kind:      "Pod",
		Namespace: "prod",
		Name:      "redis-master",
		Labels:    map[string]string{"app": "redis", "tier": "cache"},
		Images:    []string{"redis:6.2.7"},
	}
}

func TestMatch_FreeTokenScoresHighestSite(t *testing.T) {
	score, sites, ok := match(Parse("redis"), obj())
	if !ok {
		t.Fatal("expected match")
	}
	// Name prefix (60) beats exact label value (25) and image (20).
	if score != nameGrades.start || sites[0].Site != "name" {
		t.Fatalf("score=%d sites=%+v, expected %d on name", score, sites, nameGrades.start)
	}
}

func TestMatch_TwoTokensSummed(t *testing.T) {
	score, sites, ok := match(Parse("redis cache"), obj())
	if !ok {
		t.Fatal("expected match")
	}
	if score != nameGrades.start+labelGrades.whole {
		t.Fatalf("score=%d", score)
	}
	if len(sites) != 2 || sites[1].Site != "label:tier" {
		t.Fatalf("sites=%+v", sites)
	}
}

func TestMatch_SiteScores(t *testing.T) {
	cases := []struct {
		token string
		want  int
		site  string
	}{
		{"redis-master", nameGrades.whole, "name"},
		{"master", nameGrades.within, "name"},
		{"prod", namespaceGrades.whole, "namespace"},
		{"ro", namespaceGrades.within, "namespace"},
		{"cach", labelGrades.within, "label:tier"},
		{"6.2.7", imageGrades.within, "image"},
		{"pod", kindGrades.whole, "kind"},
	}
	for _, tc := range cases {
		score, sites, ok := match(Parse(tc.token), obj())
		if !ok || score != tc.want || sites[0].Site != tc.site {
			t.Errorf("token %q: score=%d sites=%+v ok=%v, want %d on %s", tc.token, score, sites, ok, tc.want, tc.site)
		}
	}
	o := obj()
	o.Kind = "PodDisruptionBudget"
	o.Name, o.Namespace, o.Labels, o.Images = "x", "", nil, nil
	if score, _, ok := match(Parse("disruption"), o); !ok || score != kindGrades.within {
		t.Errorf("kind substring score=%d ok=%v", score, ok)
	}
}

func TestMatch_TokenMustMatchSomewhere(t *testing.T) {
	if _, _, ok := match(Parse("redis nope-not-here"), obj()); ok {
		t.Fatal("expected no match — second token must reject")
	}
}

func TestMatch_KindFilter(t *testing.T) {
	o := obj()
	if _, _, ok := match(Parse("kind:Service"), o); ok {
		t.Fatal("kind:Service should reject a Pod")
	}
	if _, _, ok := match(Parse("kind:Pod"), o); !ok {
		t.Fatal("kind:Pod should match a Pod")
	}
	if _, _, ok := match(Parse("kind:pods"), o); !ok {
		t.Fatal("kind:pods should match")
	}
}

func TestMatch_NSFilter(t *testing.T) {
	if _, _, ok := match(Parse("ns:dev"), obj()); ok {
		t.Fatal("ns:dev should reject prod")
	}
	if _, _, ok := match(Parse("ns:PROD"), obj()); !ok {
		t.Fatal("ns:PROD should match case-insensitively")
	}
}

func TestMatch_LabelFilter(t *testing.T) {
	o := obj()
	if _, _, ok := match(Parse("label:app=redis"), o); !ok {
		t.Fatal("label:app=redis should match")
	}
	if _, _, ok := match(Parse("label:app=postgres"), o); ok {
		t.Fatal("label:app=postgres should reject")
	}
	if _, _, ok := match(Parse("label:app"), o); !ok {
		t.Fatal("label:app (key-only) should match when label exists")
	}
	if _, _, ok := match(Parse("label:missing"), o); ok {
		t.Fatal("label:missing should reject when label absent")
	}
}

func TestMatch_ImageFilter(t *testing.T) {
	if _, _, ok := match(Parse("image:REDIS"), obj()); !ok {
		t.Fatal("image:REDIS should match")
	}
	if _, _, ok := match(Parse("image:nginx"), obj()); ok {
		t.Fatal("image:nginx should reject")
	}
}

func TestMatch_PureFilterReturnsFlatScore(t *testing.T) {
	score, _, ok := match(Parse("kind:Pod ns:prod"), obj())
	if !ok || score != filterOnlyScore {
		t.Fatalf("filter-only match: score=%d ok=%v", score, ok)
	}
}

func TestMatch_CaseInsensitive(t *testing.T) {
	if _, _, ok := match(Parse("REDIS"), obj()); !ok {
		t.Fatal("expected case-insensitive match")
	}
}

func TestKindMatches_Variants(t *testing.T) {
	cases := []struct {
		kind, filter string
		want         bool
	}{
		{"Pod", "pod", true},
		{"Pod", "Pod", true},
		{"Pod", "pods", true},
		{"Service", "svc", false},
		{"Deployment", "deployment", true},
		{"Deployment", "deployments", true},
		{"Pod", "service", false},
	}
	for _, tc := range cases {
		if got := kindMatches(tc.kind, []string{tc.filter}); got != tc.want {
			t.Errorf("kindMatches(%q, %q) = %v, want %v", tc.kind, tc.filter, got, tc.want)
		}
	}
}
