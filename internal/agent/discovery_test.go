package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
)

// fakeDiscoverer is a hand-rolled resourceDiscoverer: real client-go's
// discovery/fake.FakeDiscovery.ServerPreferredResources always returns
// (nil, nil) (see discovery/fake/discovery.go), which can't exercise the
// partial-result-with-error shape this file's DiscoverWatchSet specifically
// has to tolerate. A minimal fake that returns exactly what's configured is
// simpler and more honest than fighting the real fake's reactor plumbing for
// a case it doesn't support.
type fakeDiscoverer struct {
	lists []*metav1.APIResourceList
	err   error
	calls int
}

func (f *fakeDiscoverer) ServerPreferredResources() ([]*metav1.APIResourceList, error) {
	f.calls++
	return f.lists, f.err
}

// fakeRulesReviewer is the rulesReviewCreator analogue of fakeDiscoverer, for
// the same reason: the generated fake for SelfSubjectRulesReviewInterface
// just echoes the input object back (empty Status) unless a reactor is
// wired up, which is more machinery than this test needs.
type fakeRulesReviewer struct {
	rules []authorizationv1.ResourceRule
	err   error
	calls int
}

func (f *fakeRulesReviewer) Create(_ context.Context, _ *authorizationv1.SelfSubjectRulesReview, _ metav1.CreateOptions) (*authorizationv1.SelfSubjectRulesReview, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &authorizationv1.SelfSubjectRulesReview{
		Status: authorizationv1.SubjectRulesReviewStatus{ResourceRules: f.rules},
	}, nil
}

func podsResourceList() *metav1.APIResourceList {
	return &metav1.APIResourceList{
		GroupVersion: "v1",
		APIResources: []metav1.APIResource{
			{Name: "pods", Namespaced: true, Kind: "Pod", Verbs: metav1.Verbs{"get", "list", "watch", "create", "update", "delete"}},
			{Name: "pods/status", Namespaced: true, Kind: "Pod", Verbs: metav1.Verbs{"get", "update", "patch"}},
		},
	}
}

func widgetsResourceList() *metav1.APIResourceList {
	return &metav1.APIResourceList{
		GroupVersion: "example.com/v1",
		APIResources: []metav1.APIResource{
			{Name: "widgets", Namespaced: true, Kind: "Widget", Verbs: metav1.Verbs{"get", "list", "watch"}},
		},
	}
}

func fullRule(group, resource string) authorizationv1.ResourceRule {
	return authorizationv1.ResourceRule{
		Verbs:     []string{"get", "list", "watch"},
		APIGroups: []string{group},
		Resources: []string{resource},
	}
}

func TestDiscoverWatchSet_ResourceInDiscoveryAndRBAC_Included(t *testing.T) {
	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{podsResourceList()}}
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{fullRule("", "pods")}}

	set, _, err := DiscoverWatchSet(context.Background(), disc, rules)
	if err != nil {
		t.Fatalf("DiscoverWatchSet returned error: %v", err)
	}
	gvk := schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}
	got, ok := set[gvk]
	if !ok {
		t.Fatalf("expected %v in watch set, got %v", gvk, set)
	}
	want := DiscoveredResource{GVR: schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}, Namespaced: true}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
	// The subresource must never appear as its own entry.
	if _, ok := set[schema.GroupVersionKind{Group: "", Version: "v1", Kind: "pods/status"}]; ok {
		t.Errorf("subresource leaked into watch set: %v", set)
	}
}

func TestDiscoverWatchSet_InDiscoveryButNotRBAC_Excluded(t *testing.T) {
	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{podsResourceList(), widgetsResourceList()}}
	// RBAC grants pods but says nothing about widgets.
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{fullRule("", "pods")}}

	set, _, err := DiscoverWatchSet(context.Background(), disc, rules)
	if err != nil {
		t.Fatalf("DiscoverWatchSet returned error: %v", err)
	}
	if _, ok := set[schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}]; !ok {
		t.Errorf("expected Pod (granted) to be included: %v", set)
	}
	if _, ok := set[schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "Widget"}]; ok {
		t.Errorf("Widget must be excluded — discovered but not RBAC-granted: %v", set)
	}
}

func TestDiscoverWatchSet_InRBACButServerDoesNotServeIt_Excluded(t *testing.T) {
	// RBAC grants get/list/watch on "widgets", but the API server's own
	// discovery never lists it (e.g. the CRD naming it was never installed,
	// or it's a resource RBAC names optimistically). Nothing to intersect
	// with means it must not appear.
	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{podsResourceList()}}
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{fullRule("", "pods"), fullRule("example.com", "widgets")}}

	set, _, err := DiscoverWatchSet(context.Background(), disc, rules)
	if err != nil {
		t.Fatalf("DiscoverWatchSet returned error: %v", err)
	}
	if _, ok := set[schema.GroupVersionKind{Group: "example.com", Version: "v1", Kind: "Widget"}]; ok {
		t.Errorf("Widget must be excluded — RBAC-granted but never served by discovery: %v", set)
	}
	if len(set) != 1 {
		t.Errorf("expected exactly Pod in the set, got %v", set)
	}
}

func TestDiscoverWatchSet_RBACVerbsAccumulateAcrossRules(t *testing.T) {
	// One rule grants only "get", another grants only "list"/"watch" on the
	// same resource — additive RBAC means the union should satisfy the
	// get+list+watch requirement even though neither rule alone does.
	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{podsResourceList()}}
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{
		{Verbs: []string{"get"}, APIGroups: []string{""}, Resources: []string{"pods"}},
		{Verbs: []string{"list", "watch"}, APIGroups: []string{""}, Resources: []string{"pods"}},
	}}

	set, _, err := DiscoverWatchSet(context.Background(), disc, rules)
	if err != nil {
		t.Fatalf("DiscoverWatchSet returned error: %v", err)
	}
	if _, ok := set[schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}]; !ok {
		t.Errorf("expected Pod to be included via accumulated verbs across rules: %v", set)
	}
}

func TestDiscoverWatchSet_WildcardRBACGrantsEverything(t *testing.T) {
	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{podsResourceList(), widgetsResourceList()}}
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{
		{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}},
	}}

	set, _, err := DiscoverWatchSet(context.Background(), disc, rules)
	if err != nil {
		t.Fatalf("DiscoverWatchSet returned error: %v", err)
	}
	if len(set) != 2 {
		t.Errorf("expected both Pod and Widget included under a wildcard grant, got %v", set)
	}
}

func TestDiscoverWatchSet_ServerDoesNotAdvertiseWatch_Excluded(t *testing.T) {
	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{{
		GroupVersion: "metrics.k8s.io/v1beta1",
		APIResources: []metav1.APIResource{
			{Name: "pods", Namespaced: true, Kind: "PodMetrics", Verbs: metav1.Verbs{"get", "list"}}, // no watch
		},
	}}}
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{fullRule("metrics.k8s.io", "pods")}}

	set, _, err := DiscoverWatchSet(context.Background(), disc, rules)
	if err != nil {
		t.Fatalf("DiscoverWatchSet returned error: %v", err)
	}
	if len(set) != 0 {
		t.Errorf("expected nothing — the API server itself doesn't advertise watch support: %v", set)
	}
}

// partialGroupErr mimics what ServerPreferredResources itself documents:
// a non-nil partial result alongside *discovery.ErrGroupDiscoveryFailed.
func TestDiscoverWatchSet_PartialGroupFailure_OtherGroupsStillDiscovered(t *testing.T) {
	disc := &fakeDiscoverer{
		lists: []*metav1.APIResourceList{podsResourceList()}, // the good group's result
		err: &discovery.ErrGroupDiscoveryFailed{
			Groups: map[schema.GroupVersion]error{
				{Group: "broken.example.com", Version: "v1"}: errors.New("service unavailable"),
			},
		},
	}
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{fullRule("", "pods")}}

	set, _, err := DiscoverWatchSet(context.Background(), disc, rules)
	if err != nil {
		t.Fatalf("a partial per-group discovery failure must not fail the whole call, got: %v", err)
	}
	if _, ok := set[schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}]; !ok {
		t.Errorf("expected Pod from the group that succeeded, got %v", set)
	}
}

func TestDiscoverWatchSet_TotalDiscoveryFailure_Errors(t *testing.T) {
	disc := &fakeDiscoverer{err: errors.New("connection refused")}
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{fullRule("", "pods")}}

	_, _, err := DiscoverWatchSet(context.Background(), disc, rules)
	if err == nil {
		t.Fatal("expected an error when discovery fails outright (not a partial-group error)")
	}
}

func TestDiscoverWatchSet_RulesReviewFailure_Errors(t *testing.T) {
	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{podsResourceList()}}
	rules := &fakeRulesReviewer{err: errors.New("forbidden")}

	_, _, err := DiscoverWatchSet(context.Background(), disc, rules)
	if err == nil {
		t.Fatal("expected an error when the SelfSubjectRulesReview call itself fails")
	}
}

func TestDiscoverWatchSet_IncompleteRulesReview_StillUsesWhatCameBack(t *testing.T) {
	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{podsResourceList()}}
	// incompleteRulesReviewer simulates Status.Incomplete=true, which a
	// bare fakeRulesReviewer never sets.
	rules := incompleteRulesReviewer{rules: []authorizationv1.ResourceRule{fullRule("", "pods")}}

	set, _, err := DiscoverWatchSet(context.Background(), disc, rules)
	if err != nil {
		t.Fatalf("DiscoverWatchSet returned error: %v", err)
	}
	if _, ok := set[schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Pod"}]; !ok {
		t.Errorf("expected Pod despite Incomplete=true, got %v", set)
	}
}

type incompleteRulesReviewer struct {
	rules []authorizationv1.ResourceRule
}

func (r incompleteRulesReviewer) Create(_ context.Context, _ *authorizationv1.SelfSubjectRulesReview, _ metav1.CreateOptions) (*authorizationv1.SelfSubjectRulesReview, error) {
	return &authorizationv1.SelfSubjectRulesReview{
		Status: authorizationv1.SubjectRulesReviewStatus{
			ResourceRules:   r.rules,
			Incomplete:      true,
			EvaluationError: "some authorizer does not support rules evaluation",
		},
	}, nil
}

// --- WatchSetCache ---

func TestWatchSetCache_SecondCallWithinTTLUsesCacheNoNewAPICall(t *testing.T) {
	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{podsResourceList()}}
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{fullRule("", "pods")}}

	fakeNow := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	cache := NewWatchSetCache(disc, rules, 10*time.Minute)
	cache.now = func() time.Time { return fakeNow }

	if _, err := cache.Get(context.Background()); err != nil {
		t.Fatalf("first Get failed: %v", err)
	}
	if disc.calls != 1 || rules.calls != 1 {
		t.Fatalf("expected exactly one discovery/rules call after first Get, got disc=%d rules=%d", disc.calls, rules.calls)
	}

	// Advance time by less than the TTL: must NOT trigger a new API call.
	fakeNow = fakeNow.Add(5 * time.Minute)
	if _, err := cache.Get(context.Background()); err != nil {
		t.Fatalf("second Get failed: %v", err)
	}
	if disc.calls != 1 || rules.calls != 1 {
		t.Fatalf("second Get within TTL must be served from cache, got disc=%d rules=%d", disc.calls, rules.calls)
	}
}

func TestWatchSetCache_RefreshesAfterTTLExpires(t *testing.T) {
	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{podsResourceList()}}
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{fullRule("", "pods")}}

	fakeNow := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	cache := NewWatchSetCache(disc, rules, 10*time.Minute)
	cache.now = func() time.Time { return fakeNow }

	if _, err := cache.Get(context.Background()); err != nil {
		t.Fatalf("first Get failed: %v", err)
	}

	fakeNow = fakeNow.Add(11 * time.Minute) // past the 10-minute TTL
	if _, err := cache.Get(context.Background()); err != nil {
		t.Fatalf("second Get failed: %v", err)
	}
	if disc.calls != 2 || rules.calls != 2 {
		t.Fatalf("expected a refresh after TTL expiry, got disc=%d rules=%d", disc.calls, rules.calls)
	}
}

func TestWatchSetCache_RefreshFailureServesStaleSetRatherThanError(t *testing.T) {
	disc := &fakeDiscoverer{lists: []*metav1.APIResourceList{podsResourceList()}}
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{fullRule("", "pods")}}

	fakeNow := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	cache := NewWatchSetCache(disc, rules, 10*time.Minute)
	cache.now = func() time.Time { return fakeNow }

	first, err := cache.Get(context.Background())
	if err != nil {
		t.Fatalf("first Get failed: %v", err)
	}

	// Break the underlying calls, then expire the TTL.
	disc.err = errors.New("connection refused")
	fakeNow = fakeNow.Add(11 * time.Minute)

	second, err := cache.Get(context.Background())
	if err != nil {
		t.Fatalf("expected the stale set to be served, not an error: %v", err)
	}
	if len(second) != len(first) {
		t.Errorf("expected the stale set to be returned unchanged, got %v want %v", second, first)
	}
}

func TestWatchSetCache_FirstCallFailureReturnsError(t *testing.T) {
	disc := &fakeDiscoverer{err: errors.New("connection refused")}
	rules := &fakeRulesReviewer{rules: []authorizationv1.ResourceRule{fullRule("", "pods")}}

	cache := NewWatchSetCache(disc, rules, 10*time.Minute)
	if _, err := cache.Get(context.Background()); err == nil {
		t.Fatal("expected an error on the very first call with nothing stale to fall back to")
	}
}
