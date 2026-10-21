package objsearch

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type listCall struct {
	kind, ns string
}

type fakeProvider struct {
	kinds   []KindRef
	objects map[string][]Object // keyed by Kind
	fail    map[string]bool
	calls   []listCall
	onList  func()
}

func (f *fakeProvider) Kinds() []KindRef { return f.kinds }

func (f *fakeProvider) List(_ context.Context, kr KindRef, ns string) ([]Object, error) {
	f.calls = append(f.calls, listCall{kr.Kind, ns})
	if f.onList != nil {
		f.onList()
	}
	if f.fail[kr.Kind] {
		return nil, errors.New("forbidden")
	}
	var out []Object
	for _, o := range f.objects[kr.Kind] {
		if ns == "" || o.Namespace == ns {
			out = append(out, o)
		}
	}
	return out, nil
}

var (
	podKind    = KindRef{Kind: "Pod", Namespaced: true}
	deployKind = KindRef{Kind: "Deployment", APIGroup: "apps", Namespaced: true}
	eventKind  = KindRef{Kind: "Event", Namespaced: true}
	secretKind = KindRef{Kind: "Secret", Namespaced: true}
	nodeKind   = KindRef{Kind: "Node"}
)

func pod(ns, name, image string) Object {
	o, _ := ObjectFromTyped(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: image}}},
		Status:     corev1.PodStatus{Phase: corev1.PodRunning},
	}, "Pod", "")
	return o
}

func deploy(ns, name, image string) Object {
	o, _ := ObjectFromTyped(&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c", Image: image}},
		}}},
	}, "Deployment", "apps")
	return o
}

func TestSearch_RanksExactNameAboveSubstring(t *testing.T) {
	p := &fakeProvider{
		kinds: []KindRef{podKind},
		objects: map[string][]Object{"Pod": {
			pod("default", "redis-master-1", "redis:6.2"),
			pod("default", "redis", "redis:7.0"),
			pod("default", "other", "redis:6.2"),
		}},
	}
	res := Search(context.Background(), p, Parse("redis"), Options{})
	if len(res.Hits) != 3 {
		t.Fatalf("expected 3 hits, got %+v", res.Hits)
	}
	if res.Hits[0].Name != "redis" || res.Hits[0].Score != nameGrades.whole {
		t.Fatalf("expected 'redis' first (exact name beats prefix), got %+v", res.Hits[0])
	}
	if res.Hits[2].Name != "other" || !reflect.DeepEqual(res.Hits[2].Matched, []string{"image"}) {
		t.Fatalf("image-only hit = %+v", res.Hits[2])
	}
	if res.Hits[0].Status != "Running" {
		t.Fatalf("status not carried: %+v", res.Hits[0])
	}
}

func TestSearch_KindFilter(t *testing.T) {
	p := &fakeProvider{
		kinds: []KindRef{podKind, deployKind},
		objects: map[string][]Object{
			"Pod":        {pod("ns", "redis", "redis:6.2")},
			"Deployment": {deploy("ns", "redis", "redis:6.2")},
		},
	}
	res := Search(context.Background(), p, Parse("kind:Deployment redis"), Options{})
	if len(res.Hits) != 1 || res.Hits[0].Kind != "Deployment" || res.Hits[0].APIGroup != "apps" {
		t.Fatalf("expected single Deployment hit, got %+v", res.Hits)
	}
	if len(p.calls) != 1 || p.calls[0].kind != "Deployment" {
		t.Fatalf("kind filter should skip listing other kinds, got %+v", p.calls)
	}
}

func TestSearch_ImageMatch(t *testing.T) {
	p := &fakeProvider{
		kinds: []KindRef{podKind},
		objects: map[string][]Object{"Pod": {
			pod("ns", "anonymous-1", "redis:6.2"),
			pod("ns", "anonymous-2", "nginx:1.21"),
		}},
	}
	res := Search(context.Background(), p, Parse("image:redis"), Options{})
	if len(res.Hits) != 1 || res.Hits[0].Name != "anonymous-1" {
		t.Fatalf("expected anonymous-1 only, got %+v", res.Hits)
	}
}

func TestSearch_LimitTruncates(t *testing.T) {
	pods := make([]Object, 0, 100)
	for i := 0; i < 100; i++ {
		pods = append(pods, pod("ns", fmt.Sprintf("pod-with-redis-%03d", i), "redis:6.2"))
	}
	p := &fakeProvider{kinds: []KindRef{podKind}, objects: map[string][]Object{"Pod": pods}}

	res := Search(context.Background(), p, Parse("redis"), Options{Limit: 10})
	if len(res.Hits) != 10 || !res.Truncated || res.TotalMatched != 100 || res.Searched != 100 {
		t.Fatalf("limit=10: hits=%d truncated=%v totalMatched=%d searched=%d", len(res.Hits), res.Truncated, res.TotalMatched, res.Searched)
	}

	res = Search(context.Background(), p, Parse("redis"), Options{Limit: 500})
	if len(res.Hits) != MaxLimit || !res.Truncated {
		t.Fatalf("limit must clamp to %d, got %d", MaxLimit, len(res.Hits))
	}

	res = Search(context.Background(), p, Parse("pod-with-redis-007"), Options{})
	if len(res.Hits) != 1 || res.Truncated {
		t.Fatalf("untruncated result flagged: %+v", res)
	}
}

func TestSearch_EmptyResultIsEmptySlice(t *testing.T) {
	p := &fakeProvider{kinds: []KindRef{podKind}}
	res := Search(context.Background(), p, Parse("nothing"), Options{})
	if res.Hits == nil || len(res.Hits) != 0 {
		t.Fatalf("hits = %#v, want empty non-nil slice", res.Hits)
	}
}

func TestSearch_DefaultSkipsEvents(t *testing.T) {
	p := &fakeProvider{
		kinds:   []KindRef{eventKind},
		objects: map[string][]Object{"Event": {{Kind: "Event", Namespace: "ns", Name: "redis-event"}}},
	}
	if res := Search(context.Background(), p, Parse("redis"), Options{}); len(res.Hits) != 0 {
		t.Fatalf("default search should skip events, got %+v", res.Hits)
	}
	if res := Search(context.Background(), p, Parse("kind:Event redis"), Options{}); len(res.Hits) != 1 {
		t.Fatalf("kind:Event should opt in, got %+v", res.Hits)
	}
}

func TestSearch_NeverScansSecrets(t *testing.T) {
	p := &fakeProvider{
		kinds:   []KindRef{secretKind},
		objects: map[string][]Object{"Secret": {{Kind: "Secret", Namespace: "ns", Name: "redis-password"}}},
	}
	for _, q := range []string{"redis", "kind:Secret redis", "kind:secrets"} {
		if res := Search(context.Background(), p, Parse(q), Options{}); len(res.Hits) != 0 {
			t.Fatalf("%q returned Secret hits: %+v", q, res.Hits)
		}
	}
	if len(p.calls) != 0 {
		t.Fatalf("Secrets were listed: %+v", p.calls)
	}
}

func TestSearch_DedupsObjectReachedTwice(t *testing.T) {
	d := deploy("kube-system", "coredns", "coredns:1.10")
	p := &fakeProvider{
		kinds:   []KindRef{deployKind, deployKind},
		objects: map[string][]Object{"Deployment": {d}},
	}
	res := Search(context.Background(), p, Parse("coredns"), Options{})
	if len(res.Hits) != 1 || res.Hits[0].Name != "coredns" {
		t.Fatalf("expected 1 hit after dedup, got %+v", res.Hits)
	}
}

func TestSearch_DynamicCRDGroupPropagates(t *testing.T) {
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "postgresql.cnpg.io/v1",
		"kind":       "Cluster",
		"metadata":   map[string]any{"name": "redis-pg", "namespace": "data", "labels": map[string]any{"app": "redis-cache-store"}},
	}}
	kr := KindRef{Kind: "Cluster", APIGroup: "postgresql.cnpg.io", Namespaced: true}
	p := &fakeProvider{
		kinds:   []KindRef{kr},
		objects: map[string][]Object{"Cluster": {ObjectFromUnstructured(u, "Cluster", "postgresql.cnpg.io")}},
	}
	res := Search(context.Background(), p, Parse("redis"), Options{})
	if len(res.Hits) != 1 || res.Hits[0].APIGroup != "postgresql.cnpg.io" {
		t.Fatalf("group not propagated: %+v", res.Hits)
	}
}

func TestSearch_NamespacesScopeNamespacedKindsOnly(t *testing.T) {
	p := &fakeProvider{
		kinds: []KindRef{podKind, nodeKind},
		objects: map[string][]Object{
			"Pod":  {pod("team-a", "redis-a", "redis"), pod("team-b", "redis-b", "redis"), pod("team-c", "redis-c", "redis")},
			"Node": {{Kind: "Node", Name: "redis-node"}},
		},
	}
	res := Search(context.Background(), p, Parse("redis"), Options{Namespaces: []string{"team-a", "team-b"}})
	names := map[string]bool{}
	for _, h := range res.Hits {
		names[h.Name] = true
	}
	if !names["redis-a"] || !names["redis-b"] || names["redis-c"] || !names["redis-node"] {
		t.Fatalf("namespace scoping wrong: %+v", res.Hits)
	}
	want := []listCall{{"Pod", "team-a"}, {"Pod", "team-b"}, {"Node", ""}}
	if !reflect.DeepEqual(p.calls, want) {
		t.Fatalf("list calls = %+v, want %+v", p.calls, want)
	}
}

func TestSearch_ListErrorMarksKindIncomplete(t *testing.T) {
	p := &fakeProvider{
		kinds:   []KindRef{podKind, deployKind},
		objects: map[string][]Object{"Pod": {pod("ns", "redis", "redis")}},
		fail:    map[string]bool{"Deployment": true},
	}
	res := Search(context.Background(), p, Parse("redis"), Options{})
	if len(res.Hits) != 1 {
		t.Fatalf("partial results lost: %+v", res)
	}
	if !reflect.DeepEqual(res.IncompleteKinds, []string{"Deployment.apps"}) {
		t.Fatalf("incompleteKinds = %v", res.IncompleteKinds)
	}
}

func TestSearch_CancelledContextMarksRemainingKinds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	p := &fakeProvider{
		kinds:   []KindRef{podKind, deployKind, nodeKind},
		objects: map[string][]Object{"Pod": {pod("ns", "redis", "redis")}},
		onList:  cancel,
	}
	res := Search(ctx, p, Parse("redis"), Options{})
	if len(res.Hits) != 1 {
		t.Fatalf("hits gathered before cancellation lost: %+v", res)
	}
	if !reflect.DeepEqual(res.IncompleteKinds, []string{"Deployment.apps", "Node"}) {
		t.Fatalf("incompleteKinds = %v", res.IncompleteKinds)
	}
}
