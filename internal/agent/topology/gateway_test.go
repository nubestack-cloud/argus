package topology

import (
	"slices"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// A route reference means the object its group and kind name, not anything
// that happens to share the name: a parentRef to a core Service named like a
// Gateway is not that Gateway, and a backendRef into another API group is not
// the core Service of that name. Two listeners on one Gateway, or the same
// backend in two rules, still make one edge.
func TestGatewayRouteEdgesHonorExplicitReferenceIdentity(t *testing.T) {
	ref := func(kv ...any) any {
		m := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	route := gatewayObject("HTTPRoute", "team", "web")
	route.Object["spec"] = map[string]any{
		"hostnames": []any{"web.example.com"},
		"parentRefs": []any{
			ref("name", "public", "sectionName", "http"),
			ref("name", "public", "sectionName", "https"),
			ref("group", "", "kind", "Service", "name", "internal"),
		},
		"rules": []any{
			map[string]any{"backendRefs": []any{ref("name", "web", "port", int64(8080))}},
			map[string]any{"backendRefs": []any{
				ref("name", "web", "port", int64(8080)),
				ref("group", "mesh.example.io", "kind", "Service", "name", "api", "port", int64(8080)),
			}},
		},
	}
	dynamic := &gatewayDynamic{objs: map[string][]*unstructured.Unstructured{
		"Gateway":   {gatewayObject("Gateway", "team", "public"), gatewayObject("Gateway", "team", "internal")},
		"HTTPRoute": {route},
	}}
	provider := &mockProvider{services: []*corev1.Service{
		{ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "web"}},
		{ObjectMeta: metav1.ObjectMeta{Namespace: "team", Name: "api"}},
	}}

	topo, err := NewBuilder(provider).WithDynamic(dynamic).Build(BuildOptions{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	var links []string
	for _, e := range topo.Edges {
		links = append(links, e.Source+" -> "+e.Target)
	}
	slices.Sort(links)
	if want := []string{"gateway/team/public -> httproute/team/web", "httproute/team/web -> service/team/web"}; !slices.Equal(links, want) {
		t.Errorf("edges = %v, want %v", links, want)
	}
	rn := nodeByID(topo.Nodes, "httproute/team/web")
	if rn == nil || rn.APIGroup != GatewayAPIGroup || rn.Summary["rulesCount"] != 2 {
		t.Errorf("route node = %+v", rn)
	}
	if len(topo.Unavailable) != 0 {
		t.Errorf("unserved route kinds must not mark the graph incomplete: %v", topo.Unavailable)
	}
}

// A Gateway API kind the agent cannot list marks the graph incomplete; one
// the cluster does not serve does not. Without a dynamic provider the kinds
// are simply absent.
func TestGatewayAPIAvailability(t *testing.T) {
	dynamic := &gatewayDynamic{
		objs: map[string][]*unstructured.Unstructured{"Gateway": {}},
		fail: map[string]bool{"HTTPRoute": true},
	}
	topo, err := NewBuilder(&mockProvider{}).WithDynamic(dynamic).Build(BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(topo.Unavailable, []string{"HTTPRoute"}) {
		t.Errorf("Unavailable = %v, want [HTTPRoute]", topo.Unavailable)
	}
	topo, err = NewBuilder(&mockProvider{}).Build(BuildOptions{})
	if err != nil || len(topo.Unavailable) != 0 || len(topo.Nodes) != 0 {
		t.Errorf("no dynamic provider: topo=%+v err=%v", topo, err)
	}
}

// A Service root reaches the Gateway through its route.
func TestNeighborhood_ThroughGatewayRoute(t *testing.T) {
	route := gatewayObject("HTTPRoute", "team", "web")
	route.Object["spec"] = map[string]any{
		"parentRefs": []any{map[string]any{"name": "edge"}},
		"rules":      []any{map[string]any{"backendRefs": []any{map[string]any{"name": "web"}}}},
	}
	dynamic := &gatewayDynamic{objs: map[string][]*unstructured.Unstructured{
		"Gateway":   {gatewayObject("Gateway", "team", "edge")},
		"HTTPRoute": {route},
	}}
	provider := &mockProvider{services: []*corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "team"}}}}
	sub, err := Neighborhood(provider, Ref{Kind: "Service", Namespace: "team", Name: "web"}, Options{Hops: 2, Dynamic: dynamic})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"gateway/team/edge", "httproute/team/web", "service/team/web"}
	if got := nodeIDs(sub); !slices.Equal(got, want) {
		t.Errorf("nodes = %v, want %v", got, want)
	}
	sub, err = Neighborhood(provider, Ref{Kind: "HTTPRoute", APIGroup: GatewayAPIGroup, Namespace: "team", Name: "web"}, Options{Dynamic: dynamic})
	if err != nil || len(sub.Nodes) != 3 {
		t.Errorf("route root: %v err=%v", nodeIDs(sub), err)
	}
}
