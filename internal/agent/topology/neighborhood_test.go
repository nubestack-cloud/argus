package topology

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// makeNode is a healthy node whose ID is the one the builder would give it.
func makeNode(kind NodeKind, ns, name string) Node {
	if clusterScopedKinds[kind] {
		ns = ""
	}
	return Node{ID: buildNodeID(kind, ns, name), Kind: kind, APIGroup: builtinGroups[kind], Namespace: ns, Name: name, Status: StatusHealthy}
}

func makeEdge(typ EdgeType, source, target string) Edge {
	return Edge{ID: source + "|" + string(typ) + "|" + target, Source: source, Target: target, Type: typ}
}

// graph builds a Topology from "kind/ns/name -type-> kind/ns/name" lines,
// creating each node the first time it is named.
func graph(lines ...string) *Topology {
	topo := &Topology{}
	seen := map[string]bool{}
	node := func(id string) string {
		parts := strings.SplitN(id, "/", 3)
		kind, ok := normalizeKind(parts[0])
		if !ok {
			panic("unknown kind in " + id)
		}
		n := makeNode(kind, parts[1], parts[2])
		if !seen[n.ID] {
			seen[n.ID] = true
			topo.Nodes = append(topo.Nodes, n)
		}
		return n.ID
	}
	for _, l := range lines {
		f := strings.Fields(l)
		typ := strings.TrimSuffix(strings.TrimPrefix(f[1], "-"), "->")
		topo.Edges = append(topo.Edges, makeEdge(EdgeType(typ), node(f[0]), node(f[2])))
	}
	return topo
}

// shop is one checkout pod and everything around it, plus a second consumer
// of its ConfigMap (ledger) that only a walk past the root would reach.
func shop() *Topology {
	return graph(
		"deployment/shop/checkout -owns-> replicaset/shop/checkout-5f",
		"replicaset/shop/checkout-5f -owns-> pod/shop/checkout-5f-a",
		"service/shop/checkout -exposes-> pod/shop/checkout-5f-a",
		"ingress/shop/storefront -routes-to-> service/shop/checkout",
		"poddisruptionbudget/shop/checkout -protects-> pod/shop/checkout-5f-a",
		"networkpolicy/shop/checkout-in -protects-> pod/shop/checkout-5f-a",
		"configmap/shop/common -configures-> pod/shop/checkout-5f-a",
		"configmap/shop/common -configures-> pod/shop/ledger-7c-b",
		"persistentvolumeclaim/shop/cart-data -uses-> pod/shop/checkout-5f-a",
		"node//worker-2 -uses-> pod/shop/checkout-5f-a",
	)
}

func nodeIDs(s *Subgraph) []string {
	var out []string
	for _, n := range s.Nodes {
		out = append(out, n.ID)
	}
	slices.Sort(out)
	return out
}

var checkoutPod = Ref{Kind: "Pod", Namespace: "shop", Name: "checkout-5f-a"}

func TestNeighborhoodWalk(t *testing.T) {
	const (
		pod, rs, dep = "pod/shop/checkout-5f-a", "replicaset/shop/checkout-5f", "deployment/shop/checkout"
		svc, ing     = "service/shop/checkout", "ingress/shop/storefront"
		pdb, np      = "poddisruptionbudget/shop/checkout", "networkpolicy/shop/checkout-in"
		cm, pvc, nd  = "configmap/shop/common", "persistentvolumeclaim/shop/cart-data", "node//worker-2"
		ledger       = "pod/shop/ledger-7c-b"
	)
	notRS := func(n *Node) bool { return n.Kind != KindReplicaSet }
	cases := []struct {
		name      string
		root      Ref
		opts      NeighborhoodOptions
		want      []string
		truncated bool
		omitted   int
	}{
		// A workload root: owners, network and policy onward; what it uses
		// (ConfigMap, claim, Node) from the root only.
		{"pod, one hop", checkoutPod, NeighborhoodOptions{Hops: 1}, []string{pod, rs, svc, pdb, np, cm, pvc, nd}, false, 0},
		{"pod, two hops", checkoutPod, NeighborhoodOptions{Hops: 2}, []string{pod, rs, svc, pdb, np, cm, pvc, nd, dep, ing}, false, 0},
		{"hops above the ceiling", checkoutPod, NeighborhoodOptions{Hops: 40}, []string{pod, rs, svc, pdb, np, cm, pvc, nd, dep, ing}, false, 0},
		{"defaults are one hop", checkoutPod, NeighborhoodOptions{}, []string{pod, rs, svc, pdb, np, cm, pvc, nd}, false, 0},
		// Profile all follows the ConfigMap on to its other consumer.
		{"all, two hops", checkoutPod, NeighborhoodOptions{Profile: ProfileAll, Hops: 2}, []string{pod, rs, svc, pdb, np, cm, pvc, nd, dep, ing, ledger}, false, 0},
		{"unknown profile is auto", checkoutPod, NeighborhoodOptions{Profile: "everything", Hops: 2}, []string{pod, rs, svc, pdb, np, cm, pvc, nd, dep, ing}, false, 0},
		{"service", Ref{Kind: "Service", Namespace: "shop", Name: "checkout"}, NeighborhoodOptions{Hops: 1}, []string{svc, pod, ing}, false, 0},
		{"pdb", Ref{Kind: "pdb", Namespace: "shop", Name: "checkout"}, NeighborhoodOptions{Hops: 1}, []string{pdb, pod}, false, 0},
		// A policy shows what it selects (and, a hop on, what else selects it).
		{"pdb, two hops", Ref{Kind: "pdb", Namespace: "shop", Name: "checkout"}, NeighborhoodOptions{Hops: 2}, []string{pdb, pod, np}, false, 0},
		// A Node: the pods on it, then their owners, and not their storage.
		{"node", Ref{Kind: "Node", Name: "worker-2"}, NeighborhoodOptions{Hops: 2}, []string{nd, pod, rs}, false, 0},
		{"budget", checkoutPod, NeighborhoodOptions{Profile: ProfileAll, Hops: 2, MaxNodes: 3}, nil, true, 0},
		// A refused node is not shown, is counted, and does not lead on to
		// the Deployment behind it.
		{"refused node", checkoutPod, NeighborhoodOptions{Profile: ProfileAll, Hops: 2, Allow: notRS}, []string{pod, svc, pdb, np, cm, pvc, nd, ing, ledger}, false, 1},
		// ...and does not use up the budget.
		{"refused node and budget", checkoutPod, NeighborhoodOptions{Profile: ProfileAll, Hops: 2, MaxNodes: 2, Allow: notRS}, nil, true, 1},
		{"refused root", Ref{Kind: "ConfigMap", Namespace: "shop", Name: "common"}, NeighborhoodOptions{Allow: func(n *Node) bool { return n.Kind != KindConfigMap }}, []string{}, false, 1},
		{"missing root", Ref{Kind: "Pod", Namespace: "shop", Name: "gone"}, NeighborhoodOptions{}, []string{}, false, 0},
	}
	topo := shop()
	idx := IndexByResource(topo)
	for _, c := range cases {
		for _, index := range []*RelationshipsIndex{nil, idx} {
			sub := BuildNeighborhoodWithIndex(topo, c.root, c.opts, index)
			got := nodeIDs(sub)
			if c.want != nil {
				want := slices.Sorted(slices.Values(c.want))
				if len(want) == 0 {
					want = nil
				}
				if !slices.Equal(got, want) {
					t.Errorf("%s (index=%v): nodes %v, want %v", c.name, index != nil, got, want)
				}
			}
			if sub.Truncated != c.truncated || sub.Omitted != c.omitted {
				t.Errorf("%s (index=%v): truncated=%v omitted=%d", c.name, index != nil, sub.Truncated, sub.Omitted)
			}
			if c.truncated && (len(sub.Nodes) != c.opts.MaxNodes || sub.Nodes[0].ID != pod) {
				t.Errorf("%s: %d nodes, first %v; want the budget, root first", c.name, len(sub.Nodes), got)
			}
			if c.opts.Allow != nil && slices.Contains(got, rs) {
				t.Errorf("%s: refused ReplicaSet shown", c.name)
			}
		}
	}
}

// Edges are kept only when both ends are in, and only of the types walked.
func TestNeighborhoodEdgesStayInside(t *testing.T) {
	sub := BuildNeighborhoodWithIndex(shop(), checkoutPod, NeighborhoodOptions{Hops: 1}, nil)
	var got []string
	for e := range edgeSet(sub.Edges) {
		got = append(got, e)
	}
	slices.Sort(got)
	want := []string{
		"configmap/shop/common -configures-> pod/shop/checkout-5f-a",
		"networkpolicy/shop/checkout-in -protects-> pod/shop/checkout-5f-a",
		"node//worker-2 -uses-> pod/shop/checkout-5f-a",
		"persistentvolumeclaim/shop/cart-data -uses-> pod/shop/checkout-5f-a",
		"poddisruptionbudget/shop/checkout -protects-> pod/shop/checkout-5f-a",
		"replicaset/shop/checkout-5f -owns-> pod/shop/checkout-5f-a",
		"service/shop/checkout -exposes-> pod/shop/checkout-5f-a",
	}
	if !slices.Equal(got, want) {
		t.Errorf("edges:\n got  %v\n want %v", got, want)
	}
}

func TestNeighborhoodEdgeCases(t *testing.T) {
	if sub := BuildNeighborhoodWithIndex(nil, checkoutPod, NeighborhoodOptions{}, nil); sub == nil || len(sub.Nodes)+len(sub.Edges) != 0 {
		t.Errorf("nil topology = %+v", sub)
	}
	if sub := BuildNeighborhoodWithIndex(shop(), Ref{Kind: "Pod", Namespace: "shop", Name: "gone"}, NeighborhoodOptions{}, nil); sub.Root.Name != "gone" {
		t.Errorf("a missing root is echoed back: %+v", sub.Root)
	}
	for in, want := range map[string]Profile{"all": ProfileAll, " ALL ": ProfileAll, "": ProfileAuto, "auto": ProfileAuto, "al": ProfileAuto} {
		if got := ResolveProfile(in); got != want {
			t.Errorf("ResolveProfile(%q) = %s", in, got)
		}
	}
}

// Root lookup accepts any spelling of the kind, matches the kind's own API
// group (or none), and refuses a mismatched group.
func TestBuildNeighborhood_RootKindAndGroupResolution(t *testing.T) {
	topo := shop()
	for _, ref := range []Ref{
		{Kind: "Deployment", Namespace: "shop", Name: "checkout"},
		{Kind: "deployments", Namespace: "shop", Name: "checkout"},
		{Kind: "deploy", Namespace: "shop", Name: "checkout"},
		{Kind: "Deployment", APIGroup: "apps", Namespace: "shop", Name: "checkout"},
	} {
		sub := BuildNeighborhoodWithIndex(topo, ref, NeighborhoodOptions{}, nil)
		if len(sub.Nodes) == 0 || sub.Nodes[0].ID != "deployment/shop/checkout" {
			t.Errorf("%+v did not resolve the Deployment: %v", ref, nodeIDs(sub))
		}
		if sub.Root.Kind != "Deployment" || sub.Root.APIGroup != "apps" {
			t.Errorf("resolved root = %+v, want canonical kind and group", sub.Root)
		}
	}
	for _, ref := range []Ref{
		{Kind: "Deployment", APIGroup: "wrong.example", Namespace: "shop", Name: "checkout"},
		{Kind: "Widget", Namespace: "shop", Name: "checkout"},
		{Kind: "PodGroup", Namespace: "shop", Name: "checkout"},
	} {
		if sub := BuildNeighborhoodWithIndex(topo, ref, NeighborhoodOptions{}, nil); len(sub.Nodes) != 0 {
			t.Errorf("%+v resolved %v, want nothing", ref, nodeIDs(sub))
		}
	}
}

// Typed objects carry no TypeMeta; the builder knows each kind's group, and
// a root resolves with the group omitted, given, or not at all with a wrong one.
func TestBuiltInNeighborhoodAPIGroups(t *testing.T) {
	meta := metav1.ObjectMeta{Namespace: "default", Name: "example"}
	provider := &mockProvider{
		deployments:  []*appsv1.Deployment{{ObjectMeta: meta}},
		statefulSets: []*appsv1.StatefulSet{{ObjectMeta: meta}},
		daemonSets:   []*appsv1.DaemonSet{{ObjectMeta: meta}},
	}
	topo := build(t, provider, BuildOptions{})
	idx := IndexByResource(topo)
	for _, tc := range []struct {
		kind  NodeKind
		group string
	}{{KindDeployment, "apps"}, {KindStatefulSet, "apps"}, {KindDaemonSet, "apps"}} {
		for _, group := range []string{"", tc.group, "wrong.example"} {
			sub := BuildNeighborhoodWithIndex(topo, Ref{Kind: string(tc.kind), APIGroup: group, Namespace: "default", Name: "example"}, NeighborhoodOptions{}, idx)
			if group == "wrong.example" {
				if len(sub.Nodes) != 0 {
					t.Fatalf("wrong group resolved: %+v", sub.Nodes)
				}
				continue
			}
			if len(sub.Nodes) == 0 || sub.Nodes[0].Kind != tc.kind || sub.Nodes[0].APIGroup != tc.group {
				t.Fatalf("group %q did not resolve %s: %+v", group, tc.kind, sub.Nodes)
			}
		}
	}
}

// --- Neighborhood (build + expand) ------------------------------------------

func incidentProvider() *mockProvider {
	labels := map[string]string{"app": "cart"}
	pods := []*corev1.Pod{}
	for i := 0; i < 8; i++ {
		p := runningPod("prod", fmt.Sprintf("cart-%d", i), "cart-rs", labels)
		p.Spec.NodeName = "worker-1"
		pods = append(pods, p)
	}
	// The broken pod is one of eight, so it would collapse into a PodGroup
	// if it were not the focus.
	pods[3].Status.ContainerStatuses[0].Ready = false
	pods[3].Status.ContainerStatuses[0].RestartCount = 7
	pods[3].Status.ContainerStatuses[0].State = corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: "CrashLoopBackOff"}}
	pods[3].Spec.Volumes = []corev1.Volume{{Name: "cfg", VolumeSource: corev1.VolumeSource{
		ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: "cart-config"}},
	}}}
	pods = append(pods, runningPod("other", "unrelated", "", map[string]string{"app": "cart"}))
	return &mockProvider{
		pods:        pods,
		deployments: []*appsv1.Deployment{deployment("prod", "cart", labels)},
		replicaSets: []*appsv1.ReplicaSet{replicaSet("prod", "cart-rs", "cart", labels)},
		services:    []*corev1.Service{{ObjectMeta: metav1.ObjectMeta{Name: "cart", Namespace: "prod"}, Spec: corev1.ServiceSpec{Selector: labels}}},
		configMaps:  []*corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "cart-config", Namespace: "prod"}, Data: map[string]string{"k": "sha256:" + strings.Repeat("a", 64)}}},
		nodes: []*corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"}, Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
		}}},
	}
}

func TestNeighborhood_FocusPodStaysIndividual(t *testing.T) {
	p := incidentProvider()
	sub, err := Neighborhood(p, Ref{Kind: "Pod", Namespace: "prod", Name: "cart-3"}, Options{Hops: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.Nodes) == 0 || sub.Nodes[0].ID != "pod/prod/cart-3" {
		t.Fatalf("root pod not resolved: %v", nodeIDs(sub))
	}
	root := sub.Nodes[0]
	if root.Status != StatusUnhealthy || root.StatusReason != "CrashLoopBackOff" {
		t.Errorf("root status = %s/%s, want unhealthy/CrashLoopBackOff", root.Status, root.StatusReason)
	}
	edges := edgeSet(sub.Edges)
	for _, want := range []string{
		"deployment/prod/cart -owns-> pod/prod/cart-3",
		"configmap/prod/cart-config -configures-> pod/prod/cart-3",
		"node//worker-1 -uses-> pod/prod/cart-3",
		"service/prod/cart -exposes-> deployment/prod/cart",
	} {
		if !edges[want] {
			t.Errorf("missing edge %s in %v", want, edges)
		}
	}
	// The other seven pods collapse into one group under the Deployment.
	if !edges["deployment/prod/cart -owns-> podgroup-prod-app-cart"] {
		t.Errorf("expected the sibling pods as one PodGroup: %v", nodeIDs(sub))
	}
	for _, n := range sub.Nodes {
		if n.Namespace == "other" {
			t.Errorf("neighbourhood crossed into another namespace: %s", n.ID)
		}
	}
	// Only the root's namespace was listed.
	for _, ns := range p.calls[KindPod] {
		if ns != "prod" {
			t.Errorf("pods listed in namespace %q, want only prod", ns)
		}
	}
}

func TestNeighborhood_UnreferencedFocusStillResolves(t *testing.T) {
	p := &mockProvider{
		configMaps: []*corev1.ConfigMap{{ObjectMeta: metav1.ObjectMeta{Name: "orphan", Namespace: "prod"}}},
		pvcs:       []*corev1.PersistentVolumeClaim{{ObjectMeta: metav1.ObjectMeta{Name: "orphan-data", Namespace: "prod"}}},
	}
	for _, root := range []Ref{
		{Kind: "ConfigMap", Namespace: "prod", Name: "orphan"},
		{Kind: "pvc", Namespace: "prod", Name: "orphan-data"},
	} {
		sub, err := Neighborhood(p, root, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if len(sub.Nodes) != 1 {
			t.Errorf("%+v: expected the unreferenced root alone, got %v", root, nodeIDs(sub))
		}
	}
}

func TestNeighborhood_ClusterScopedRoot(t *testing.T) {
	p := incidentProvider()
	sub, err := Neighborhood(p, Ref{Kind: "Node", Namespace: "ignored", Name: "worker-1"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.Nodes) == 0 || sub.Nodes[0].ID != "node//worker-1" || sub.Root.Namespace != "" {
		t.Fatalf("node root not resolved: root=%+v nodes=%v", sub.Root, nodeIDs(sub))
	}
	if len(sub.Nodes) < 2 {
		t.Errorf("expected the hosted pods around the node, got %v", nodeIDs(sub))
	}
}

func TestNeighborhood_RejectsBadRoots(t *testing.T) {
	p := incidentProvider()
	if _, err := Neighborhood(p, Ref{Kind: "Secret", Namespace: "prod", Name: "tls"}, Options{}); !errors.Is(err, ErrUnsupportedKind) {
		t.Errorf("Secret root: err = %v, want ErrUnsupportedKind", err)
	}
	if _, err := Neighborhood(p, Ref{Kind: "Pod", Name: "cart-3"}, Options{}); err == nil {
		t.Error("namespaced root without namespace must error")
	}
	if _, err := Neighborhood(p, Ref{Kind: "Pod", Namespace: "prod"}, Options{}); err == nil {
		t.Error("root without name must error")
	}
	if _, err := Neighborhood(nil, Ref{Kind: "Pod", Namespace: "prod", Name: "x"}, Options{}); err == nil {
		t.Error("nil provider must error")
	}
	sub, err := Neighborhood(p, Ref{Kind: "Pod", Namespace: "prod", Name: "missing"}, Options{})
	if err != nil || len(sub.Nodes) != 0 {
		t.Errorf("missing root: sub=%v err=%v, want empty and no error", sub, err)
	}
}

// Whatever the caller asks for, the result stays within the node and edge
// caps and says so.
func TestNeighborhood_Caps(t *testing.T) {
	labels := map[string]string{"app": "big"}
	p := &mockProvider{deployments: []*appsv1.Deployment{deployment("prod", "big", labels)}}
	for i := 0; i < 120; i++ {
		p.services = append(p.services, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: fmt.Sprintf("svc-%03d", i), Namespace: "prod"},
			Spec:       corev1.ServiceSpec{Selector: labels},
		})
	}
	sub, err := Neighborhood(p, Ref{Kind: "Deployment", Namespace: "prod", Name: "big"}, Options{MaxNodes: 1000, Hops: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(sub.Nodes) > MaxNeighborhoodNodes || len(sub.Edges) > MaxNeighborhoodEdges {
		t.Fatalf("caps exceeded: %d nodes, %d edges", len(sub.Nodes), len(sub.Edges))
	}
	if len(sub.Nodes) != MaxNeighborhoodNodes || !sub.Truncated {
		t.Errorf("expected exactly %d nodes and truncated, got %d truncated=%v", MaxNeighborhoodNodes, len(sub.Nodes), sub.Truncated)
	}

	// The edge cap keeps the root's own edges first.
	topo := &Topology{}
	hub := makeNode(KindDeployment, "prod", "hub")
	topo.Nodes = append(topo.Nodes, hub)
	for i := 0; i < 30; i++ {
		svc := makeNode(KindService, "prod", fmt.Sprintf("s%02d", i))
		topo.Nodes = append(topo.Nodes, svc)
	}
	for i := 0; i < 30; i++ {
		for j := 0; j < 30; j++ {
			if i != j {
				topo.Edges = append(topo.Edges, makeEdge(EdgeRoutesTo, topo.Nodes[1+i].ID, topo.Nodes[1+j].ID))
			}
		}
	}
	for i := 0; i < 30; i++ {
		topo.Edges = append(topo.Edges, makeEdge(EdgeExposes, topo.Nodes[1+i].ID, hub.ID))
	}
	sub = BuildNeighborhoodWithIndex(topo, Ref{Kind: "Deployment", Namespace: "prod", Name: "hub"}, NeighborhoodOptions{MaxNodes: 50}, nil)
	if len(sub.Edges) <= MaxNeighborhoodEdges {
		t.Fatalf("fixture should exceed the edge cap before capping, got %d", len(sub.Edges))
	}
	capEdges(sub)
	if len(sub.Edges) != MaxNeighborhoodEdges || !sub.Truncated {
		t.Fatalf("capEdges: %d edges truncated=%v", len(sub.Edges), sub.Truncated)
	}
	rootEdges := 0
	for _, e := range sub.Edges {
		if e.Target == hub.ID {
			rootEdges++
		}
	}
	if rootEdges != 30 {
		t.Errorf("edge cap dropped root edges: kept %d of 30", rootEdges)
	}
}

func TestNeighborhood_ReportsUnavailableKinds(t *testing.T) {
	p := incidentProvider()
	p.fail = map[NodeKind]bool{KindService: true}
	sub, err := Neighborhood(p, Ref{Kind: "Pod", Namespace: "prod", Name: "cart-3"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sub.Unavailable, []string{"Service"}) {
		t.Errorf("Unavailable = %v, want [Service]", sub.Unavailable)
	}
	if len(sub.Nodes) == 0 {
		t.Error("a failed Service list must not stop the rest of the graph")
	}
}

// The tool-result shape: nodes and edges are arrays, never null, and node
// summaries carry no spec, env, annotations or ConfigMap data.
func TestNeighborhood_JSONShape(t *testing.T) {
	p := incidentProvider()
	p.pods[3].Annotations = map[string]string{"secret-ish": "do-not-leak"}
	p.pods[3].Spec.Containers[0].Env = []corev1.EnvVar{{Name: "TOKEN", Value: "sha256:" + strings.Repeat("b", 64)}}
	sub, err := Neighborhood(p, Ref{Kind: "Pod", Namespace: "prod", Name: "cart-3"}, Options{Hops: 2})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(sub)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"do-not-leak", "TOKEN", strings.Repeat("a", 64), strings.Repeat("b", 64), "annotations", `"env"`, `"spec"`} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("neighbourhood JSON contains %q: %s", leak, raw)
		}
	}
	empty, _ := json.Marshal(BuildNeighborhoodWithIndex(nil, Ref{Kind: "Pod", Namespace: "x", Name: "y"}, NeighborhoodOptions{}, nil))
	if !strings.Contains(string(empty), `"nodes":[]`) || !strings.Contains(string(empty), `"edges":[]`) {
		t.Errorf("empty subgraph must marshal arrays, got %s", empty)
	}
}
