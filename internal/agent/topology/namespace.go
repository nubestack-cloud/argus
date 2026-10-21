package topology

import (
	"errors"
	"sort"
	"time"
)

// Namespace-map caps. A namespace is drawn whole when it fits; past the cap
// the most telling objects are kept (entry points, then workloads, then what
// they use) and everything dropped is counted by kind, never silently.
const (
	NamespaceDefaultMaxNodes = 150
	NamespaceMaxNodes        = 300
	NamespaceMaxEdges        = 600
)

// namespaceKindRank orders kinds for the cap: traffic entry points and the
// workloads behind them first, configuration and storage last. A lower rank
// survives the cap first; unlisted kinds rank after all of these.
var namespaceKindRank = map[NodeKind]int{
	KindGateway: 0, KindHTTPRoute: 0, KindGRPCRoute: 0, KindTCPRoute: 0, KindTLSRoute: 0, KindIngress: 0,
	KindService:    1,
	KindDeployment: 2, KindStatefulSet: 2, KindDaemonSet: 2, KindCronJob: 2,
	KindJob: 3, KindReplicaSet: 3,
	KindPodGroup: 4, KindPod: 4,
	KindHPA: 5, KindPDB: 5, KindNetworkPolicy: 5,
	KindPVC: 6, KindPV: 6,
	KindConfigMap: 7, KindServiceAccount: 7,
}

// healthRank puts a problem ahead of a healthy object of the same kind rank,
// so a cap never drops the object someone opened the map to find.
var healthRank = map[HealthStatus]int{StatusUnhealthy: 0, StatusDegraded: 1, StatusUnknown: 2, StatusNeutral: 3, StatusHealthy: 4}

// NamespaceOptions configures NamespaceMap.
type NamespaceOptions struct {
	// MaxNodes defaults to NamespaceDefaultMaxNodes and is clamped to
	// NamespaceMaxNodes.
	MaxNodes int
	Dynamic  DynamicProvider
	Now      func() time.Time
}

// NamespaceGraph is one namespace's relationship graph, capped.
type NamespaceGraph struct {
	Namespace string `json:"namespace"`
	Nodes     []Node `json:"nodes"`
	Edges     []Edge `json:"edges"`
	// TotalNodes is how many nodes the namespace has before the cap;
	// OmittedNodes = TotalNodes - len(Nodes), broken down in OmittedByKind.
	TotalNodes    int            `json:"totalNodes"`
	OmittedNodes  int            `json:"omittedNodes,omitempty"`
	OmittedByKind map[string]int `json:"omittedByKind,omitempty"`
	// OmittedEdges counts edges dropped because an endpoint was omitted or
	// the edge cap was reached.
	OmittedEdges int  `json:"omittedEdges,omitempty"`
	Truncated    bool `json:"truncated,omitempty"`
	// ClusterNodes counts the cluster Nodes the namespace's pods run on.
	// They are left out of the map: every pod links to one, and a
	// namespace map drawn around them shows scheduling, not the app.
	ClusterNodes int `json:"clusterNodes,omitempty"`
	// Unavailable names kinds that could not be listed, so a sparse map
	// reads as partial rather than as an empty namespace.
	Unavailable []string `json:"unavailable,omitempty"`
}

// NamespaceMap builds the whole graph of one namespace: replica pods sharing
// a group collapse into one PodGroup node, Deployment-owned ReplicaSets are
// hidden behind their Deployment (as in the neighbourhood), and cluster
// Nodes are left out. The result is capped at opts.MaxNodes nodes and
// NamespaceMaxEdges edges with honest omitted counts.
func NamespaceMap(p ResourceProvider, namespace string, opts NamespaceOptions) (*NamespaceGraph, error) {
	if p == nil {
		return nil, errors.New("topology: resource provider not initialized")
	}
	if namespace == "" {
		return nil, errors.New("topology: namespace is required")
	}
	maxNodes := opts.MaxNodes
	if maxNodes <= 0 {
		maxNodes = NamespaceDefaultMaxNodes
	}
	if maxNodes > NamespaceMaxNodes {
		maxNodes = NamespaceMaxNodes
	}
	topo, err := NewBuilder(p).WithDynamic(opts.Dynamic).WithClock(opts.Now).Build(BuildOptions{
		Namespaces:        []string{namespace},
		MaxIndividualPods: 1,
		GroupPodsByOwner:  true,
	})
	if err != nil {
		return nil, err
	}
	out := &NamespaceGraph{Namespace: namespace, Nodes: []Node{}, Edges: []Edge{}, Unavailable: topo.Unavailable}

	candidates := make([]Node, 0, len(topo.Nodes))
	clusterNodes := map[string]bool{}
	for _, n := range topo.Nodes {
		if n.Kind == KindNode {
			clusterNodes[n.ID] = true
			continue
		}
		candidates = append(candidates, n)
	}
	out.TotalNodes = len(candidates)
	out.ClusterNodes = len(clusterNodes)

	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		if ra, rb := kindRank(a.Kind), kindRank(b.Kind); ra != rb {
			return ra < rb
		}
		if ha, hb := healthRank[a.Status], healthRank[b.Status]; ha != hb {
			return ha < hb
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.Name < b.Name
	})
	kept := map[string]bool{}
	for _, n := range candidates {
		if len(out.Nodes) >= maxNodes {
			if out.OmittedByKind == nil {
				out.OmittedByKind = map[string]int{}
			}
			out.OmittedByKind[string(n.Kind)]++
			out.OmittedNodes++
			continue
		}
		kept[n.ID] = true
		out.Nodes = append(out.Nodes, n)
	}
	for _, e := range topo.Edges {
		if clusterNodes[e.Source] || clusterNodes[e.Target] {
			continue // left out by design, not by the cap
		}
		if !kept[e.Source] || !kept[e.Target] {
			out.OmittedEdges++
			continue
		}
		if len(out.Edges) >= NamespaceMaxEdges {
			out.OmittedEdges++
			continue
		}
		out.Edges = append(out.Edges, e)
	}
	out.Truncated = out.OmittedNodes > 0 || out.OmittedEdges > 0
	return out, nil
}

func kindRank(k NodeKind) int {
	if r, ok := namespaceKindRank[k]; ok {
		return r
	}
	return 8
}
