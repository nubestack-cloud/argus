package topology

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Profile says how far a neighbourhood may reach. Auto chooses a bounded set
// of edge types from the root's kind; all walks every type and is only ever
// asked for explicitly.
type Profile string

const (
	ProfileAuto Profile = "auto"
	ProfileAll  Profile = "all"
)

// ResolveProfile reads a caller's profile. Only "all" (any case, any
// surrounding space) widens the walk; anything else, unknown words included,
// is auto, so a typo can never broaden what is returned.
func ResolveProfile(s string) Profile {
	if strings.EqualFold(strings.TrimSpace(s), string(ProfileAll)) {
		return ProfileAll
	}
	return ProfileAuto
}

// Walk bounds. Two hops get from a Pod to its Deployment through the
// ReplicaSet and no further; 25 nodes holds a workload with its owners,
// Services, policies and mounts. The exported caps hold whatever a caller
// asks for, so the result always fits one tool response.
const (
	defaultHops          = 1
	hopCeiling           = 2
	defaultNodeBudget    = 25
	MaxNeighborhoodNodes = 50
	MaxNeighborhoodEdges = 100
)

// NeighborhoodOptions configures BuildNeighborhoodWithIndex. Zero values mean
// auto, one hop and 25 nodes.
type NeighborhoodOptions struct {
	Profile  Profile
	Hops     int
	MaxNodes int

	// Allow is asked about every node the walk reaches, the root included;
	// nil admits everything. The check happens as the walk goes: a refused
	// node takes no share of the budget and cannot connect two admitted ones,
	// and only the number refused is reported (Subgraph.Omitted). Filtering a
	// finished graph instead would let an object the caller may not see
	// decide what else they are shown.
	Allow func(*Node) bool
}

// Subgraph is the walked neighbourhood of one object. Nodes are in the order
// they were reached, the root first; Edges are the walkable edges whose two
// ends both made it in.
type Subgraph struct {
	Root      Ref    `json:"root"`
	Nodes     []Node `json:"nodes"`
	Edges     []Edge `json:"edges"`
	Truncated bool   `json:"truncated,omitempty"`
	// Omitted is how many nodes Allow refused — a count, never which.
	Omitted int `json:"omitted,omitempty"`
	// Unavailable is the kinds that could not be listed, so a sparse graph
	// reads differently from an isolated object.
	Unavailable []string `json:"unavailable,omitempty"`
	// Unmapped marks a root of a kind the graph does not draw
	// (UnmappedNeighborhood): only generic ownership is shown, and Note
	// says so.
	Unmapped bool   `json:"unmapped,omitempty"`
	Note     string `json:"note,omitempty"`
}

type edgeTypes map[EdgeType]bool

func typesOf(types ...EdgeType) edgeTypes {
	s := edgeTypes{}
	for _, t := range types {
		s[t] = true
	}
	return s
}

// every lists all edge types, so a new type joins ProfileAll by being added
// here.
var every = []EdgeType{EdgeOwns, EdgeRoutesTo, EdgeExposes, EdgeUses, EdgeConfigures, EdgeProtects}

// walkPlan is which edge types the walk follows. leaf types are followed out
// of the root and never beyond: what a workload uses — its ConfigMaps, its
// ServiceAccount, its volumes, the Node it runs on — is worth showing, but
// followed onward each of those leads to every other consumer (all the
// workloads on the namespace's default ServiceAccount, every pod on that
// node) and the budget fills with objects that have nothing to do with the
// root.
type walkPlan struct {
	onward, leaf edgeTypes
}

// atRoot is what the first hop may follow: onward and leaf types together.
func (p walkPlan) atRoot() edgeTypes {
	s := edgeTypes{}
	for t := range p.onward {
		s[t] = true
	}
	for t := range p.leaf {
		s[t] = true
	}
	return s
}

// planFor picks the walk for a root. Under auto the root's kind decides:
// a workload shows its owner chain, what fronts it and what guards it; an
// entry point shows its routing; a policy shows what it selects; a Node shows
// its pods and their owners. Kinds outside those groups walk everything.
func planFor(p Profile, root NodeKind) walkPlan {
	if p != ProfileAll {
		switch root {
		case KindPod, KindPodGroup, KindReplicaSet, KindDeployment, KindStatefulSet,
			KindDaemonSet, KindJob, KindCronJob:
			return walkPlan{typesOf(EdgeOwns, EdgeRoutesTo, EdgeExposes, EdgeProtects), typesOf(EdgeUses, EdgeConfigures)}
		case KindService, KindIngress, KindGateway, KindHTTPRoute, KindGRPCRoute, KindTLSRoute, KindTCPRoute:
			return walkPlan{onward: typesOf(EdgeRoutesTo, EdgeExposes)}
		case KindPDB, KindNetworkPolicy:
			return walkPlan{onward: typesOf(EdgeProtects)}
		case KindNode:
			return walkPlan{typesOf(EdgeOwns), typesOf(EdgeUses)}
		}
	}
	return walkPlan{onward: typesOf(every...)}
}

// rootIn finds the node a Ref names. The kind may be spelled any accepted
// way; an APIGroup, when given, must be that kind's own; a cluster-scoped
// kind's namespace is disregarded. A PodGroup is never a root.
func rootIn(nodes map[string]*Node, r Ref) *Node {
	kind, ok := normalizeKind(r.Kind)
	switch {
	case !ok, kind == KindPodGroup, r.Name == "":
		return nil
	case r.APIGroup != "" && !strings.EqualFold(r.APIGroup, builtinGroups[kind]):
		return nil
	}
	ns := r.Namespace
	if clusterScopedKinds[kind] {
		ns = ""
	}
	return nodes[buildNodeID(kind, ns, r.Name)]
}

// BuildNeighborhoodWithIndex walks t outward from root, breadth first and
// treating edges as undirected — a Service is as much a Pod's neighbour as
// the Pod is the Service's. idx, when given, answers "which edges touch this
// node" without scanning t.Edges; the result is the same either way. A root
// that is not in t, or that Allow refuses, gives an empty Subgraph, never nil.
func BuildNeighborhoodWithIndex(t *Topology, root Ref, opts NeighborhoodOptions, idx *RelationshipsIndex) *Subgraph {
	sub := &Subgraph{Root: root, Nodes: []Node{}, Edges: []Edge{}}
	if t == nil {
		return sub
	}
	sub.Unavailable = t.Unavailable
	nodes := make(map[string]*Node, len(t.Nodes))
	for i := range t.Nodes {
		nodes[t.Nodes[i].ID] = &t.Nodes[i]
	}
	start := rootIn(nodes, root)
	if start == nil {
		return sub
	}
	sub.Root = Ref{Kind: string(start.Kind), APIGroup: start.APIGroup, Namespace: start.Namespace, Name: start.Name}
	if opts.Allow != nil && !opts.Allow(start) {
		sub.Omitted = 1
		return sub
	}

	hops := min(max(opts.Hops, 0), hopCeiling)
	if hops == 0 {
		hops = defaultHops
	}
	budget := opts.MaxNodes
	if budget <= 0 {
		budget = defaultNodeBudget
	}
	plan := planFor(opts.Profile, start.Kind)
	firstHop := plan.atRoot()

	touching := func(id string, follow edgeTypes) []Edge {
		var out []Edge
		if idx != nil {
			in, outEdges := idx.EdgesFor(id)
			for _, e := range slices.Concat(outEdges, in) {
				if follow[e.Type] {
					out = append(out, e)
				}
			}
			return out
		}
		for _, e := range t.Edges {
			if follow[e.Type] && (e.Source == id || e.Target == id) {
				out = append(out, e)
			}
		}
		return out
	}

	reached := []string{start.ID}
	in := map[string]bool{start.ID: true}
	refused := map[string]bool{}
	frontier := reached
walk:
	for hop := range hops {
		follow := plan.onward
		if hop == 0 {
			follow = firstHop
		}
		var next []string
		for _, id := range frontier {
			for _, e := range touching(id, follow) {
				other := e.Target
				if other == id {
					other = e.Source
				}
				n := nodes[other]
				if n == nil || in[other] || refused[other] {
					continue
				}
				if opts.Allow != nil && !opts.Allow(n) {
					refused[other] = true
					continue
				}
				if len(in) >= budget {
					// Out of room: keep looking at this node's edges so
					// refusals are still counted, then stop the walk.
					sub.Truncated = true
					continue
				}
				in[other] = true
				reached = append(reached, other)
				next = append(next, other)
			}
			if sub.Truncated {
				break walk
			}
		}
		if len(next) == 0 {
			break
		}
		frontier = next
	}

	sub.Omitted = len(refused)
	for _, id := range reached {
		sub.Nodes = append(sub.Nodes, *nodes[id])
	}
	// Edges come from t.Edges in its own order, so an index changes nothing
	// about the output.
	for _, e := range t.Edges {
		if firstHop[e.Type] && in[e.Source] && in[e.Target] {
			sub.Edges = append(sub.Edges, e)
		}
	}
	return sub
}

// Options configures Neighborhood.
type Options struct {
	// Profile defaults to auto.
	Profile Profile
	// Hops defaults to 1 and is clamped to 2.
	Hops int
	// MaxNodes defaults to 25 and is clamped to MaxNeighborhoodNodes.
	MaxNodes int
	// Allow drops nodes the caller must not see (kinds the agent cannot
	// read, say); see NeighborhoodOptions.Allow.
	Allow func(*Node) bool
	// Dynamic adds Gateway API kinds; nil leaves them out.
	Dynamic DynamicProvider
	// Now is the grading clock; nil means time.Now.
	Now func() time.Time
}

// ErrUnsupportedKind is returned for a root kind the graph does not draw.
var ErrUnsupportedKind = errors.New("topology: unsupported kind")

// Neighborhood builds the bounded relationship graph around root: the root's
// namespace (every namespace for a cluster-scoped root) is built with root as
// the focus, then expanded by BFS. The result has at most
// MaxNeighborhoodNodes nodes and MaxNeighborhoodEdges edges; Truncated is set
// when either cap — or opts.MaxNodes — cut it short. A root that does not
// exist yields a Subgraph with no nodes and no error.
func Neighborhood(p ResourceProvider, root Ref, opts Options) (*Subgraph, error) {
	if p == nil {
		return nil, errors.New("topology: resource provider not initialized")
	}
	kind, ok := normalizeKind(root.Kind)
	if !ok || kind == KindPodGroup {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedKind, root.Kind)
	}
	if root.Name == "" {
		return nil, errors.New("topology: root name is required")
	}
	if clusterScopedKinds[kind] {
		root.Namespace = ""
	} else if root.Namespace == "" {
		return nil, fmt.Errorf("topology: %s is namespaced; root namespace is required", kind)
	}
	root.Kind = string(kind)

	buildOpts := BuildOptions{Focus: root}
	if root.Namespace != "" {
		buildOpts.Namespaces = []string{root.Namespace}
	}
	b := NewBuilder(p).WithDynamic(opts.Dynamic).WithClock(opts.Now)
	topo, err := b.Build(buildOpts)
	if err != nil {
		return nil, err
	}

	budget := opts.MaxNodes
	if budget <= 0 {
		budget = defaultNodeBudget
	}
	sub := BuildNeighborhoodWithIndex(topo, root, NeighborhoodOptions{
		Profile:  ResolveProfile(string(opts.Profile)),
		Hops:     opts.Hops,
		MaxNodes: min(budget, MaxNeighborhoodNodes),
		Allow:    opts.Allow,
	}, IndexByResource(topo))
	capEdges(sub)
	return sub, nil
}

// capEdges cuts sub to MaxNeighborhoodEdges and marks it truncated. The
// root's own edges are kept ahead of the rest: they are what the graph is
// for.
func capEdges(sub *Subgraph) {
	if len(sub.Edges) <= MaxNeighborhoodEdges {
		return
	}
	var root string
	if len(sub.Nodes) > 0 {
		root = sub.Nodes[0].ID
	}
	onRoot := func(e Edge) bool { return e.Source == root || e.Target == root }
	slices.SortStableFunc(sub.Edges, func(a, b Edge) int {
		switch {
		case onRoot(a) && !onRoot(b):
			return -1
		case onRoot(b) && !onRoot(a):
			return 1
		}
		return 0
	})
	sub.Edges = sub.Edges[:MaxNeighborhoodEdges]
	sub.Truncated = true
}
