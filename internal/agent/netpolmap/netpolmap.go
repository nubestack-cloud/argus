// Package netpolmap answers, for one namespace, "what can reach each workload,
// what can each workload reach, and where is that wider or narrower than it
// looks" from core NetworkPolicy objects alone. It powers the cluster page's
// Network policy tab (get_network_policy_map).
//
// Every selector is resolved to what it matches NOW: a podSelector to the
// workloads whose pods it selects, a namespaceSelector without a podSelector
// to the namespace, an ipBlock to the CIDR plus any node whose address falls
// in it. A selector that matches nothing is reported as matching nothing,
// never dropped, because "this rule admits nobody" is the finding.
//
// It is a static prediction. The network plugin enforces policy, and
// plugin-specific kinds (CiliumNetworkPolicy, Calico's) are not read; the
// caller says so. Pure: no API calls.
package netpolmap

import (
	"fmt"
	"net"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"argus/internal/agent/netpol"
)

// Caps keep one namespace inside the tunnel frame budget. Each is reported
// as truncated when hit, never silently.
const (
	MaxWorkloads     = 300
	MaxAllowsPerSide = 40
	MaxFindingItems  = 25
)

// Input is the cluster state the map is built from. Pods, policies and
// namespaces are cluster-wide: a peer in another namespace is resolved
// against that namespace's pods, and the effective check reads the peer's
// own policies.
type Input struct {
	Namespaces  []*corev1.Namespace
	Pods        []*corev1.Pod
	ReplicaSets []*appsv1.ReplicaSet
	Jobs        []*batchv1.Job
	Nodes       []*corev1.Node
	Policies    []*networkingv1.NetworkPolicy
}

// Peer is one end a rule admits.
type Peer struct {
	// Type is workload | namespace | cidr | anywhere | none.
	//   workload: the pods of one workload (Kind/Namespace/Name).
	//   namespace: every pod in Namespace (a namespaceSelector, or an empty
	//     podSelector, with nothing narrower).
	//   cidr: an ipBlock; Nodes names the nodes whose address it contains.
	//   anywhere: a rule with no from/to, or a direction no policy restricts.
	//   none: a selector that matches no pods or namespaces right now.
	Type      string   `json:"type"`
	Kind      string   `json:"kind,omitempty"`
	Namespace string   `json:"namespace,omitempty"`
	Name      string   `json:"name,omitempty"`
	CIDR      string   `json:"cidr,omitempty"`
	Except    []string `json:"except,omitempty"`
	Nodes     []string `json:"nodes,omitempty"`
	// Selector is the rule's peer as written, for a peer that came from one.
	Selector string `json:"selector,omitempty"`
	// Matched, for a workload peer, is how many workloads the rule's selector
	// matched. 1 means the rule names this workload in particular; more means
	// it was caught by a broader selector.
	Matched int `json:"matched,omitempty"`
}

// key is what one chip stands for: the same workload, namespace or address
// range admitted by two rules is one peer with both rules' ports. Only a
// selector that matches nothing is identified by its text.
func (p Peer) key() string {
	parts := []string{p.Type, p.Kind, p.Namespace, p.Name, p.CIDR, strings.Join(p.Except, ",")}
	if p.Type == "none" {
		parts = append(parts, p.Selector)
	}
	return strings.Join(parts, "|")
}

// Allow is one peer a workload accepts from (ingress) or may reach (egress).
type Allow struct {
	Peer  Peer     `json:"peer"`
	Ports []string `json:"ports"`
	// Policies are the policies whose rules admit this peer.
	Policies []string `json:"policies,omitempty"`
	// Effective, for a workload peer on a numeric port, is the whole path
	// judged from both ends: allowed, blocked (the OTHER end's policies refuse
	// it, so this rule admits traffic that can never arrive), or unknown.
	// Empty when not judged.
	Effective string   `json:"effective,omitempty"`
	BlockedBy []string `json:"blockedBy,omitempty"`
}

// Workload is one owner of pods in the namespace, with what its policies allow.
type Workload struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Pods int    `json:"pods"`
	// IngressIsolated/EgressIsolated: some policy selects these pods for that
	// direction, so only what a rule admits gets through. Not isolated means
	// the direction is open to everything.
	// HostNetwork: the pods share the node's network namespace, so no
	// NetworkPolicy applies to them whatever selects them. Ingress and Egress
	// are empty and no finding names them.
	HostNetwork      bool     `json:"hostNetwork,omitempty"`
	IngressIsolated  bool     `json:"ingressIsolated"`
	EgressIsolated   bool     `json:"egressIsolated"`
	Policies         []string `json:"policies"`
	Ingress          []Allow  `json:"ingress"`
	Egress           []Allow  `json:"egress"`
	IngressTruncated bool     `json:"ingressTruncated,omitempty"`
	EgressTruncated  bool     `json:"egressTruncated,omitempty"`
}

// Policy is one NetworkPolicy in the namespace and what it applies to.
type Policy struct {
	Name      string   `json:"name"`
	Types     []string `json:"types"`
	Workloads []string `json:"workloads"`
}

// Finding is one recommendation. Severity is warning (traffic is open or
// broken in a way that is probably unintended) or review (worth a look, may
// be deliberate).
type Finding struct {
	Code     string   `json:"code"`
	Severity string   `json:"severity"`
	Title    string   `json:"title"`
	Fix      string   `json:"fix"`
	Objects  []string `json:"objects"`
	// More counts objects beyond MaxFindingItems.
	More int `json:"more,omitempty"`
}

// Map is one namespace's policy map.
type Map struct {
	Namespace          string     `json:"namespace"`
	Workloads          []Workload `json:"workloads"`
	WorkloadsTruncated bool       `json:"workloadsTruncated,omitempty"`
	Policies           []Policy   `json:"policies"`
	Findings           []Finding  `json:"findings"`
}

// IndexRow summarises one namespace for the picker.
type IndexRow struct {
	Name      string `json:"name"`
	Workloads int    `json:"workloads"`
	Policies  int    `json:"policies"`
	// Open counts workloads that accept traffic from anywhere (not
	// ingress-isolated, and not on the host network, where policy does not
	// apply at all).
	Open     int `json:"open"`
	Warnings int `json:"warnings"`
	Reviews  int `json:"reviews"`
}

// world is the resolved cluster: pods grouped by workload, namespaces by name.
type world struct {
	in        Input
	nsByName  map[string]*corev1.Namespace
	podsByNS  map[string][]*corev1.Pod
	polByNS   map[string][]*networkingv1.NetworkPolicy
	ownerOf   map[*corev1.Pod]workloadRef
	rsOwner   map[string]workloadRef // ns/rsName -> Deployment
	jobOwner  map[string]workloadRef // ns/jobName -> CronJob
	nodeAddrs map[string][]net.IP
}

type workloadRef struct{ Kind, Namespace, Name string }

func (w workloadRef) label() string { return w.Kind + " " + w.Name }

func newWorld(in Input) *world {
	w := &world{
		in:        in,
		nsByName:  map[string]*corev1.Namespace{},
		podsByNS:  map[string][]*corev1.Pod{},
		polByNS:   map[string][]*networkingv1.NetworkPolicy{},
		ownerOf:   map[*corev1.Pod]workloadRef{},
		rsOwner:   map[string]workloadRef{},
		jobOwner:  map[string]workloadRef{},
		nodeAddrs: map[string][]net.IP{},
	}
	for _, n := range in.Namespaces {
		w.nsByName[n.Name] = n
	}
	for _, rs := range in.ReplicaSets {
		if o := metav1.GetControllerOf(rs); o != nil && o.Kind == "Deployment" {
			w.rsOwner[rs.Namespace+"/"+rs.Name] = workloadRef{"Deployment", rs.Namespace, o.Name}
		}
	}
	for _, j := range in.Jobs {
		if o := metav1.GetControllerOf(j); o != nil && o.Kind == "CronJob" {
			w.jobOwner[j.Namespace+"/"+j.Name] = workloadRef{"CronJob", j.Namespace, o.Name}
		}
	}
	for _, p := range in.Pods {
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue // finished pods hold no connections
		}
		w.podsByNS[p.Namespace] = append(w.podsByNS[p.Namespace], p)
		w.ownerOf[p] = w.resolveOwner(p)
	}
	for _, np := range in.Policies {
		w.polByNS[np.Namespace] = append(w.polByNS[np.Namespace], np)
	}
	for _, n := range in.Nodes {
		for _, a := range n.Status.Addresses {
			if ip := net.ParseIP(a.Address); ip != nil {
				w.nodeAddrs[n.Name] = append(w.nodeAddrs[n.Name], ip)
			}
		}
	}
	return w
}

func (w *world) resolveOwner(p *corev1.Pod) workloadRef {
	o := metav1.GetControllerOf(p)
	if o == nil {
		return workloadRef{"Pod", p.Namespace, p.Name}
	}
	switch o.Kind {
	case "ReplicaSet":
		if d, ok := w.rsOwner[p.Namespace+"/"+o.Name]; ok {
			return d
		}
	case "Job":
		if c, ok := w.jobOwner[p.Namespace+"/"+o.Name]; ok {
			return c
		}
	case "Node":
		// A static pod's controller is its Node; the pod is its own workload.
		return workloadRef{"Pod", p.Namespace, p.Name}
	}
	return workloadRef{o.Kind, p.Namespace, o.Name}
}

// group is one workload's pods; rep is the pod policies are judged against.
// Pods of one workload share a template, so their labels agree.
type group struct {
	ref  workloadRef
	pods []*corev1.Pod
}

func (w *world) groups(ns string) []*group {
	byRef := map[workloadRef]*group{}
	var out []*group
	for _, p := range w.podsByNS[ns] {
		r := w.ownerOf[p]
		g := byRef[r]
		if g == nil {
			g = &group{ref: r}
			byRef[r] = g
			out = append(out, g)
		}
		g.pods = append(g.pods, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ref.Kind != out[j].ref.Kind {
			return out[i].ref.Kind < out[j].ref.Kind
		}
		return out[i].ref.Name < out[j].ref.Name
	})
	return out
}

// Build maps one namespace.
func Build(in Input, namespace string) Map {
	return newWorld(in).build(namespace)
}

// Index summarises every namespace that has pods or policies.
func Index(in Input) []IndexRow {
	w := newWorld(in)
	names := map[string]bool{}
	for ns := range w.podsByNS {
		names[ns] = true
	}
	for ns := range w.polByNS {
		names[ns] = true
	}
	var out []IndexRow
	for ns := range names {
		m := w.build(ns)
		r := IndexRow{Name: ns, Workloads: len(m.Workloads), Policies: len(m.Policies)}
		for _, wl := range m.Workloads {
			if !wl.IngressIsolated && !wl.HostNetwork {
				r.Open++
			}
		}
		for _, f := range m.Findings {
			if f.Severity == "warning" {
				r.Warnings++
			} else {
				r.Reviews++
			}
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Warnings != out[j].Warnings {
			return out[i].Warnings > out[j].Warnings
		}
		if out[i].Policies != out[j].Policies {
			return out[i].Policies > out[j].Policies
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (w *world) build(ns string) Map {
	m := Map{Namespace: ns, Workloads: []Workload{}, Policies: []Policy{}, Findings: []Finding{}}
	groups := w.groups(ns)
	policies := w.polByNS[ns]

	selectedBy := map[string][]string{} // policy name -> workload labels
	for _, g := range groups {
		if len(m.Workloads) >= MaxWorkloads {
			m.WorkloadsTruncated = true
			break
		}
		rep := g.pods[0]
		wl := Workload{Kind: g.ref.Kind, Name: g.ref.Name, Pods: len(g.pods), Policies: []string{}}
		var ingressPol, egressPol []*networkingv1.NetworkPolicy
		for _, np := range policies {
			ok, err := netpol.Selects(np, rep)
			if err != nil || !ok {
				continue
			}
			wl.Policies = append(wl.Policies, np.Name)
			selectedBy[np.Name] = append(selectedBy[np.Name], g.ref.label())
			t := netpol.EffectivePolicyTypes(np)
			if t.Ingress {
				ingressPol = append(ingressPol, np)
			}
			if t.Egress {
				egressPol = append(egressPol, np)
			}
		}
		wl.IngressIsolated = len(ingressPol) > 0
		wl.EgressIsolated = len(egressPol) > 0
		if rep.Spec.HostNetwork {
			wl.HostNetwork = true
			wl.Ingress, wl.Egress = []Allow{}, []Allow{}
			m.Workloads = append(m.Workloads, wl)
			continue
		}
		wl.Ingress, wl.IngressTruncated = w.allows(ns, rep, ingressPol, netpol.DirectionIngress)
		wl.Egress, wl.EgressTruncated = w.allows(ns, rep, egressPol, netpol.DirectionEgress)
		m.Workloads = append(m.Workloads, wl)
	}
	for _, np := range policies {
		t := netpol.EffectivePolicyTypes(np)
		p := Policy{Name: np.Name, Types: []string{}, Workloads: selectedBy[np.Name]}
		if t.Ingress {
			p.Types = append(p.Types, "Ingress")
		}
		if t.Egress {
			p.Types = append(p.Types, "Egress")
		}
		if p.Workloads == nil {
			p.Workloads = []string{}
		}
		m.Policies = append(m.Policies, p)
	}
	m.Findings = findings(m, len(policies) > 0)
	return m
}

// allows lists what the given policies admit for one direction of rep's
// pods. No policies means the direction is not isolated: one "anywhere" peer.
func (w *world) allows(ns string, rep *corev1.Pod, pols []*networkingv1.NetworkPolicy, dir netpol.Direction) ([]Allow, bool) {
	if len(pols) == 0 {
		return []Allow{{Peer: Peer{Type: "anywhere"}, Ports: []string{"all ports"}}}, false
	}
	merged := map[string]*Allow{}
	var order []string
	add := func(peer Peer, ports []string, policy string) {
		k := peer.key()
		a := merged[k]
		if a == nil {
			a = &Allow{Peer: peer}
			merged[k] = a
			order = append(order, k)
		} else {
			if peer.Selector != "" && !strings.Contains(a.Peer.Selector, peer.Selector) {
				a.Peer.Selector += "; " + peer.Selector
			}
			// The most specific rule decides whether this workload was named.
			if peer.Matched > 0 && (a.Peer.Matched == 0 || peer.Matched < a.Peer.Matched) {
				a.Peer.Matched = peer.Matched
			}
		}
		a.Ports = appendUnique(a.Ports, ports...)
		a.Policies = appendUnique(a.Policies, policy)
	}
	for _, np := range pols {
		if dir == netpol.DirectionIngress {
			for _, r := range np.Spec.Ingress {
				ports := portLabels(r.Ports)
				for _, peer := range w.peers(np.Namespace, r.From) {
					add(peer, ports, np.Name)
				}
			}
		} else {
			for _, r := range np.Spec.Egress {
				ports := portLabels(r.Ports)
				for _, peer := range w.peers(np.Namespace, r.To) {
					add(peer, ports, np.Name)
				}
			}
		}
	}
	out := make([]Allow, 0, len(order))
	for _, k := range order {
		a := *merged[k]
		if allPorts(a.Ports) {
			a.Ports = []string{"all ports"}
		}
		sort.Strings(a.Policies)
		out = append(out, a)
	}
	for i := range out {
		w.judge(&out[i], rep, dir)
	}
	sort.SliceStable(out, func(i, j int) bool { return peerRank(out[i].Peer) < peerRank(out[j].Peer) })
	if len(out) > MaxAllowsPerSide {
		return out[:MaxAllowsPerSide], true
	}
	return out, false
}

// peers resolves one rule's peer list. An empty list admits everything.
func (w *world) peers(policyNS string, list []networkingv1.NetworkPolicyPeer) []Peer {
	if len(list) == 0 {
		return []Peer{{Type: "anywhere"}}
	}
	var out []Peer
	for _, p := range list {
		out = append(out, w.peer(policyNS, p)...)
	}
	return out
}

func (w *world) peer(policyNS string, p networkingv1.NetworkPolicyPeer) []Peer {
	if p.IPBlock != nil {
		return []Peer{w.cidrPeer(p.IPBlock)}
	}
	selector := describePeer(p)
	// Which namespaces the peer covers.
	var namespaces []string
	if p.NamespaceSelector == nil {
		namespaces = []string{policyNS}
	} else {
		sel, err := metav1.LabelSelectorAsSelector(p.NamespaceSelector)
		if err != nil {
			return []Peer{{Type: "none", Selector: selector}}
		}
		for name, n := range w.nsByName {
			if sel.Matches(labels.Set(n.Labels)) {
				namespaces = append(namespaces, name)
			}
		}
		sort.Strings(namespaces)
	}
	// No podSelector, or an empty one: whole namespaces.
	if p.PodSelector == nil || (len(p.PodSelector.MatchLabels) == 0 && len(p.PodSelector.MatchExpressions) == 0) {
		if len(namespaces) == 0 {
			return []Peer{{Type: "none", Selector: selector}}
		}
		out := make([]Peer, 0, len(namespaces))
		for _, ns := range namespaces {
			out = append(out, Peer{Type: "namespace", Namespace: ns, Selector: selector})
		}
		return out
	}
	podSel, err := metav1.LabelSelectorAsSelector(p.PodSelector)
	if err != nil {
		return []Peer{{Type: "none", Selector: selector}}
	}
	seen := map[workloadRef]bool{}
	var out []Peer
	for _, ns := range namespaces {
		for _, pod := range w.podsByNS[ns] {
			if !podSel.Matches(labels.Set(pod.Labels)) {
				continue
			}
			r := w.ownerOf[pod]
			if seen[r] {
				continue
			}
			seen[r] = true
			out = append(out, Peer{Type: "workload", Kind: r.Kind, Namespace: r.Namespace, Name: r.Name, Selector: selector})
		}
	}
	if len(out) == 0 {
		return []Peer{{Type: "none", Selector: selector}}
	}
	for i := range out {
		out[i].Matched = len(out)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Namespace+"/"+out[i].Name < out[j].Namespace+"/"+out[j].Name })
	return out
}

func (w *world) cidrPeer(b *networkingv1.IPBlock) Peer {
	p := Peer{Type: "cidr", CIDR: b.CIDR, Except: b.Except}
	_, block, err := net.ParseCIDR(b.CIDR)
	if err != nil {
		return p
	}
	var excepts []*net.IPNet
	for _, e := range b.Except {
		if _, n, err := net.ParseCIDR(e); err == nil {
			excepts = append(excepts, n)
		}
	}
	if ones, _ := block.Mask.Size(); ones == 0 {
		return p // 0.0.0.0/0 contains every node; naming them says nothing
	}
	for name, ips := range w.nodeAddrs {
		for _, ip := range ips {
			if block.Contains(ip) && !containedIn(ip, excepts) {
				p.Nodes = append(p.Nodes, name)
				break
			}
		}
	}
	sort.Strings(p.Nodes)
	return p
}

// judge decides the whole path for a workload peer: does the OTHER end's
// policy let the traffic through as well?
func (w *world) judge(a *Allow, rep *corev1.Pod, dir netpol.Direction) {
	if a.Peer.Type != "workload" {
		return
	}
	other := w.repOf(workloadRef{a.Peer.Kind, a.Peer.Namespace, a.Peer.Name})
	if other == nil {
		return
	}
	var src, dst *corev1.Pod
	if dir == netpol.DirectionIngress {
		src, dst = other, rep
	} else {
		src, dst = rep, other
	}
	port, proto, ok := firstConcretePort(a.Ports, dst)
	if !ok {
		return
	}
	pols := append(append([]*networkingv1.NetworkPolicy{}, w.polByNS[src.Namespace]...), w.polByNS[dst.Namespace]...)
	if src.Namespace == dst.Namespace {
		pols = w.polByNS[src.Namespace]
	}
	v := netpol.Evaluate(
		netpol.Peer{Pod: src, Namespace: w.nsByName[src.Namespace]},
		[]netpol.Backend{{Peer: netpol.Peer{Pod: dst, Namespace: w.nsByName[dst.Namespace]}, Port: port, Protocol: proto}},
		pols)
	switch v.Kind {
	case netpol.Allowed:
		a.Effective = "allowed"
	case netpol.Denied:
		a.Effective = "blocked"
		a.BlockedBy = v.Policies
	default:
		a.Effective = "unknown"
	}
}

func (w *world) repOf(r workloadRef) *corev1.Pod {
	for _, p := range w.podsByNS[r.Namespace] {
		if w.ownerOf[p] == r {
			return p
		}
	}
	return nil
}

// firstConcretePort picks the first numeric (or resolvable named) port from
// labels like "TCP 8080"; "all ports" has none to test.
func firstConcretePort(ports []string, dst *corev1.Pod) (int32, corev1.Protocol, bool) {
	for _, l := range ports {
		parts := strings.SplitN(l, " ", 2)
		if len(parts) != 2 {
			continue
		}
		proto := corev1.Protocol(parts[0])
		spec := strings.SplitN(parts[1], "-", 2)[0]
		var n int32
		if _, err := fmt.Sscanf(spec, "%d", &n); err == nil && n > 0 {
			return n, proto, true
		}
		if p, ok := netpol.ContainerPortByName(dst, spec, proto); ok {
			return p, proto, true
		}
	}
	return 0, "", false
}

func portLabels(ports []networkingv1.NetworkPolicyPort) []string {
	if len(ports) == 0 {
		return []string{"all ports"}
	}
	var out []string
	for _, p := range ports {
		proto := "TCP"
		if p.Protocol != nil {
			proto = string(*p.Protocol)
		}
		switch {
		case p.Port == nil:
			out = append(out, proto+" all")
		case p.EndPort != nil:
			out = append(out, fmt.Sprintf("%s %s-%d", proto, p.Port.String(), *p.EndPort))
		default:
			out = append(out, proto+" "+p.Port.String())
		}
	}
	return out
}

func allPorts(ports []string) bool {
	for _, p := range ports {
		if p == "all ports" {
			return true
		}
	}
	return false
}

func describePeer(p networkingv1.NetworkPolicyPeer) string {
	var parts []string
	if p.NamespaceSelector != nil {
		parts = append(parts, "namespaces "+selectorText(p.NamespaceSelector))
	}
	if p.PodSelector != nil {
		parts = append(parts, "pods "+selectorText(p.PodSelector))
	}
	return strings.Join(parts, ", ")
}

func selectorText(s *metav1.LabelSelector) string {
	if len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0 {
		return "(all)"
	}
	sel, err := metav1.LabelSelectorAsSelector(s)
	if err != nil {
		return "(invalid selector)"
	}
	return sel.String()
}

func peerRank(p Peer) int {
	switch p.Type {
	case "anywhere":
		return 0
	case "cidr":
		return 1
	case "namespace":
		return 2
	case "workload":
		return 3
	}
	return 4
}

func containedIn(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func appendUnique(list []string, items ...string) []string {
	for _, it := range items {
		dup := false
		for _, have := range list {
			if have == it {
				dup = true
				break
			}
		}
		if !dup {
			list = append(list, it)
		}
	}
	return list
}
