package netpol

import (
	"net"
	"slices"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
)

// Peer is one end of a connection: a pod and, when the caller could read it,
// its Namespace. namespaceSelector rules match Namespace labels, so without
// the Namespace such a rule cannot be decided — it is not a quiet no.
type Peer struct {
	Pod       *corev1.Pod
	Namespace *corev1.Namespace
	// External is an end that is no pod at all: a node, the host network,
	// the world outside the cluster. A selector never matches it; an ipBlock
	// is matched against IP. A nil Pod that is not External is a pod the
	// caller could not find, about which nothing can be decided.
	External bool
	// Host is a node, the host network or the API server: known to the
	// cluster, but not a pod. Whether policies apply to it is up to the
	// network plugin, so nothing about it can be decided.
	Host bool
	// IP is the address actually seen for this end (from a flow record),
	// and is preferred over the pod's own addresses for ipBlock matching.
	IP string
}

// Backend is a destination pod with the port and protocol the connection
// uses on it. A Service's targetPort can be a different number on each pod,
// so each backend has its own.
type Backend struct {
	Peer
	Port     int32
	Protocol corev1.Protocol
}

// Kind is how sure a verdict is. Only Denied is evidence: every policy given
// was examined and none admits the connection. Unknown is everything the
// model cannot decide, and never means "not blocked".
type Kind int

const (
	Unknown Kind = iota
	Allowed
	Denied
)

func (k Kind) String() string {
	switch k {
	case Allowed:
		return "allowed"
	case Denied:
		return "denied"
	}
	return "unknown"
}

// MarshalText writes a Kind as its word, never its number.
func (k Kind) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

// Direction is which end's policies a denial comes from.
type Direction string

const (
	DirectionIngress Direction = "ingress"
	DirectionEgress  Direction = "egress"
	// DirectionBoth: neither end alone explains it — some backends are cut
	// off by the source's egress policies, the rest by their own ingress —
	// so both sets of policies are named.
	DirectionBoth Direction = "ingress+egress"
)

// Verdict is Evaluate's answer. Policies are the namespace/name, sorted, of
// the policies that together isolate the denied end; NetworkPolicy is
// additive, so no one of them is "the" blocker.
type Verdict struct {
	Kind      Kind      `json:"verdict"`
	Direction Direction `json:"direction,omitempty"`
	Policies  []string  `json:"decidingPolicies,omitempty"`
}

// answer is a three-valued truth: yes, no, or cannot tell.
type answer int

const (
	maybe answer = iota
	yes
	no
)

// or joins alternatives — the rules of a policy, the entries of a rule, the
// backends of a Service: yes if any is yes, no only if all are no.
func (a answer) or(b answer) answer {
	switch {
	case a == yes || b == yes:
		return yes
	case a == maybe || b == maybe:
		return maybe
	}
	return no
}

// and joins the two legs of one path, which works only if both do: no if
// either is no, yes only if both are yes.
func (a answer) and(b answer) answer {
	switch {
	case a == no || b == no:
		return no
	case a == maybe || b == maybe:
		return maybe
	}
	return yes
}

// Evaluate decides whether policies deny a connection from src to any of the
// backends. policies must be every NetworkPolicy in the source's and the
// destinations' namespaces; the caller calls this only when it has the whole
// list, since a missing policy could be the one that admits the traffic.
//
// Denied needs positive evidence at one end: the source's egress is isolated
// and nothing admits any backend, or every backend's ingress is isolated and
// nothing admits the source. Whatever cannot be decided — host-network pods,
// namespace selectors without the Namespace, ipBlock rules on egress (a
// cluster IP's DNAT makes the matched address the CNI's business), malformed
// selectors — is Unknown.
func Evaluate(src Peer, dst []Backend, policies []*networkingv1.NetworkPolicy) Verdict {
	if src.Pod == nil || src.Pod.Spec.HostNetwork || len(dst) == 0 ||
		slices.ContainsFunc(dst, func(b Backend) bool { return b.Pod == nil || b.Pod.Spec.HostNetwork }) {
		return Verdict{Kind: Unknown}
	}
	egressSet, ok := isolating(src.Pod, policies, DirectionEgress)
	if !ok {
		return Verdict{Kind: Unknown}
	}

	// Each backend is judged on its whole path — the source's egress and
	// the backend's ingress together — and the connection works if any path
	// does. Judging the two directions apart would call a Service reachable
	// when egress lets through only one backend and ingress only another.
	path, egress, ingress := no, no, no
	var ingressSet []*networkingv1.NetworkPolicy
	for _, b := range dst {
		if samePod(src.Pod, b.Pod) {
			// Nothing blocks a pod from itself.
			path, egress, ingress = yes, yes, yes
			continue
		}
		mine, ok := isolating(b.Pod, policies, DirectionIngress)
		if !ok {
			return Verdict{Kind: Unknown}
		}
		ingressSet = append(ingressSet, mine...)
		out := admittedBy(egressSet, func(np *networkingv1.NetworkPolicy) Explanation {
			return Explain(np, DirectionEgress, src.Pod, b.Peer, b.Port, b.Protocol)
		})
		in := admittedBy(mine, func(np *networkingv1.NetworkPolicy) Explanation {
			return Explain(np, DirectionIngress, b.Pod, src, b.Port, b.Protocol)
		})
		path, egress, ingress = path.or(out.and(in)), egress.or(out), ingress.or(in)
	}

	switch {
	case path == yes:
		return Verdict{Kind: Allowed}
	case path == maybe:
		return Verdict{Kind: Unknown}
	case egress == no:
		return Verdict{Kind: Denied, Direction: DirectionEgress, Policies: policyNames(egressSet)}
	case ingress == no:
		return Verdict{Kind: Denied, Direction: DirectionIngress, Policies: policyNames(ingressSet)}
	}
	return Verdict{Kind: Denied, Direction: DirectionBoth, Policies: policyNames(slices.Concat(egressSet, ingressSet))}
}

// admittedBy asks each isolating policy in turn. With none the pod is not
// isolated in that direction and anything goes; otherwise it is admitted if
// any policy admits it. A policy that does not apply counts as no — which, in
// an "any of", changes nothing.
func admittedBy(set []*networkingv1.NetworkPolicy, ask func(*networkingv1.NetworkPolicy) Explanation) answer {
	if len(set) == 0 {
		return yes
	}
	got := no
	for _, np := range set {
		switch ask(np).Effect {
		case Admits:
			got = got.or(yes)
		case Undecidable:
			got = got.or(maybe)
		}
	}
	return got
}

// Selects reports whether a policy applies to a pod: the pod is in the
// policy's namespace and matches its podSelector (empty matches every pod
// there). The error is a malformed selector; a caller that must be certain
// treats it as undecidable, a display may just pass over it.
func Selects(np *networkingv1.NetworkPolicy, pod *corev1.Pod) (bool, error) {
	if np == nil || pod == nil || np.Namespace != pod.Namespace {
		return false, nil
	}
	sel, err := metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)
	return err == nil && sel.Matches(labels.Set(pod.Labels)), err
}

// isolating is the policies that select pod and isolate it in dir. ok is
// false when any selector cannot be parsed: that policy's effect is unknown,
// and no verdict may rest on the others.
func isolating(pod *corev1.Pod, policies []*networkingv1.NetworkPolicy, dir Direction) ([]*networkingv1.NetworkPolicy, bool) {
	var out []*networkingv1.NetworkPolicy
	for _, np := range policies {
		hit, err := Selects(np, pod)
		if err != nil {
			return nil, false
		}
		types := EffectivePolicyTypes(np)
		if hit && (dir == DirectionIngress && types.Ingress || dir == DirectionEgress && types.Egress) {
			out = append(out, np)
		}
	}
	return out, true
}

// inBlock compares an ipBlock with the addresses of its own family only — a
// dual-stack pod reaches an IPv6 backend from its IPv6 address, about which
// an IPv4 block says nothing. yes: an address lies in the block and in none
// of its exceptions. no: there are addresses of the family and none
// qualifies. maybe: none of the family, or a malformed block. Whether a no
// settles anything is for the caller to judge.
func inBlock(block *networkingv1.IPBlock, ips []net.IP) answer {
	_, cidr, err := net.ParseCIDR(block.CIDR)
	if err != nil {
		return maybe
	}
	var except []*net.IPNet
	for _, e := range block.Except {
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			return maybe
		}
		except = append(except, n)
	}
	v4 := cidr.IP.To4() != nil
	got := maybe
	for _, ip := range ips {
		if (ip.To4() != nil) != v4 {
			continue
		}
		got = no
		if cidr.Contains(ip) && !slices.ContainsFunc(except, func(n *net.IPNet) bool { return n.Contains(ip) }) {
			return yes
		}
	}
	return got
}

// podIPs is a pod's distinct addresses, the primary first.
func podIPs(pod *corev1.Pod) []net.IP {
	var out []net.IP
	for _, s := range append([]string{pod.Status.PodIP}, ipStrings(pod.Status.PodIPs)...) {
		ip := net.ParseIP(s)
		if ip != nil && !slices.ContainsFunc(out, ip.Equal) {
			out = append(out, ip)
		}
	}
	return out
}

func ipStrings(ips []corev1.PodIP) []string {
	out := make([]string, len(ips))
	for i, p := range ips {
		out[i] = p.IP
	}
	return out
}

// samePod compares UIDs when both pods have one, else namespace and name.
func samePod(a, b *corev1.Pod) bool {
	if a.UID == "" || b.UID == "" {
		return a.Namespace == b.Namespace && a.Name == b.Name
	}
	return a.UID == b.UID
}

// policyNames is the distinct namespace/name of each policy, sorted.
func policyNames(policies []*networkingv1.NetworkPolicy) []string {
	var out []string
	for _, np := range policies {
		out = append(out, np.Namespace+"/"+np.Name)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
