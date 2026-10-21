package netpol

import (
	"fmt"
	"maps"
	"net"
	"slices"
	"strings"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// Effect is what one policy says about one connection. It is not a verdict:
// NetworkPolicy is additive, so a policy that does not admit a connection
// blocks nothing by itself — only having no policy that admits it does.
// Evaluate combines the Effects of all the policies that select a pod.
type Effect int

const (
	// NotApplicable: the policy does not select the pod, or does not
	// isolate this direction, and has no say.
	NotApplicable Effect = iota
	// Admits: one of the policy's rules lets the connection through.
	Admits
	// DoesNotAdmit: the policy isolates the pod in this direction and none
	// of its rules lets the connection through.
	DoesNotAdmit
	// Undecidable: the answer turns on something a static reading cannot
	// see — a rewritten address, a pod that cannot be found, a host-network
	// pod, a port nobody knows.
	Undecidable
)

var effectWords = map[Effect][2]string{
	NotApplicable: {"not applicable", "notApplicable"},
	Admits:        {"admits", "admits"},
	DoesNotAdmit:  {"does not admit", "doesNotAdmit"},
	Undecidable:   {"undecidable", "undecidable"},
}

// String is the Effect in prose, for use inside a sentence.
func (e Effect) String() string { return effectWords[e][0] }

// MarshalText is the Effect as a stable camelCase token for tool results.
func (e Effect) MarshalText() ([]byte, error) {
	if w, ok := effectWords[e]; ok {
		return []byte(w[1]), nil
	}
	return []byte("notApplicable"), nil
}

// Explanation is an Effect and the sentence behind it, written for someone
// reading down a list of policies.
type Explanation struct {
	Effect Effect `json:"effect"`
	Reason string `json:"reason"`
}

// Explain says whether one policy admits a connection in dir. selected is
// the pod the policy would have to select — the destination for ingress, the
// source for egress — and peer is the far end. port and proto are the
// destination's; a port of 0 means it is not known.
//
// Evaluate is built from this, so that what a rule means is worked out in
// exactly one place.
func Explain(np *networkingv1.NetworkPolicy, dir Direction, selected *corev1.Pod, peer Peer, port int32, proto corev1.Protocol) Explanation {
	if np == nil {
		return Explanation{NotApplicable, "no policy"}
	}
	if selected == nil {
		return Explanation{Undecidable, "the pod this policy would govern is not known"}
	}
	hit, err := Selects(np, selected)
	switch {
	case err != nil:
		return Explanation{Undecidable, "its pod selector cannot be read (" + err.Error() + ")"}
	case !hit:
		return Explanation{NotApplicable, "does not select pod " + podRef(selected)}
	}
	types := EffectivePolicyTypes(np)
	var rules []rule
	switch dir {
	case DirectionIngress:
		if !types.Ingress {
			return Explanation{NotApplicable, "governs only outgoing traffic"}
		}
		for _, r := range np.Spec.Ingress {
			rules = append(rules, rule{r.Ports, r.From})
		}
	case DirectionEgress:
		if !types.Egress {
			return Explanation{NotApplicable, "governs only incoming traffic"}
		}
		for _, r := range np.Spec.Egress {
			rules = append(rules, rule{r.Ports, r.To})
		}
	default:
		return Explanation{NotApplicable, "no direction"}
	}

	switch {
	case selected.Spec.HostNetwork:
		return Explanation{Undecidable, "pod " + podRef(selected) + " uses the host network, where NetworkPolicy does not apply in the usual way"}
	case peer.Pod != nil && peer.Pod.Spec.HostNetwork:
		// Whether a selector can see a host-network pod is the plugin's call.
		return Explanation{Undecidable, "pod " + podRef(peer.Pod) + " uses the host network; whether policies treat it as a pod depends on the network plugin"}
	case peer.Host:
		return Explanation{Undecidable, describePeer(peer, dir) + " is a node or the host network; whether policies cover it depends on the network plugin"}
	case len(rules) == 0:
		return Explanation{DoesNotAdmit, fmt.Sprintf("isolates %s traffic and has no rule letting any in", flow(dir))}
	}

	// A named port is looked up on the destination pod: the selected pod on
	// ingress, the peer on egress. Something that is not a pod has no named
	// ports; a destination pod that cannot be found leaves the answer open.
	portOwner := selected
	if dir == DirectionEgress {
		portOwner = peer.Pod
	}
	target := describePort(port, proto)

	result, portsMatched := no, false
	var doubts []string
	doubt := func(s string) {
		if s != "" && !slices.Contains(doubts, s) {
			doubts = append(doubts, s)
		}
	}
	for i, r := range rules {
		n := i + 1
		if len(r.ports) > 0 {
			switch portsAnswer(r.ports, port, proto, portOwner, peer.External) {
			case no:
				continue
			case maybe:
				result = result.or(maybe)
				if port <= 0 {
					doubt(fmt.Sprintf("rule %d is limited to certain ports and this connection's port is not known", n))
				} else {
					doubt(fmt.Sprintf("rule %d names a port, and the destination pod to look it up on cannot be found", n))
				}
				continue
			}
		}
		portsMatched = true
		if len(r.peers) == 0 {
			return Explanation{Admits, fmt.Sprintf("rule %d lets %s %s through %s", n, flow(dir), target, anywhere(dir))}
		}
		here := no
		for j := range r.peers {
			a, what := entryAdmits(&r.peers[j], peer, np.Namespace, dir)
			switch a {
			case yes:
				return Explanation{Admits, fmt.Sprintf("rule %d lets %s %s through %s %s", n, flow(dir), target, fromTo(dir), what)}
			case maybe:
				here = here.or(maybe)
				doubt(what)
			}
		}
		result = result.or(here)
	}
	switch {
	case result == maybe:
		return Explanation{Undecidable, strings.Join(doubts, "; ")}
	case !portsMatched:
		return Explanation{DoesNotAdmit, "no rule lets " + target + " through; its rules are for other ports"}
	}
	return Explanation{DoesNotAdmit, fmt.Sprintf("no rule lets %s %s through %s %s", flow(dir), target, fromTo(dir), describePeer(peer, dir))}
}

// rule is an ingress or egress rule seen the same way: ports, and the peers
// on the far side.
type rule struct {
	ports []networkingv1.NetworkPolicyPort
	peers []networkingv1.NetworkPolicyPeer
}

// portsAnswer weighs a rule's port entries as the alternatives they are. A
// numeric entry covering the port settles it whatever named entries beside
// it say; only a named entry that cannot be looked up (the destination pod
// is unknown) leaves it open, and a destination that is not a pod has no
// named ports at all. Protocol comes first and holds even when the port is
// unknown: another protocol's entry never matches, and a protocol with no
// port admits every port of it.
func portsAnswer(ports []networkingv1.NetworkPolicyPort, port int32, proto corev1.Protocol, owner *corev1.Pod, external bool) answer {
	proto = ProtocolOrTCP(string(proto))
	got := no
	for _, e := range ports {
		switch {
		case entryProtocol(e) != proto:
		case e.Port == nil:
			return yes
		case port <= 0:
			got = got.or(maybe)
		case e.Port.Type == intstr.String && owner == nil && !external:
			got = got.or(maybe)
		case entryCovers(e, port, proto, owner):
			return yes
		}
	}
	return got
}

// rangeCaveat is why an ipBlock never settles anything about a pod on the
// far end: network plugins disagree on whether address ranges match pod
// addresses at all.
const rangeCaveat = "network plugins differ on whether an address range matches pod addresses (Cilium, by default, does not), so whether this rule applies cannot be told"

// entryAdmits decides whether one from/to entry admits the far end, and
// describes the entry. ns is the policy's namespace: a podSelector with no
// namespaceSelector only ever means pods there.
//
// A selector matches pods only, never an external end. An ipBlock is
// compared with the address the policy would see. A match admits. A miss
// settles nothing on ingress (the source may have been rewritten on the
// way) or on egress to a pod (a cluster IP is rewritten by DNAT), but does
// on egress to an outside address, which nothing in the cluster rewrites.
func entryAdmits(e *networkingv1.NetworkPolicyPeer, far Peer, ns string, dir Direction) (answer, string) {
	if b := e.IPBlock; b != nil {
		what := "addresses in " + b.CIDR
		if len(b.Except) > 0 {
			what += " other than " + strings.Join(b.Except, ", ")
		}
		if dir == DirectionEgress && !far.External {
			// The reference plugin matches a pod's address against the
			// range; Cilium by default matches only addresses outside the
			// cluster. Neither a hit nor a miss proves anything.
			return maybe, what + ": " + rangeCaveat
		}
		if !wellFormed(b) {
			return maybe, what + ": the range or an exception is not a valid CIDR"
		}
		ips := addressesOf(far)
		switch inBlock(b, ips) {
		case yes:
			if !far.External {
				// The same disagreement holds on ingress; a pod that cannot
				// be found is still a pod.
				return maybe, what + ": " + rangeCaveat
			}
			return yes, what
		case no:
			if dir == DirectionEgress {
				return no, what
			}
			return maybe, what + ": the source address may be rewritten before this rule sees it, so whether " + addressOrPeer(far, dir) + " is in range cannot be told"
		}
		if dir == DirectionEgress && len(ips) > 0 {
			// The destination is known and reached over the other address
			// family; this block cannot admit it.
			return no, what
		}
		return maybe, what + ": no " + family(b.CIDR) + " address is known for " + describePeer(far, dir)
	}
	if e.NamespaceSelector == nil && e.PodSelector == nil {
		return maybe, "an empty from/to entry, which has no reading"
	}
	what := describeSelectorPeer(e, ns)
	switch {
	case far.External:
		return no, what
	case far.Pod == nil:
		return maybe, what + ": the pod at the far end cannot be found (it may be gone)"
	}

	inNS := yes
	switch {
	case e.NamespaceSelector == nil:
		if far.Pod.Namespace != ns {
			inNS = no
		}
	case emptySelector(e.NamespaceSelector):
		// Every namespace.
	case far.Namespace == nil:
		inNS = maybe
	default:
		inNS = selectorAnswer(e.NamespaceSelector, far.Namespace.Labels)
	}
	isPod := yes
	if e.PodSelector != nil {
		isPod = selectorAnswer(e.PodSelector, far.Pod.Labels)
	}
	switch {
	case inNS == no || isPod == no:
		return no, what
	case inNS == maybe:
		return maybe, what + ": namespace " + far.Pod.Namespace + "'s labels are not available to check"
	case isPod == maybe:
		return maybe, what + ": the selector cannot be read"
	}
	return yes, what
}

// selectorAnswer matches labels against a selector; one that cannot be
// parsed is maybe.
func selectorAnswer(sel *metav1.LabelSelector, set map[string]string) answer {
	s, err := metav1.LabelSelectorAsSelector(sel)
	switch {
	case err != nil:
		return maybe
	case s.Matches(labels.Set(set)):
		return yes
	}
	return no
}

func describeSelectorPeer(e *networkingv1.NetworkPolicyPeer, ns string) string {
	pods := "any pod"
	if e.PodSelector != nil && !emptySelector(e.PodSelector) {
		pods = "pods " + describeSelector(e.PodSelector)
	}
	switch {
	case e.NamespaceSelector == nil:
		return pods + " in namespace " + ns
	case emptySelector(e.NamespaceSelector):
		return pods + " in any namespace"
	}
	return pods + " in namespaces " + describeSelector(e.NamespaceSelector)
}

func describeSelector(sel *metav1.LabelSelector) string {
	var terms []string
	if sel != nil {
		for _, k := range slices.Sorted(maps.Keys(sel.MatchLabels)) {
			terms = append(terms, k+"="+sel.MatchLabels[k])
		}
		for _, x := range sel.MatchExpressions {
			t := x.Key + " " + string(x.Operator)
			if len(x.Values) > 0 {
				t += " (" + strings.Join(x.Values, ",") + ")"
			}
			terms = append(terms, t)
		}
	}
	if len(terms) == 0 {
		return "with any labels"
	}
	return "labeled " + strings.Join(terms, ", ")
}

func flow(dir Direction) string {
	if dir == DirectionEgress {
		return "outgoing"
	}
	return "incoming"
}

func fromTo(dir Direction) string {
	if dir == DirectionEgress {
		return "to"
	}
	return "from"
}

func anywhere(dir Direction) string {
	if dir == DirectionEgress {
		return "to any destination"
	}
	return "from any source"
}

// addressOrPeer is the address a range would be tested against, or the peer
// when no address is known.
func addressOrPeer(p Peer, dir Direction) string {
	switch {
	case p.IP != "":
		return p.IP
	case p.Pod != nil && p.Pod.Status.PodIP != "":
		return p.Pod.Status.PodIP
	}
	return describePeer(p, dir)
}

func family(cidr string) string {
	if ip, _, err := net.ParseCIDR(cidr); err == nil && ip.To4() == nil {
		return "IPv6"
	}
	return "IPv4"
}

func describePeer(p Peer, dir Direction) string {
	who := "the source"
	if dir == DirectionEgress {
		who = "the destination"
	}
	at := ""
	if p.IP != "" {
		at = " " + p.IP
	}
	switch {
	case p.Pod != nil:
		return who + " pod " + podRef(p.Pod)
	case p.External:
		return who + at + " (outside the cluster)"
	case p.Host:
		return who + at + " (host network)"
	}
	return who
}

func podRef(pod *corev1.Pod) string {
	switch {
	case pod == nil:
		return "an unknown pod"
	case pod.Namespace == "":
		return pod.Name
	}
	return pod.Namespace + "/" + pod.Name
}

func describePort(port int32, proto corev1.Protocol) string {
	p := ProtocolOrTCP(string(proto))
	if port <= 0 {
		return string(p) + " (port unknown)"
	}
	return fmt.Sprintf("%s/%d", p, port)
}

// addressesOf prefers the address actually observed: a flow seen on one of a
// dual-stack pod's addresses must not be admitted on the other's account.
// With none observed, a pod's addresses stand in.
func addressesOf(p Peer) []net.IP {
	if ip := net.ParseIP(p.IP); ip != nil {
		return []net.IP{ip}
	}
	if p.Pod != nil {
		return podIPs(p.Pod)
	}
	return nil
}

func emptySelector(sel *metav1.LabelSelector) bool {
	return sel != nil && len(sel.MatchLabels) == 0 && len(sel.MatchExpressions) == 0
}

func wellFormed(b *networkingv1.IPBlock) bool {
	for _, c := range append([]string{b.CIDR}, b.Except...) {
		if _, _, err := net.ParseCIDR(c); err != nil {
			return false
		}
	}
	return true
}
