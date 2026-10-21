package netpol

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

func TestExplain(t *testing.T) {
	src, dst := cart(), redis(6379)
	outside := Peer{External: true, IP: "198.51.100.23"}
	gone := Peer{}
	redisPolicy := func(name string, opts ...func(*networkingv1.NetworkPolicySpec)) *networkingv1.NetworkPolicy {
		return netPolicy("data", name, append([]func(*networkingv1.NetworkPolicySpec){selecting(redisLabels), isolates(in)}, opts...)...)
	}
	cartEgress := func(name string, opts ...func(*networkingv1.NetworkPolicySpec)) *networkingv1.NetworkPolicy {
		return netPolicy("storefront", name, append([]func(*networkingv1.NetworkPolicySpec){selecting(cartLabels), isolates(out)}, opts...)...)
	}
	udp := corev1.ProtocolUDP
	tcpProto := corev1.ProtocolTCP
	dnsUDP := tcp(53)
	dnsUDP.Protocol = &udp

	cases := []struct {
		why    string
		np     *networkingv1.NetworkPolicy
		dir    Direction
		sel    *corev1.Pod
		peer   Peer
		port   int32
		effect Effect
		reason string // must appear in the reason
	}{
		{"not selected", netPolicy("data", "other", selecting(map[string]string{"app": "pg"}), isolates(in)), DirectionIngress, dst.Pod, src, 6379,
			NotApplicable, "does not select pod data/redis-0"},
		{"egress-only, asked about ingress", redisPolicy("out", isolates(out)), DirectionIngress, dst.Pod, src, 6379,
			NotApplicable, "governs only outgoing traffic"},
		{"ingress-only, asked about egress", cartEgress("in", isolates(in)), DirectionEgress, src.Pod, dst.Peer, 6379,
			NotApplicable, "governs only incoming traffic"},
		{"isolating with no rules", netPolicy("data", "deny-all", isolates(in)), DirectionIngress, dst.Pod, src, 6379,
			DoesNotAdmit, "isolates incoming traffic and has no rule"},
		{"a rule with no peers", redisPolicy("open", allowIn(ports(tcp(6379)))), DirectionIngress, dst.Pod, src, 6379,
			Admits, "rule 1 lets incoming TCP/6379 through from any source"},
		{"a namespace selector, named in the reason", redisPolicy("from-storefront", allowIn(nil, nsNamed("storefront"))), DirectionIngress, dst.Pod, src, 6379,
			Admits, "from any pod in namespaces labeled kubernetes.io/metadata.name=storefront"},
		{"an empty namespace selector needs no Namespace", redisPolicy("anyone", allowIn(nil, anyNamespace())), DirectionIngress, dst.Pod, Peer{Pod: src.Pod}, 6379,
			Admits, "from any pod in any namespace"},
		{"rules only for other ports", redisPolicy("sentinel", allowIn(ports(tcp(26379)), nsNamed("storefront"))), DirectionIngress, dst.Pod, src, 6379,
			DoesNotAdmit, "no rule lets TCP/6379 through; its rules are for other ports"},
		{"no rule for this source", redisPolicy("from-batch", allowIn(nil, nsNamed("batch"))), DirectionIngress, dst.Pod, src, 6379,
			DoesNotAdmit, "no rule lets incoming TCP/6379 through from the source pod storefront/cart-7f"},
		{"port-limited rule, unknown port", redisPolicy("6379", allowIn(ports(tcp(6379)), nsNamed("storefront"))), DirectionIngress, dst.Pod, src, 0,
			Undecidable, "rule 1 is limited to certain ports and this connection's port is not known"},
		{"protocol-only entry, unknown port", redisPolicy("any-tcp", allowIn(ports(networkingv1.NetworkPolicyPort{Protocol: &tcpProto}), nsNamed("storefront"))), DirectionIngress, dst.Pod, src, 0,
			Admits, "TCP (port unknown)"},
		{"other-protocol entry, unknown port", redisPolicy("dns", allowIn(ports(dnsUDP), nsNamed("storefront"))), DirectionIngress, dst.Pod, src, 0,
			DoesNotAdmit, "its rules are for other ports"},
		{"a selector never matches the outside", redisPolicy("anyone", allowIn(nil, anyNamespace())), DirectionIngress, dst.Pod, outside, 6379,
			DoesNotAdmit, "from the source 198.51.100.23 (outside the cluster)"},
		{"a range holding an outside source", redisPolicy("office", allowIn(nil, cidr("198.51.100.0/24"))), DirectionIngress, dst.Pod, outside, 6379,
			Admits, "from addresses in 198.51.100.0/24"},
		{"a range holding a pod source", redisPolicy("pods", allowIn(nil, cidr("10.42.0.0/16"))), DirectionIngress, dst.Pod, src, 6379,
			Undecidable, "network plugins differ"},
		{"a range holding a source pod that cannot be found", redisPolicy("pods", allowIn(nil, cidr("10.42.0.0/16"))), DirectionIngress, dst.Pod, Peer{IP: "10.42.1.99"}, 6379,
			Undecidable, "network plugins differ"},
		{"a range missing an outside source", redisPolicy("office", allowIn(nil, cidr("192.0.2.0/24"))), DirectionIngress, dst.Pod, outside, 6379,
			Undecidable, "the source address may be rewritten"},
		{"an egress range missing an outside destination", cartEgress("to-office", allowOut(nil, cidr("192.0.2.0/24"))), DirectionEgress, src.Pod, outside, 443,
			DoesNotAdmit, "no rule lets outgoing TCP/443 through to the destination 198.51.100.23 (outside the cluster)"},
		{"an egress range of the other family", cartEgress("to-office", allowOut(nil, cidr("198.51.100.0/24"))), DirectionEgress, src.Pod, Peer{External: true, IP: "2001:db8::23"}, 443,
			DoesNotAdmit, "to the destination 2001:db8::23 (outside the cluster)"},
		{"an egress range and an outside end with no address", cartEgress("to-office", allowOut(nil, cidr("192.0.2.0/24"))), DirectionEgress, src.Pod, Peer{External: true}, 443,
			Undecidable, "no IPv4 address is known"},
		{"an egress range to a pod, even on a hit", cartEgress("to-data", allowOut(nil, cidr("10.42.3.0/24"))), DirectionEgress, src.Pod, dst.Peer, 6379,
			Undecidable, "network plugins differ"},
		{"a malformed exception", cartEgress("bad", allowOut(nil, cidr("198.51.100.0/24", "nonsense"))), DirectionEgress, src.Pod, outside, 443,
			Undecidable, "not a valid CIDR"},
		{"the observed address wins", redisPolicy("v4", allowIn(nil, cidr("10.42.0.0/16"))), DirectionIngress, dst.Pod, func() Peer {
			p := cart()
			p.Pod.Status.PodIPs = []corev1.PodIP{{IP: "10.42.1.20"}, {IP: "fd42::20"}}
			p.IP = "fd42::20" // the flow came over IPv6
			return p
		}(), 6379, Undecidable, "no IPv4 address is known"},
		{"a far-end pod that cannot be found", redisPolicy("from-storefront", allowIn(nil, nsNamed("storefront"))), DirectionIngress, dst.Pod, gone, 6379,
			Undecidable, "the pod at the far end cannot be found"},
		{"a named egress port with no pod to read it from", cartEgress("named", allowOut(ports(named("redis")), anyNamespace())), DirectionEgress, src.Pod, gone, 6379,
			Undecidable, "rule 1 names a port, and the destination pod to look it up on cannot be found"},
		{"a numeric entry beside an unreadable name", cartEgress("mixed", allowOut(ports(tcp(443), named("https")))), DirectionEgress, src.Pod, gone, 443,
			Admits, "rule 1 lets outgoing TCP/443 through to any destination"},
		{"a host-network far end", redisPolicy("from-storefront", allowIn(nil, nsNamed("storefront"))), DirectionIngress, dst.Pod, func() Peer { p := cart(); p.Pod.Spec.HostNetwork = true; return p }(), 6379,
			Undecidable, "uses the host network"},
		{"a node, even against an open rule", redisPolicy("open", allowIn(nil)), DirectionIngress, dst.Pod, Peer{Host: true, IP: "10.0.0.11"}, 6379,
			Undecidable, "the source 10.0.0.11 (host network) is a node or the host network"},
		{"a host-network selected pod", netPolicy("data", "deny-all", isolates(in)), DirectionIngress, func() *corev1.Pod { p := redis(6379).Pod; p.Spec.HostNetwork = true; return p }(), src, 6379,
			Undecidable, "uses the host network"},
		{"no policy", nil, DirectionIngress, dst.Pod, src, 6379, NotApplicable, "no policy"},
		{"no selected pod", netPolicy("data", "deny-all", isolates(in)), DirectionIngress, nil, src, 6379, Undecidable, "not known"},
	}
	for _, c := range cases {
		got := Explain(c.np, c.dir, c.sel, c.peer, c.port, corev1.ProtocolTCP)
		if got.Effect != c.effect || !strings.Contains(got.Reason, c.reason) {
			t.Errorf("%s:\n got  %v: %q\n want %v: …%q…", c.why, got.Effect, got.Reason, c.effect, c.reason)
		}
	}
}

// Evaluate folds Explain; one denial and one admission keep the two from
// drifting apart.
func TestEvaluateAgreesWithExplain(t *testing.T) {
	src, dst := cart(), redis(6379)
	deny := netPolicy("data", "deny-all", isolates(in))
	open := netPolicy("data", "open", selecting(redisLabels), isolates(in), allowIn(nil))
	if v, e := Evaluate(src, []Backend{dst}, []*networkingv1.NetworkPolicy{deny}), Explain(deny, DirectionIngress, dst.Pod, src, 6379, corev1.ProtocolTCP); v.Kind != Denied || e.Effect != DoesNotAdmit {
		t.Errorf("deny: %+v / %+v", v, e)
	}
	if v, e := Evaluate(src, []Backend{dst}, []*networkingv1.NetworkPolicy{deny, open}), Explain(open, DirectionIngress, dst.Pod, src, 6379, corev1.ProtocolTCP); v.Kind != Allowed || e.Effect != Admits {
		t.Errorf("open: %+v / %+v", v, e)
	}
}
