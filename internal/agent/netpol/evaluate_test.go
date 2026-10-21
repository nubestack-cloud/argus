package netpol

import (
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// The test world: a cart pod in storefront calling redis in data.

func newPod(ns, name, ip string, labels map[string]string, ports ...corev1.ContainerPort) *corev1.Pod {
	p := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "main", Ports: ports}}}}
	p.Namespace, p.Name, p.Labels, p.Status.PodIP = ns, name, labels, ip
	return p
}

func newNamespace(name string, extra ...string) *corev1.Namespace {
	ns := &corev1.Namespace{}
	ns.Name = name
	ns.Labels = map[string]string{"kubernetes.io/metadata.name": name}
	for _, kv := range extra {
		k, v, _ := strings.Cut(kv, "=")
		ns.Labels[k] = v
	}
	return ns
}

var (
	cartLabels  = map[string]string{"app": "cart"}
	redisLabels = map[string]string{"app": "redis"}
)

func cart() Peer {
	return Peer{Pod: newPod("storefront", "cart-7f", "10.42.1.20", cartLabels), Namespace: newNamespace("storefront", "team=web")}
}

func redis(port int32) Backend {
	pod := newPod("data", "redis-0", "10.42.3.7", redisLabels, corev1.ContainerPort{Name: "redis", ContainerPort: 6379})
	return Backend{Peer: Peer{Pod: pod, Namespace: newNamespace("data")}, Port: port, Protocol: corev1.ProtocolTCP}
}

// netPolicy builds a policy in ns; each option shapes its spec.
func netPolicy(ns, name string, opts ...func(*networkingv1.NetworkPolicySpec)) *networkingv1.NetworkPolicy {
	np := &networkingv1.NetworkPolicy{}
	np.Namespace, np.Name = ns, name
	for _, o := range opts {
		o(&np.Spec)
	}
	return np
}

func selecting(labels map[string]string) func(*networkingv1.NetworkPolicySpec) {
	return func(s *networkingv1.NetworkPolicySpec) { s.PodSelector = metav1.LabelSelector{MatchLabels: labels} }
}

func isolates(types ...networkingv1.PolicyType) func(*networkingv1.NetworkPolicySpec) {
	return func(s *networkingv1.NetworkPolicySpec) { s.PolicyTypes = types }
}

const (
	in  = networkingv1.PolicyTypeIngress
	out = networkingv1.PolicyTypeEgress
)

// allowIn adds one ingress rule; nil ports and no peers mean everything.
func allowIn(ports []networkingv1.NetworkPolicyPort, from ...networkingv1.NetworkPolicyPeer) func(*networkingv1.NetworkPolicySpec) {
	return func(s *networkingv1.NetworkPolicySpec) {
		s.Ingress = append(s.Ingress, networkingv1.NetworkPolicyIngressRule{Ports: ports, From: from})
	}
}

func allowOut(ports []networkingv1.NetworkPolicyPort, to ...networkingv1.NetworkPolicyPeer) func(*networkingv1.NetworkPolicySpec) {
	return func(s *networkingv1.NetworkPolicySpec) {
		s.Egress = append(s.Egress, networkingv1.NetworkPolicyEgressRule{Ports: ports, To: to})
	}
}

func tcp(n int32) networkingv1.NetworkPolicyPort {
	p := intstr.FromInt32(n)
	return networkingv1.NetworkPolicyPort{Port: &p}
}

func tcpRange(from, to int32) networkingv1.NetworkPolicyPort {
	p := tcp(from)
	p.EndPort = &to
	return p
}

func named(name string) networkingv1.NetworkPolicyPort {
	p := intstr.FromString(name)
	return networkingv1.NetworkPolicyPort{Port: &p}
}

func ports(p ...networkingv1.NetworkPolicyPort) []networkingv1.NetworkPolicyPort { return p }

func nsNamed(name string) networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": name}}}
}

func podsHere(labels map[string]string) networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{PodSelector: &metav1.LabelSelector{MatchLabels: labels}}
}

func podsAnywhere(labels map[string]string) networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{NamespaceSelector: &metav1.LabelSelector{}, PodSelector: &metav1.LabelSelector{MatchLabels: labels}}
}

func anyNamespace() networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{NamespaceSelector: &metav1.LabelSelector{}}
}

func cidr(c string, except ...string) networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{IPBlock: &networkingv1.IPBlock{CIDR: c, Except: except}}
}

// verdictText is "allowed", "unknown", or "denied <direction> [policies]".
func verdictText(v Verdict) string {
	if v.Kind != Denied {
		return v.Kind.String()
	}
	return fmt.Sprintf("denied %s %v", v.Direction, v.Policies)
}

func TestEvaluate(t *testing.T) {
	denyAll := netPolicy("data", "deny-all", isolates(in))
	withPodIPs := func(p Peer, ips ...string) Peer {
		for _, ip := range ips {
			p.Pod.Status.PodIPs = append(p.Pod.Status.PodIPs, corev1.PodIP{IP: ip})
		}
		return p
	}
	cases := []struct {
		why      string
		src      Peer
		dst      []Backend
		policies []*networkingv1.NetworkPolicy
		want     string
	}{
		{"nothing isolates anything", cart(), []Backend{redis(6379)}, nil, "allowed"},
		{"a default deny on the destination", cart(), []Backend{redis(6379)}, []*networkingv1.NetworkPolicy{denyAll}, "denied ingress [data/deny-all]"},
		{"a rule that admits everything", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "open", selecting(redisLabels), isolates(in), allowIn(nil))}, "allowed"},
		{"the source's namespace is selected", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "from-storefront", selecting(redisLabels), isolates(in), allowIn(nil, nsNamed("storefront")))}, "allowed"},
		{"another namespace is selected", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "from-batch", selecting(redisLabels), isolates(in), allowIn(nil, nsNamed("batch")))}, "denied ingress [data/from-batch]"},
		// A podSelector alone means pods in the policy's own namespace.
		{"a pod selector reaches only its own namespace", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "local", selecting(redisLabels), isolates(in), allowIn(nil, podsHere(cartLabels)))}, "denied ingress [data/local]"},
		{"pods of a label in any namespace", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "carts", selecting(redisLabels), isolates(in), allowIn(nil, podsAnywhere(cartLabels)))}, "allowed"},
		{"another port", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "sentinel-only", selecting(redisLabels), isolates(in), allowIn(ports(tcp(26379)), nsNamed("storefront")))}, "denied ingress [data/sentinel-only]"},
		{"a named port, looked up on the destination", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "named", selecting(redisLabels), isolates(in), allowIn(ports(named("redis")), nsNamed("storefront")))}, "allowed"},
		{"a port range", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "range", selecting(redisLabels), isolates(in), allowIn(ports(tcpRange(6000, 6999)), nsNamed("storefront")))}, "allowed"},
		{"an unset protocol is TCP", cart(), []Backend{func() Backend { b := redis(6379); b.Protocol = ""; return b }()},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "tcp", selecting(redisLabels), isolates(in), allowIn(ports(tcp(6379)), nsNamed("storefront")))}, "allowed"},
		// NetworkPolicy is additive.
		{"a second policy admits despite a deny-all", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{denyAll, netPolicy("data", "from-storefront", selecting(redisLabels), isolates(in), allowIn(nil, nsNamed("storefront")))}, "allowed"},
		{"a policy elsewhere has no say", cart(), []Backend{redis(6379)}, []*networkingv1.NetworkPolicy{netPolicy("batch", "deny-all", isolates(in))}, "allowed"},

		// Egress.
		{"the source may only reach DNS", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("storefront", "dns-only", selecting(cartLabels), isolates(out), allowOut(ports(tcp(53))))}, "denied egress [storefront/dns-only]"},
		{"egress allowed, ingress refused", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("storefront", "to-data", selecting(cartLabels), isolates(out), allowOut(nil, nsNamed("data"))), denyAll}, "denied ingress [data/deny-all]"},
		{"an egress ipBlock to a pod cannot be judged", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("storefront", "to-range", selecting(cartLabels), isolates(out), allowOut(nil, cidr("10.42.3.0/24")))}, "unknown"},

		// policyTypes defaulting.
		{"no policyTypes isolates ingress", cart(), []Backend{redis(6379)}, []*networkingv1.NetworkPolicy{netPolicy("data", "implicit", selecting(redisLabels))}, "denied ingress [data/implicit]"},
		{"no policyTypes, with egress rules, isolates egress too", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("storefront", "implicit-out", selecting(cartLabels), allowOut(ports(tcp(53))))}, "denied egress [storefront/implicit-out]"},
		{"an egress-only policy leaves ingress open", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "out-only", selecting(redisLabels), isolates(out))}, "allowed"},

		// Address ranges against pods are the network plugin's business.
		{"a range containing the source pod", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "range", selecting(redisLabels), isolates(in), allowIn(nil, cidr("10.42.0.0/16")))}, "unknown"},
		{"a range whose exception holds the source", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "range", selecting(redisLabels), isolates(in), allowIn(nil, cidr("10.42.0.0/16", "10.42.1.0/24")))}, "unknown"},
		{"a range missing the source, which may be rewritten", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "range", selecting(redisLabels), isolates(in), allowIn(nil, cidr("172.16.0.0/12")))}, "unknown"},
		{"a range and a source with no address", Peer{Pod: newPod("storefront", "cart-7f", "", cartLabels), Namespace: newNamespace("storefront")}, []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "range", selecting(redisLabels), isolates(in), allowIn(nil, cidr("10.42.0.0/16")))}, "unknown"},
		{"an IPv6 range and a dual-stack source", withPodIPs(cart(), "10.42.1.20", "fd42::20"), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "v6", selecting(redisLabels), isolates(in), allowIn(nil, cidr("fd42::/64")))}, "unknown"},
		{"an IPv6 range and an IPv4-only source", cart(), []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "v6", selecting(redisLabels), isolates(in), allowIn(nil, cidr("fd42::/64")))}, "unknown"},

		// What cannot be decided.
		{"a namespace selector without the source's Namespace", Peer{Pod: cart().Pod}, []Backend{redis(6379)},
			[]*networkingv1.NetworkPolicy{netPolicy("data", "from-storefront", selecting(redisLabels), isolates(in), allowIn(nil, nsNamed("storefront")))}, "unknown"},
		{"a host-network destination", cart(), []Backend{func() Backend { b := redis(6379); b.Pod.Spec.HostNetwork = true; return b }()}, []*networkingv1.NetworkPolicy{denyAll}, "unknown"},
		{"a host-network source", Peer{Pod: func() *corev1.Pod { p := cart().Pod; p.Spec.HostNetwork = true; return p }()}, []Backend{redis(6379)}, []*networkingv1.NetworkPolicy{denyAll}, "unknown"},
		{"a selector that cannot be parsed", cart(), []Backend{redis(6379)}, []*networkingv1.NetworkPolicy{netPolicy("data", "broken", isolates(in),
			func(s *networkingv1.NetworkPolicySpec) {
				s.PodSelector.MatchExpressions = []metav1.LabelSelectorRequirement{{Key: "app", Operator: "Resembles"}}
			})}, "unknown"},
		{"no destinations", cart(), nil, []*networkingv1.NetworkPolicy{denyAll}, "unknown"},

		// Several backends: the connection works if any one path does.
		{"one backend not selected by the deny", cart(), []Backend{redis(6379), func() Backend {
			b := redis(6379)
			b.Pod = newPod("data", "redis-replica-0", "10.42.3.8", map[string]string{"app": "redis-replica"})
			return b
		}()}, []*networkingv1.NetworkPolicy{netPolicy("data", "deny-redis", selecting(redisLabels), isolates(in))}, "allowed"},
		{"backends on different ports", cart(), []Backend{redis(6379), func() Backend {
			b := redis(6380)
			b.Pod = newPod("data", "redis-1", "10.42.3.9", redisLabels)
			return b
		}()}, []*networkingv1.NetworkPolicy{netPolicy("data", "6380", selecting(redisLabels), isolates(in), allowIn(ports(tcp(6380)), nsNamed("storefront")))}, "allowed"},
		// Egress reaches only shard a; ingress admits only shard b. No path
		// is whole, and both ends share the blame.
		{"egress to one backend, ingress to the other", cart(), func() []Backend {
			a, b := redis(6379), redis(6379)
			a.Pod = newPod("data", "redis-a", "10.42.3.10", map[string]string{"app": "redis", "shard": "a"})
			b.Pod = newPod("data", "redis-b", "10.42.3.11", map[string]string{"app": "redis", "shard": "b"})
			return []Backend{a, b}
		}(), []*networkingv1.NetworkPolicy{
			netPolicy("storefront", "to-shard-a", selecting(cartLabels), isolates(out), allowOut(nil, podsAnywhere(map[string]string{"shard": "a"}))),
			denyAll,
			netPolicy("data", "shard-b-open", selecting(map[string]string{"shard": "b"}), isolates(in), allowIn(nil, nsNamed("storefront"))),
		}, "denied ingress+egress [data/deny-all data/shard-b-open storefront/to-shard-a]"},
		{"a pod talking to itself", cart(), []Backend{{Peer: cart(), Port: 8080, Protocol: corev1.ProtocolTCP}},
			[]*networkingv1.NetworkPolicy{netPolicy("storefront", "deny-all", isolates(in))}, "allowed"},
	}
	for _, c := range cases {
		if got := verdictText(Evaluate(c.src, c.dst, c.policies)); got != c.want {
			t.Errorf("%s: %s, want %s", c.why, got, c.want)
		}
	}
}

func TestRuleMatchesPort(t *testing.T) {
	pod := redis(6379).Pod
	udp := corev1.ProtocolUDP
	udp53 := tcp(53)
	udp53.Protocol = &udp
	anyUDP := networkingv1.NetworkPolicyPort{Protocol: &udp}
	cases := []struct {
		rule  []networkingv1.NetworkPolicyPort
		port  int32
		proto corev1.Protocol
		want  bool
	}{
		{nil, 6379, "", true},
		{ports(tcp(6379)), 6379, "tcp", true},
		{ports(tcp(6379)), 6379, corev1.ProtocolUDP, false},
		{ports(tcpRange(6000, 6500)), 6500, "", true},
		{ports(tcpRange(6000, 6500)), 6501, "", false},
		// An end below the start is ignored: the entry is the one port.
		{ports(tcpRange(6379, 100)), 6379, "", true},
		{ports(named("redis")), 6379, "", true},
		// A name the pod does not declare does not match.
		{ports(named("metrics")), 6379, "", false},
		{ports(udp53, anyUDP), 9999, corev1.ProtocolUDP, true},
		{ports(udp53), 53, corev1.ProtocolTCP, false},
	}
	for _, c := range cases {
		if got := RuleMatchesPort(c.rule, c.port, c.proto, pod); got != c.want {
			t.Errorf("%v %d/%s: %v", c.rule, c.port, c.proto, got)
		}
	}
	if _, ok := ContainerPortByName(nil, "redis", corev1.ProtocolTCP); ok {
		t.Error("nil pod has ports")
	}
	if ProtocolOrTCP("") != corev1.ProtocolTCP || ProtocolOrTCP("sctp") != corev1.ProtocolSCTP {
		t.Error("protocol normalisation")
	}
}
