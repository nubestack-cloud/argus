package netpolmap

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

func ns(name string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: map[string]string{"kubernetes.io/metadata.name": name}}}
}

// deployPod is a pod owned by ReplicaSet <name>-rs, owned by Deployment <name>.
func deployPod(namespace, name string, lbl map[string]string) (*corev1.Pod, *appsv1.ReplicaSet) {
	yes := true
	rs := &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name + "-rs",
		OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: name, Controller: &yes}}}}
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name + "-rs-x", Labels: lbl,
			OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: name + "-rs", Controller: &yes}}},
		Spec:   corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Ports: []corev1.ContainerPort{{Name: "http", ContainerPort: 8080}}}}},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	return pod, rs
}

func tcp(n int) networkingv1.NetworkPolicyPort {
	p := corev1.ProtocolTCP
	v := intstr.FromInt(n)
	return networkingv1.NetworkPolicyPort{Protocol: &p, Port: &v}
}

func udp(n int) networkingv1.NetworkPolicyPort {
	p := corev1.ProtocolUDP
	v := intstr.FromInt(n)
	return networkingv1.NetworkPolicyPort{Protocol: &p, Port: &v}
}

func pol(namespace, name string, sel map[string]string, types []networkingv1.PolicyType, in []networkingv1.NetworkPolicyIngressRule, eg []networkingv1.NetworkPolicyEgressRule) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name},
		Spec: networkingv1.NetworkPolicySpec{PodSelector: metav1.LabelSelector{MatchLabels: sel}, PolicyTypes: types, Ingress: in, Egress: eg}}
}

func nsPeer(name string) networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{NamespaceSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": name}}}
}

func podPeer(lbl map[string]string) networkingv1.NetworkPolicyPeer {
	return networkingv1.NetworkPolicyPeer{PodSelector: &metav1.LabelSelector{MatchLabels: lbl}}
}

var both = []networkingv1.PolicyType{networkingv1.PolicyTypeIngress, networkingv1.PolicyTypeEgress}

func fixture() Input {
	app := map[string]string{"app": "shop"}
	role := func(r string) map[string]string { return map[string]string{"app": "shop", "role": r} }
	api, apiRS := deployPod("shop", "api", role("api"))
	db, dbRS := deployPod("shop", "db", map[string]string{"db": "main"})
	opsAPI, opsAPIRS := deployPod("shop", "ops-api", role("ops-api"))
	opsBFF, opsBFFRS := deployPod("shop", "ops-bff", role("ops-bff"))
	worker, workerRS := deployPod("shop", "worker", map[string]string{"app": "worker"})
	nginx, nginxRS := deployPod("ingress-nginx", "controller", map[string]string{"app": "nginx"})
	dns53 := []networkingv1.NetworkPolicyPort{udp(53), tcp(53)}
	return Input{
		Namespaces:  []*corev1.Namespace{ns("shop"), ns("ingress-nginx"), ns("kube-system")},
		Pods:        []*corev1.Pod{api, db, opsAPI, opsBFF, worker, nginx},
		ReplicaSets: []*appsv1.ReplicaSet{apiRS, dbRS, opsAPIRS, opsBFFRS, workerRS, nginxRS},
		Nodes: []*corev1.Node{{ObjectMeta: metav1.ObjectMeta{Name: "worker-1"},
			Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "10.0.0.11"}}}}},
		Policies: []*networkingv1.NetworkPolicy{
			// Default deny for the app, with DNS.
			pol("shop", "default-deny", app, both, nil, []networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{nsPeer("kube-system")}, Ports: dns53}}),
			pol("shop", "api", role("api"), both,
				[]networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{nsPeer("ingress-nginx"), {IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.11/32"}}}, Ports: []networkingv1.NetworkPolicyPort{tcp(8080)}}},
				[]networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{podPeer(map[string]string{"db": "main"})}, Ports: []networkingv1.NetworkPolicyPort{tcp(5432)}}}),
			pol("shop", "db", map[string]string{"db": "main"}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
				[]networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{podPeer(app), podPeer(map[string]string{"app": "gone"})}, Ports: []networkingv1.NetworkPolicyPort{tcp(5432)}}}, nil),
			// ops-api admits ops-bff, but ops-bff's own egress never lists ops-api.
			pol("shop", "ops-api", role("ops-api"), both,
				[]networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{podPeer(role("ops-bff"))}, Ports: []networkingv1.NetworkPolicyPort{tcp(8080)}}}, nil),
			// Egress-isolated with no DNS (worker is not labelled app=shop).
			pol("shop", "worker", map[string]string{"app": "worker"}, both, nil,
				[]networkingv1.NetworkPolicyEgressRule{{To: []networkingv1.NetworkPolicyPeer{podPeer(map[string]string{"db": "main"})}, Ports: []networkingv1.NetworkPolicyPort{tcp(5432)}}}),
			pol("shop", "stale", map[string]string{"app": "retired"}, both, nil, nil),
		},
	}
}

func workload(t *testing.T, m Map, name string) Workload {
	t.Helper()
	for _, w := range m.Workloads {
		if w.Name == name {
			return w
		}
	}
	t.Fatalf("no workload %q in %+v", name, m.Workloads)
	return Workload{}
}

func finding(m Map, code string) *Finding {
	for i := range m.Findings {
		if m.Findings[i].Code == code {
			return &m.Findings[i]
		}
	}
	return nil
}

func TestBuildResolvesPeersToWhatTheyMatch(t *testing.T) {
	m := Build(fixture(), "shop")
	api := workload(t, m, "api")
	if api.Kind != "Deployment" || !api.IngressIsolated || !api.EgressIsolated {
		t.Fatalf("api should be a Deployment isolated both ways: %+v", api)
	}
	var sawNS, sawNode bool
	for _, a := range api.Ingress {
		if a.Peer.Type == "namespace" && a.Peer.Namespace == "ingress-nginx" {
			sawNS = true
		}
		if a.Peer.Type == "cidr" && len(a.Peer.Nodes) == 1 && a.Peer.Nodes[0] == "worker-1" {
			sawNode = true
		}
		if strings.Join(a.Ports, ",") != "TCP 8080" {
			t.Errorf("api ingress ports = %v", a.Ports)
		}
	}
	if !sawNS || !sawNode {
		t.Errorf("api ingress should name the ingress-nginx namespace and node worker-1: %+v", api.Ingress)
	}
	db := workload(t, m, "db")
	var fromAPI bool
	for _, a := range db.Ingress {
		if a.Peer.Type == "workload" && a.Peer.Name == "api" {
			fromAPI = true
			if a.Effective != "allowed" {
				t.Errorf("api -> db is allowed by both ends, got %q", a.Effective)
			}
		}
	}
	if !fromAPI {
		t.Errorf("db's app=shop rule should resolve to the api Deployment: %+v", db.Ingress)
	}
	if db.EgressIsolated {
		t.Errorf("db has no Egress policy")
	}
}

func TestFindings(t *testing.T) {
	m := Build(fixture(), "shop")
	for code, want := range map[string]string{
		"half-open":    "Deployment ops-api from Deployment shop/ops-bff",
		"dns-blocked":  "Deployment worker",
		"dead-rule":    "app=gone",
		"empty-policy": "NetworkPolicy stale",
		"egress-open":  "Deployment db",
	} {
		f := finding(m, code)
		if f == nil {
			t.Errorf("missing finding %s; have %+v", code, m.Findings)
			continue
		}
		if !strings.Contains(strings.Join(f.Objects, "\n"), want) {
			t.Errorf("finding %s objects %v do not mention %q", code, f.Objects, want)
		}
	}
	// Default deny with a DNS rule: api resolves names fine.
	if f := finding(m, "dns-blocked"); f != nil && strings.Contains(strings.Join(f.Objects, " "), "Deployment api") {
		t.Errorf("api has a DNS egress rule but was reported: %v", f.Objects)
	}
	// Every workload is selected for ingress, so nothing is wide open.
	if finding(m, "open-ingress") != nil {
		t.Errorf("no workload is unselected for ingress: %+v", finding(m, "open-ingress"))
	}
}

func TestNamespaceWithoutPoliciesIsOneFinding(t *testing.T) {
	m := Build(fixture(), "ingress-nginx")
	if len(m.Findings) != 1 || m.Findings[0].Code != "no-policies" {
		t.Fatalf("want exactly no-policies, got %+v", m.Findings)
	}
	w := workload(t, m, "controller")
	if w.IngressIsolated || len(w.Ingress) != 1 || w.Ingress[0].Peer.Type != "anywhere" {
		t.Errorf("an unselected workload accepts from anywhere: %+v", w)
	}
}

func TestIndexPutsWarningsFirst(t *testing.T) {
	idx := Index(fixture())
	if len(idx) != 2 || idx[0].Name != "shop" || idx[0].Warnings == 0 || idx[0].Policies != 6 {
		t.Fatalf("index = %+v", idx)
	}
	if idx[1].Name != "ingress-nginx" || idx[1].Open != 1 {
		t.Errorf("ingress-nginx row = %+v", idx[1])
	}
}

// Observed on rke2 2026-10-13: rke2-canal (hostNetwork) was reported as
// accepting from anyone. Policy does not apply to host-network pods at all.
func TestHostNetworkPodsAreNotJudged(t *testing.T) {
	in := fixture()
	canal, canalRS := deployPod("shop", "canal", map[string]string{"app": "canal"})
	canal.Spec.HostNetwork = true
	in.Pods = append(in.Pods, canal)
	in.ReplicaSets = append(in.ReplicaSets, canalRS)
	m := Build(in, "shop")
	w := workload(t, m, "canal")
	if !w.HostNetwork || len(w.Ingress) != 0 || len(w.Egress) != 0 {
		t.Fatalf("host-network workload should carry no allows: %+v", w)
	}
	for _, f := range m.Findings {
		if strings.Contains(strings.Join(f.Objects, " "), "Deployment canal") {
			t.Errorf("finding %s names a host-network workload", f.Code)
		}
	}
}

// Observed on rke2 2026-10-13: nebula-db admits every app pod, and
// nebula-admin's own egress goes only to the pooler. That refused path is the
// design working, not a mistake: marked on the allow, not a finding.
func TestBroadSelectorRefusalIsNotAFinding(t *testing.T) {
	m := Build(fixture(), "shop")
	db := workload(t, m, "db")
	var bff *Allow
	for i, a := range db.Ingress {
		if a.Peer.Type == "workload" && a.Peer.Name == "ops-bff" {
			bff = &db.Ingress[i]
		}
	}
	if bff == nil || bff.Effective != "blocked" || bff.Peer.Matched < 2 {
		t.Fatalf("db's app=shop rule should cover ops-bff, refused by ops-bff's egress: %+v", bff)
	}
	if f := finding(m, "half-open"); f != nil && strings.Contains(strings.Join(f.Objects, " "), "Deployment db") {
		t.Errorf("a broad selector's refused path was reported: %v", f.Objects)
	}
}

// Observed on rke2 2026-10-13: nebula-db-pooler-rw appeared twice in nebula-db's
// inbound list, once per rule that admits it.
func TestOnePeerPerWorkloadAcrossRules(t *testing.T) {
	in := fixture()
	extra := pol("shop", "db-metrics", map[string]string{"db": "main"}, []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		[]networkingv1.NetworkPolicyIngressRule{{From: []networkingv1.NetworkPolicyPeer{podPeer(map[string]string{"app": "shop", "role": "api"})}, Ports: []networkingv1.NetworkPolicyPort{tcp(9187)}}}, nil)
	in.Policies = append(in.Policies, extra)
	m := Build(in, "shop")
	var seen []Allow
	for _, a := range workload(t, m, "db").Ingress {
		if a.Peer.Type == "workload" && a.Peer.Name == "api" {
			seen = append(seen, a)
		}
	}
	if len(seen) != 1 {
		t.Fatalf("api should be one peer of db, got %d: %+v", len(seen), seen)
	}
	if strings.Join(seen[0].Ports, ",") != "TCP 5432,TCP 9187" || seen[0].Peer.Matched != 1 {
		t.Errorf("merged peer = %+v", seen[0])
	}
}
