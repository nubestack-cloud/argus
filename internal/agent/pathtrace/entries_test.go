package pathtrace

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// A publishNotReadyAddresses Service publishes endpoints regardless of
// readiness, so meta "ready" counts published endpoints and the 0-ready
// note is info, not warning. A plain Service keeps strict readiness.
func TestBuildPodsHop_PublishNotReadyAddresses(t *testing.T) {
	notReadyPod := func(name, ip string) *corev1.Pod {
		p := mkPod(name, "prod", map[string]string{"app": "db"}, false, corev1.ContainerPort{ContainerPort: 5432})
		p.Status.PodIP = ip
		return p
	}
	svc := func(pnr bool) *corev1.Service {
		s := mkService("db", "prod", map[string]string{"app": "db"}, corev1.ServicePort{Port: 5432})
		s.Spec.PublishNotReadyAddresses = pnr
		return s
	}
	pods := []*corev1.Pod{notReadyPod("db-0", "10.0.0.1"), notReadyPod("db-1", "10.0.0.2")}
	cases := []struct {
		name         string
		pnr          bool
		wantReady    int
		wantSeverity string
	}{
		{"publishNotReadyAddresses", true, 2, SeverityInfo},
		{"plain Service", false, 0, SeverityWarning},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := walker{p: newFake()}
			hop := w.buildPodsHop(svc(c.pnr), pods, false)
			if got := hop.Meta["ready"]; got != c.wantReady {
				t.Errorf("meta[ready] = %v, want %d", got, c.wantReady)
			}
			if got, _ := hop.Meta["publishNotReadyAddresses"].(bool); got != c.pnr {
				t.Errorf("meta[publishNotReadyAddresses] = %v", got)
			}
			f := findingByCode(hop.Findings, "pods:no-ready-endpoints")
			if f == nil {
				t.Fatalf("expected the no-ready note, got %+v", hop.Findings)
			}
			if f.Severity != c.wantSeverity {
				t.Errorf("severity = %q, want %q", f.Severity, c.wantSeverity)
			}
			if c.pnr && !strings.Contains(f.Message, "publishNotReadyAddresses") {
				t.Errorf("PNR note should explain traffic still routes, got %q", f.Message)
			}
			svcF := serviceBackendFindings(svc(c.pnr), pods, false)
			if len(svcF) != 1 || svcF[0].Code != "svc:no-ready-endpoints" {
				t.Fatalf("service findings = %+v", svcF)
			}
			wantSvcSev := SeverityCritical
			if c.pnr {
				wantSvcSev = SeverityInfo
			}
			if svcF[0].Severity != wantSvcSev {
				t.Errorf("service no-ready severity = %q, want %q", svcF[0].Severity, wantSvcSev)
			}
		})
	}
}

// PNR waives readiness, not the terminal-phase or has-an-IP rules.
func TestBuildPodsHop_PNRCountsOnlyPublishedEndpoints(t *testing.T) {
	pod := func(name, ip string, phase corev1.PodPhase, deleted bool) *corev1.Pod {
		p := mkPod(name, "prod", map[string]string{"app": "db"}, false)
		p.Status.Phase, p.Status.PodIP = phase, ip
		if deleted {
			gone := metav1.Now()
			p.DeletionTimestamp = &gone
		}
		return p
	}
	svc := mkService("db", "prod", map[string]string{"app": "db"}, corev1.ServicePort{Port: 5432})
	svc.Spec.PublishNotReadyAddresses = true
	pods := []*corev1.Pod{
		pod("running-not-ready", "10.0.0.1", corev1.PodRunning, false),
		pod("terminating", "10.0.0.2", corev1.PodRunning, true),
		pod("succeeded", "10.0.0.3", corev1.PodSucceeded, false),
		pod("failed", "10.0.0.4", corev1.PodFailed, false),
		pod("no-ip", "", corev1.PodPending, false),
	}
	w := walker{p: newFake()}
	hop := w.buildPodsHop(svc, pods, false)
	if got := hop.Meta["ready"]; got != 2 {
		t.Errorf("meta[ready] = %v, want 2", got)
	}
	if got := hop.Meta["selected"]; got != 5 {
		t.Errorf("meta[selected] = %v, want 5", got)
	}
}

// Unreadable pods are uncertain, not a confident empty; no selector is
// genuinely nothing to read.
func TestSelectedPods_UnreadableIsNotEmpty(t *testing.T) {
	f := newFake()
	f.unreadable["Pod"] = true
	w := walker{p: f}
	withSelector := mkService("shop", "prod", map[string]string{"app": "shop"})
	if pods, unreadable := w.selectedPods(withSelector); !unreadable || pods != nil {
		t.Errorf("selector + unreadable pods: got %v/%v, want nil/true", pods, unreadable)
	}
	if pods, unreadable := w.selectedPods(mkService("db", "prod", nil)); unreadable || pods != nil {
		t.Errorf("no selector: got %v/%v, want nil/false", pods, unreadable)
	}
	if pods, unreadable := w.selectedPods(nil); unreadable || pods != nil {
		t.Errorf("nil svc: got %v/%v", pods, unreadable)
	}
}

func TestSelectedPods_MatchesSelectorInNamespace(t *testing.T) {
	f := newFake()
	f.pods = append(f.pods,
		mkPod("a", "prod", map[string]string{"app": "shop", "tier": "web"}, true),
		mkPod("b", "prod", map[string]string{"app": "other"}, true),
		mkPod("c", "dev", map[string]string{"app": "shop"}, true),
	)
	w := walker{p: f}
	pods, _ := w.selectedPods(mkService("shop", "prod", map[string]string{"app": "shop"}))
	if len(pods) != 1 || pods[0].Name != "a" {
		t.Errorf("pods = %+v", pods)
	}
}

func TestPodsWorkloadResolvesThroughTheReplicaSet(t *testing.T) {
	ctrl := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "web-abc-1", Namespace: "prod",
		OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "web-abc", Controller: &ctrl}},
	}}
	f := newFake()
	f.unreadable["ReplicaSet"] = true
	w := walker{p: f}
	if got := w.ownerWorkload(pod); got == nil || got.Kind != "ReplicaSet" || got.Name != "web-abc" {
		t.Errorf("unreadable ReplicaSet: got %+v, want the ReplicaSet itself", got)
	}
	f.unreadable["ReplicaSet"] = false
	f.replicaSets = append(f.replicaSets, &appsv1.ReplicaSet{ObjectMeta: metav1.ObjectMeta{
		Name: "web-abc", Namespace: "prod",
		OwnerReferences: []metav1.OwnerReference{{Kind: "Deployment", Name: "web", Controller: &ctrl}},
	}})
	if got := w.ownerWorkload(pod); got == nil || got.Kind != "Deployment" || got.Name != "web" {
		t.Errorf("got %+v, want Deployment web", got)
	}
}

func TestPodsWorkloadTakesADirectOwnerAsIs(t *testing.T) {
	ctrl := true
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
		Name: "db-0", Namespace: "prod",
		OwnerReferences: []metav1.OwnerReference{{Kind: "StatefulSet", Name: "db", Controller: &ctrl}},
	}}
	w := walker{p: newFake()}
	if got := w.ownerWorkload(pod); got == nil || got.Kind != "StatefulSet" || got.Name != "db" {
		t.Errorf("got %+v", got)
	}
}

func TestPodsWorkloadDeclinesWhenOwnersDisagree(t *testing.T) {
	ctrl := true
	mk := func(name, owner string) *corev1.Pod {
		return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: "prod",
			OwnerReferences: []metav1.OwnerReference{{Kind: "StatefulSet", Name: owner, Controller: &ctrl}},
		}}
	}
	w := walker{p: newFake()}
	if got := w.podsWorkload([]*corev1.Pod{mk("a", "one"), mk("b", "two")}); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

func TestPodsWorkloadIsNilForAnUnownedPod(t *testing.T) {
	w := walker{p: newFake()}
	if got := w.podsWorkload([]*corev1.Pod{{ObjectMeta: metav1.ObjectMeta{Name: "solo", Namespace: "prod"}}}); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

// The Pods hop roster carries ready and not-ready pods, the not-ready with
// a plain-English cause.
func TestPodsConfig_PerPodRoster(t *testing.T) {
	ready := mkPod("ready-1", "prod", nil, true, corev1.ContainerPort{ContainerPort: 8080})
	crashing := crashingPod("bad-1", "prod", nil)
	c := podsConfig([]*corev1.Pod{ready, crashing}, &corev1.Service{})
	if c == nil || len(c.Pods) != 2 {
		t.Fatalf("roster = %+v, want 2 rows", c)
	}
	byName := map[string]PodStatus{}
	for _, p := range c.Pods {
		byName[p.Name] = p
	}
	if !byName["ready-1"].Ready || byName["ready-1"].IP == "" {
		t.Errorf("ready-1 = %+v", byName["ready-1"])
	}
	if byName["bad-1"].Ready || !strings.Contains(strings.ToLower(byName["bad-1"].Reason), "crash") {
		t.Errorf("bad-1 = %+v", byName["bad-1"])
	}
}

// A not-ready pod is never capped out of the roster, and PodTotal keeps the
// true count.
func TestPodsConfig_CulpritNeverSampledOut(t *testing.T) {
	var pods []*corev1.Pod
	for i := 0; i < maxPodsInConfig+2; i++ {
		pods = append(pods, mkPod("a"+string(rune('a'+i)), "prod", nil, true))
	}
	pods = append(pods, crashingPod("zzz-crash", "prod", nil))
	c := podsConfig(pods, &corev1.Service{})
	if c.PodTotal != maxPodsInConfig+3 {
		t.Errorf("PodTotal = %d", c.PodTotal)
	}
	if len(c.Pods) != maxPodsInConfig {
		t.Errorf("roster len = %d, want capped at %d", len(c.Pods), maxPodsInConfig)
	}
	if c.Pods[0].Name != "zzz-crash" {
		t.Errorf("the culprit must lead the roster; got %+v", c.Pods[0])
	}
}

// Container ports are filtered to those the Service targets.
func TestPodsConfig_OnlyTargetedContainerPorts(t *testing.T) {
	pod := mkPod("p", "prod", nil, true,
		corev1.ContainerPort{Name: "http", ContainerPort: 8080},
		corev1.ContainerPort{Name: "metrics", ContainerPort: 9090})
	c := podsConfig([]*corev1.Pod{pod}, mkService("s", "prod", nil))
	if len(c.ContainerPorts) != 1 || c.ContainerPorts[0].Port != 8080 {
		t.Errorf("container ports = %+v, want only the targeted :8080", c.ContainerPorts)
	}
}

func TestEndpointSlicesWithNoEndpointsSaysSo(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("manual", "prod", nil, corev1.ServicePort{Port: 80}))
	tr := build(t, f, "Service", "prod", "manual")
	if sf := findingByCode(tr.Findings, "svc:selectorless"); sf == nil || !strings.Contains(sf.Message, "no endpoints at all") {
		t.Errorf("selectorless finding = %+v", sf)
	}
}
