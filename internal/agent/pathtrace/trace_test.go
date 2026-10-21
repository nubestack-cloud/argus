package pathtrace

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/intstr"
)

var apiLabels = map[string]string{"app": "api"}

func build(t *testing.T, p Provider, kind, ns, name string) *Trace {
	t.Helper()
	return Build(context.Background(), p, kind, ns, name, Options{})
}

func TestBuild_ServiceHealthy(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "prod", apiLabels,
		corev1.ServicePort{Name: "http", Port: 80, TargetPort: intstr.FromString("http")}))
	pod := mkPod("api-1", "prod", apiLabels, true, corev1.ContainerPort{Name: "http", ContainerPort: 8080})
	pod.Spec.Containers[0].ReadinessProbe = &corev1.Probe{ProbeHandler: corev1.ProbeHandler{HTTPGet: &corev1.HTTPGetAction{Port: intstr.FromString("http")}}}
	f.pods = append(f.pods, pod)

	tr := build(t, f, "Service", "prod", "api")
	if tr.Verdict != VerdictHealthy {
		t.Fatalf("verdict = %q (%s), want healthy", tr.Verdict, tr.Reason)
	}
	if tr.Subject.Kind != "Service" || tr.Subject.Name != "api" {
		t.Errorf("subject = %+v", tr.Subject)
	}
	if len(tr.Downstream) != 2 || tr.Downstream[0].Resource.Kind != "Service" || tr.Downstream[1].Resource.Kind != "Pods" {
		t.Fatalf("downstream = %+v, want Service then Pods", tr.Downstream)
	}
	if tr.BrokenAt != -1 {
		t.Errorf("brokenAt = %d, want -1", tr.BrokenAt)
	}
	if tr.Downstream[1].Meta["selected"] != 1 || tr.Downstream[1].Meta["endpointSource"] != "pod-readiness" {
		t.Errorf("pods meta = %+v", tr.Downstream[1].Meta)
	}
	if hc := tr.Downstream[1].Config.HealthChecks; len(hc) != 1 || hc[0].Port != "http→8080" {
		t.Errorf("health checks = %+v, want the resolved readiness probe", hc)
	}
	if !strings.HasPrefix(tr.Headline, "No break found") || !strings.Contains(tr.Headline, "1 ready endpoint") || !strings.Contains(tr.Headline, "no traffic was sent") {
		t.Errorf("healthy headline = %q", tr.Headline)
	}
}

func TestBuild_ServiceNoSelectorIsSelectorless(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("manual", "prod", nil, corev1.ServicePort{Port: 80}))
	ready := true
	f.slices = append(f.slices, &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{Name: "manual-1", Namespace: "prod", Labels: map[string]string{discoveryv1.LabelServiceName: "manual"}},
		Endpoints:  []discoveryv1.Endpoint{{Addresses: []string{"10.1.1.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}}},
	})
	tr := build(t, f, "Service", "prod", "manual")
	if len(tr.Downstream) != 1 {
		t.Fatalf("downstream = %+v, want the Service hop only", tr.Downstream)
	}
	if tr.Downstream[0].Meta["selectorless"] != true || tr.Downstream[0].Meta["manualEndpoints"] != 1 {
		t.Errorf("meta = %+v", tr.Downstream[0].Meta)
	}
	f0 := findingByCode(tr.Findings, "svc:selectorless")
	if f0 == nil || !strings.Contains(f0.Message, "1 endpoint(s), 1 ready") {
		t.Errorf("selectorless finding = %+v", f0)
	}
	if tr.Verdict != VerdictUnknown || tr.UnknownClass != UnknownClassByDesign || tr.Reason == "" {
		t.Errorf("verdict=%q class=%q reason=%q, want unknown/by-design with a reason", tr.Verdict, tr.UnknownClass, tr.Reason)
	}
	if !strings.HasPrefix(tr.Headline, "Can't verify:") {
		t.Errorf("headline = %q", tr.Headline)
	}
}

func TestBuild_ServiceExternalNameIsTerminal(t *testing.T) {
	f := newFake()
	svc := mkService("ext", "prod", nil, corev1.ServicePort{Name: "https", Port: 443})
	svc.Spec.Type = corev1.ServiceTypeExternalName
	svc.Spec.ExternalName = "stripe.example.com"
	f.services = append(f.services, svc)
	tr := build(t, f, "Service", "prod", "ext")
	if len(tr.Downstream) != 2 || tr.Downstream[1].Resource.Kind != "ExternalName" {
		t.Fatalf("downstream = %+v", tr.Downstream)
	}
	if tr.Verdict != VerdictHealthy {
		t.Errorf("ExternalName verdict = %q, want healthy", tr.Verdict)
	}
	if !strings.Contains(tr.Headline, "stripe.example.com") {
		t.Errorf("headline = %q", tr.Headline)
	}
}

func TestBuild_ServiceWithUpstreamIngressIsParallel(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "prod", apiLabels))
	f.pods = append(f.pods, mkPod("api-1", "prod", apiLabels, true))
	f.ingresses = append(f.ingresses, ingressTo("ing-b", "prod", "api"), ingressTo("ing-a", "prod", "api"))
	tr := build(t, f, "Service", "prod", "api")
	if len(tr.Upstreams) != 2 || tr.Upstreams[0].Resource.Name != "ing-a" {
		t.Fatalf("upstreams = %+v, want both Ingresses sorted", tr.Upstreams)
	}
	if tr.Verdict != VerdictHealthy && tr.Verdict != VerdictDegraded {
		t.Errorf("verdict = %q", tr.Verdict)
	}
}

func TestBuild_BrokenServiceFlagsBrokenAt(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "prod", apiLabels))
	f.pods = append(f.pods, crashingPod("api-1", "prod", apiLabels))
	tr := build(t, f, "Service", "prod", "api")
	if tr.Verdict != VerdictBroken {
		t.Fatalf("verdict = %q, want broken with 0 ready pods", tr.Verdict)
	}
	// The "no ready endpoints" symptom sits on the Service hop - where
	// traffic stops - so BrokenAt is the Service.
	if tr.BrokenAt != 0 {
		t.Errorf("brokenAt = %d, want 0", tr.BrokenAt)
	}
	f0 := findingByCode(tr.Findings, "svc:no-ready-endpoints")
	if f0 == nil || f0.Hop != "downstream[0]" || f0.Severity != SeverityCritical {
		t.Fatalf("no-ready finding = %+v", f0)
	}
	// Linked to the crashing pod: its logs, not describe service.
	if f0.Resource == nil || f0.Resource.Name != "api-1" || f0.Command != "kubectl logs api-1 -n prod --previous" {
		t.Errorf("no-ready finding not linked to the culprit pod: %+v", f0)
	}
	want := "Breaks at: Service prod/api - No ready endpoints: 0 of 1 selected pods are ready"
	if !strings.HasPrefix(tr.Headline, want) || !strings.Contains(tr.Headline, "crash-looping") {
		t.Errorf("headline = %q, want prefix %q naming the crash loop", tr.Headline, want)
	}
	if pf := findingByCode(tr.Findings, "pods:no-ready-endpoints"); pf == nil || pf.Hop != "downstream[1]" {
		t.Errorf("pods hop should name the culprit, got %+v", pf)
	}
}

func TestBuild_SelectorMatchesNoPodsIsBroken(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "prod", apiLabels))
	tr := build(t, f, "Service", "prod", "api")
	if tr.Verdict != VerdictBroken || tr.BrokenAt != 0 {
		t.Fatalf("verdict=%q brokenAt=%d, want broken/0", tr.Verdict, tr.BrokenAt)
	}
	f0 := findingByCode(tr.Findings, "svc:no-ready-endpoints")
	if f0 == nil || !strings.Contains(f0.Message, "matches no pods") || f0.Command != "kubectl get pods -n prod -l app=api" {
		t.Errorf("finding = %+v", f0)
	}
}

func TestBuild_PartiallyReadyIsDegraded(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "prod", apiLabels))
	f.pods = append(f.pods, mkPod("api-1", "prod", apiLabels, true), crashingPod("api-2", "prod", apiLabels))
	tr := build(t, f, "Service", "prod", "api")
	if tr.Verdict != VerdictDegraded {
		t.Fatalf("verdict = %q, want degraded (one replica still serves)", tr.Verdict)
	}
	f0 := findingByCode(tr.Findings, "pods:some-not-ready")
	if f0 == nil || f0.Resource == nil || f0.Resource.Name != "api-2" {
		t.Errorf("some-not-ready finding = %+v", f0)
	}
	if !strings.HasPrefix(tr.Headline, "Degraded at: Pods") {
		t.Errorf("headline = %q", tr.Headline)
	}
}

func TestBuild_UnreadablePodsIsUnknown(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "prod", apiLabels))
	f.unreadable["Pod"] = true
	tr := build(t, f, "Service", "prod", "api")
	if tr.Verdict != VerdictUnknown || tr.UnknownClass != UnknownClassInvestigate {
		t.Fatalf("verdict=%q class=%q, want unknown/investigate", tr.Verdict, tr.UnknownClass)
	}
	if findingByCode(tr.Findings, "svc:no-ready-endpoints") != nil {
		t.Error("unreadable pods must not be reported as no ready endpoints")
	}
	if findingByCode(tr.Findings, "pods:lister-error") == nil {
		t.Error("expected pods:lister-error")
	}
}

func TestBuild_LoadBalancerPendingDegrades(t *testing.T) {
	f := newFake()
	svc := mkService("api", "prod", apiLabels)
	svc.Spec.Type = corev1.ServiceTypeLoadBalancer
	f.services = append(f.services, svc)
	f.pods = append(f.pods, mkPod("api-1", "prod", apiLabels, true))
	tr := build(t, f, "Service", "prod", "api")
	if tr.Verdict != VerdictDegraded || findingByCode(tr.Findings, "svc:loadbalancer-pending") == nil {
		t.Errorf("verdict=%q findings=%+v, want degraded with loadbalancer-pending", tr.Verdict, tr.Findings)
	}
}

func TestBuild_NilProviderReturnsUnknown(t *testing.T) {
	for _, tt := range []struct{ kind, group string }{
		{"Service", ""},
		{"Ingress", "networking.k8s.io"},
		{"HTTPRoute", "gateway.networking.k8s.io"},
		{"Gateway", "gateway.networking.k8s.io"},
	} {
		tr := Build(context.Background(), nil, tt.kind, "prod", "entry", Options{})
		if tr.Verdict != VerdictUnknown || tr.Reason == "" {
			t.Errorf("%s: verdict=%q reason=%q, want unknown with a reason", tt.kind, tr.Verdict, tr.Reason)
		}
		if tr.Subject.Kind != tt.kind || tr.Subject.Group != tt.group {
			t.Errorf("%s: subject = %+v, want group %q", tt.kind, tr.Subject, tt.group)
		}
	}
}

func TestBuild_UnknownKindReturnsUnknown(t *testing.T) {
	tr := build(t, newFake(), "Pod", "prod", "x")
	if tr.Verdict != VerdictUnknown {
		t.Errorf("verdict = %q, want unknown for unsupported kind", tr.Verdict)
	}
}

func TestBuild_MissingServiceIsUnknownNotBroken(t *testing.T) {
	tr := build(t, newFake(), "svc", "prod", "nope")
	if tr.Verdict != VerdictUnknown || !strings.Contains(tr.Reason, "not found") {
		t.Errorf("verdict=%q reason=%q", tr.Verdict, tr.Reason)
	}
	if tr.Subject.Kind != "Service" {
		t.Errorf("kind should normalize, got %+v", tr.Subject)
	}
}

func TestBuild_CancelledContextIsHonestPartial(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "prod", apiLabels))
	f.pods = append(f.pods, mkPod("api-1", "prod", apiLabels, true))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tr := Build(ctx, f, "Service", "prod", "api", Options{})
	if tr.Verdict != VerdictUnknown || !strings.Contains(tr.Reason, "partial") {
		t.Errorf("verdict=%q reason=%q, want unknown partial", tr.Verdict, tr.Reason)
	}
}

func TestBuild_JSONShape(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "prod", apiLabels))
	f.pods = append(f.pods, crashingPod("api-1", "prod", apiLabels))
	b, err := json.Marshal(build(t, f, "Service", "prod", "api"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"subject", "upstreams", "downstream", "verdict", "brokenAt", "headline", "findings"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q in %s", k, b)
		}
	}
	if m["upstreams"] == nil {
		t.Error("upstreams must be [] not null")
	}
	hop := m["downstream"].([]any)[0].(map[string]any)
	if _, ok := hop["findings"]; ok {
		t.Error("findings are flattened onto the trace, not repeated per hop")
	}
	fd := m["findings"].([]any)[0].(map[string]any)
	for _, k := range []string{"code", "hop", "severity", "message", "command"} {
		if _, ok := fd[k]; !ok {
			t.Errorf("finding missing %q: %v", k, fd)
		}
	}
}

func TestFlattenFindings_DefaultsCommandToHopReproducer(t *testing.T) {
	tr := &Trace{Downstream: []Hop{{
		Resource: ResourceRef{Kind: "Ingress", Namespace: "prod", Name: "web"},
		Findings: []Finding{{Code: "x", Severity: SeverityInfo}},
	}}}
	got := flattenFindings(tr)
	if len(got) != 1 || got[0].Hop != "downstream[0]" || got[0].Command != "kubectl describe ingress web -n prod" {
		t.Errorf("flattened = %+v", got)
	}
}

// --- Verdicts ---

// path builds hops from "Edge Kind/name sev [ready=N] [flag…]" specs, with
// "-" for no finding; a sev is crit, warn or info, or missing (a critical
// missing_ref finding). A flag is a true meta key, except unreadable, which
// marks the hop's endpoint source unknown. The first spec is the entry hop.
func path(specs ...string) []Hop {
	var hops []Hop
	for _, spec := range specs {
		f := strings.Fields(spec)
		kind, name, _ := strings.Cut(f[1], "/")
		h := Hop{Edge: f[0], Resource: ResourceRef{Kind: kind, Name: name}}
		switch f[2] {
		case "crit", "warn", "info":
			h.Findings = []Finding{{Code: "x:" + f[2], Severity: map[string]string{"crit": SeverityCritical, "warn": SeverityWarning, "info": SeverityInfo}[f[2]]}}
		case "missing":
			h.Findings = []Finding{{Code: "missing_ref:backend-service", Severity: SeverityCritical}}
		}
		for _, extra := range f[3:] {
			if h.Meta == nil {
				h.Meta = map[string]any{}
			}
			if n, ok := strings.CutPrefix(extra, "ready="); ok {
				h.Meta["ready"], _ = strconv.Atoi(n)
			} else if extra == "unreadable" {
				h.Meta["endpointSource"] = "unknown"
			} else {
				h.Meta[extra] = true
			}
		}
		hops = append(hops, h)
	}
	return hops
}

func TestComputeVerdict(t *testing.T) {
	cases := []struct {
		why        string
		down, up   []Hop
		verdict    string
		brokenAt   int
		reasonHint string
	}{
		{"one backend of two broken", path("entry:Ingress Ingress/app -", "Ingress->Service Service/a crit", "Service->Pods Pods -", "Ingress->Service Service/b -"),
			nil, VerdictDegraded, 1, "1 of 2 routes broken"},
		{"every backend broken", path("entry:Ingress Ingress/app -", "Ingress->Service Service/a crit", "Ingress->Service Service/b crit"),
			nil, VerdictBroken, 1, "all 2 routes broken"},
		{"the entry itself broken", path("entry:Ingress Ingress/app crit", "Ingress->Service Service/a -"),
			nil, VerdictBroken, 0, ""},
		{"a warning on the entry", path("entry:Ingress Ingress/app warn", "Ingress->Service Service/a -"),
			nil, VerdictDegraded, -1, ""},
		{"a single chain", path("entry:Service Service/svc -", "Service->Pods Pods crit"),
			nil, VerdictBroken, 1, ""},
		// A missing backend named on the entry is one broken route of two.
		{"a missing backend beside a working one", path("entry:Ingress Ingress/app missing", "Ingress->Service Service/echo -", "Service->Pods Pods -", "Ingress->Service Service/ghost -"),
			nil, VerdictDegraded, 0, "1 of 2 routes broken"},
		{"the only backend missing", path("entry:Ingress Ingress/app missing", "Ingress->Service Service/ghost -"),
			nil, VerdictBroken, 0, ""},
		// Traffic still reaches the ready pods.
		{"critical pods with one ready", path("entry:Service Service/dual -", "Service->Pods Pods crit ready=1"),
			nil, VerdictDegraded, -1, ""},
		{"critical pods with none ready", path("entry:Service Service/dual -", "Service->Pods Pods crit ready=0"),
			nil, VerdictBroken, 1, ""},
		{"one Gateway route of two broken", path("entry:Gateway Gateway/gw -", "Gateway->HTTPRoute HTTPRoute/ok -", "Gateway->HTTPRoute HTTPRoute/bad crit"),
			nil, VerdictDegraded, 2, "1 of 2 routes broken"},
		// A weight-0 backend carries nothing, so its pods cannot break the path.
		{"a drained backend", path("entry:HTTPRoute HTTPRoute/r -", "HTTPRoute->Service Service/stable -", "Service->Pods Pods -", "HTTPRoute->Service Service/canary info drained", "Service->Pods Pods crit"),
			nil, VerdictHealthy, -1, ""},
		// Upstream: a missing backend there is some other route's problem.
		{"an upstream's missing backend", path("entry:Service Service/echo -"), path("x Ingress/multi missing"),
			VerdictHealthy, -1, ""},
		{"one upstream of two broken", path("entry:Service Service/echo -"), path("x Ingress/a crit", "x Ingress/b -"),
			VerdictDegraded, -1, ""},
		// Nothing reaches the subject, but the subject is not to blame.
		{"every upstream broken", path("entry:Service Service/echo -"), path("x Ingress/web crit"),
			VerdictBroken, -1, "every entry path"},
		{"a selectorless Service", path("entry:Service Service/manual - selectorless"), nil,
			VerdictUnknown, -1, ""},
		{"unreadable pods", path("entry:Service Service/svc -", "Service->Pods Pods info unreadable"),
			nil, VerdictUnknown, -1, ""},
		{"a broken path stays broken even if unverifiable", path("entry:Service Service/svc crit", "Service->Pods Pods - unreadable"),
			nil, VerdictBroken, 0, ""},
	}
	for _, c := range cases {
		tr := &Trace{Downstream: c.down, Upstreams: c.up}
		v, at := computeVerdict(tr)
		if v != c.verdict || at != c.brokenAt || !strings.Contains(tr.Reason, c.reasonHint) {
			t.Errorf("%s: %s at %d (%q), want %s at %d (…%q…)", c.why, v, at, tr.Reason, c.verdict, c.brokenAt, c.reasonHint)
		}
	}
}

// --- Reproducers and pod diagnosis ---

func TestReproducerForRef_PodTargetsTheSpecificPod(t *testing.T) {
	cmd := reproducerForRef(ResourceRef{Kind: "Pod", Namespace: "prod", Name: "web-abc123"})
	if cmd != "kubectl describe pod web-abc123 -n prod" {
		t.Errorf("pod reproducer = %q", cmd)
	}
	if got := reproducerForRef(ResourceRef{Kind: "HTTPRoute", Namespace: "prod", Name: "r"}); !strings.Contains(got, "status.parents") {
		t.Errorf("route reproducer = %q", got)
	}
}

func TestSelectorReproducer_Sorted(t *testing.T) {
	got := selectorReproducer(ResourceRef{Namespace: "prod"}, map[string]string{"tier": "web", "app": "shop"})
	if got != "kubectl get pods -n prod -l app=shop,tier=web" {
		t.Errorf("got %q", got)
	}
}

func TestPodDiagnosis_StateTrueCommand(t *testing.T) {
	waiting := func(reason string) *corev1.Pod {
		return &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "prod"},
			Status: corev1.PodStatus{ContainerStatuses: []corev1.ContainerStatus{
				{Name: "app", State: corev1.ContainerState{Waiting: &corev1.ContainerStateWaiting{Reason: reason}}},
			}},
		}
	}
	cause, cmd := podDiagnosis(waiting("CrashLoopBackOff"))
	if cmd != "kubectl logs p -n prod --previous" || !strings.Contains(cause, "CrashLoopBackOff") {
		t.Errorf("crashloop = (%q, %q)", cause, cmd)
	}
	for _, reason := range []string{"ImagePullBackOff", "ErrImagePull"} {
		c, cmd := podDiagnosis(waiting(reason))
		if cmd != "kubectl describe pod p -n prod" || !strings.Contains(c, "image") {
			t.Errorf("%s = (%q, %q), want describe and an image cause", reason, c, cmd)
		}
	}
	pending := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", Namespace: "prod"}, Status: corev1.PodStatus{Phase: corev1.PodPending}}
	if c, cmd := podDiagnosis(pending); strings.Contains(cmd, "--previous") || !strings.Contains(c, "Pending") {
		t.Errorf("pending = (%q, %q)", c, cmd)
	}
}

// --- targetPort checks ---

func readyPodPorts(name string, ports ...int32) *corev1.Pod {
	cps := make([]corev1.ContainerPort, len(ports))
	for i, p := range ports {
		cps[i] = corev1.ContainerPort{ContainerPort: p}
	}
	return mkPod(name, "prod", nil, true, cps...)
}

func svcPorts(port, targetPort int32) *corev1.Service {
	return mkService("api", "prod", nil, corev1.ServicePort{Port: port, TargetPort: intstr.FromInt32(targetPort)})
}

func TestTargetPortAdvisory_FiresOnPositiveEvidence(t *testing.T) {
	f, ok := targetPortAdvisory(svcPorts(80, 9999), []*corev1.Pod{readyPodPorts("p", 8080)})
	if !ok {
		t.Fatal("expected the advisory when pods declare :8080 but the Service targets :9999")
	}
	if f.Severity != SeverityWarning || f.Code != "svc:targetport-no-listener" {
		t.Errorf("finding = %+v", f)
	}
	if !strings.Contains(f.Message, "9999") || !strings.Contains(f.Message, ":8080") {
		t.Errorf("message = %q", f.Message)
	}
	if f.Command != "kubectl get svc api -n prod -o yaml" {
		t.Errorf("command = %q", f.Command)
	}
}

func TestTargetPortAdvisory_SilentWhenNoPortsDeclared(t *testing.T) {
	if _, ok := targetPortAdvisory(svcPorts(80, 9999), []*corev1.Pod{readyPodPorts("p")}); ok {
		t.Error("must not fire when pods declare no container ports")
	}
}

func TestTargetPortAdvisory_SilentWhenMatched(t *testing.T) {
	if _, ok := targetPortAdvisory(svcPorts(80, 8080), []*corev1.Pod{readyPodPorts("p", 8080)}); ok {
		t.Error("must not fire when the targetPort matches")
	}
}

func TestTargetPortAdvisory_DegradesNotBreaks(t *testing.T) {
	adv, _ := targetPortAdvisory(svcPorts(80, 9999), []*corev1.Pod{readyPodPorts("p", 8080)})
	tr := &Trace{Downstream: []Hop{
		{Resource: ResourceRef{Kind: "Service", Name: "api"}, Edge: "entry:Service", Findings: []Finding{adv}},
		{Resource: ResourceRef{Kind: "Pods"}, Edge: "Service->Pods"},
	}}
	if v, _ := computeVerdict(tr); v != VerdictDegraded {
		t.Errorf("verdict = %q, want degraded", v)
	}
}

func TestUnresolvedNamedTargetPort(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "prod", apiLabels, corev1.ServicePort{Port: 80, TargetPort: intstr.FromString("web")}))
	f.pods = append(f.pods, mkPod("api-1", "prod", apiLabels, true, corev1.ContainerPort{Name: "http", ContainerPort: 8080}))
	tr := build(t, f, "Service", "prod", "api")
	if findingByCode(tr.Findings, "svc:unresolved-targetport") == nil || tr.Verdict != VerdictDegraded {
		t.Errorf("verdict=%q findings=%+v", tr.Verdict, tr.Findings)
	}
}

// --- Upstream enumeration honesty ---

func TestServiceUpstreams_UnreadableRouteIndexFlagsIncomplete(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "team-a", nil, corev1.ServicePort{Port: 80}))
	f.unreadable["HTTPRoute"] = true
	tr := build(t, f, "Service", "team-a", "api")
	if len(tr.Upstreams) != 0 {
		t.Errorf("upstreams = %+v", tr.Upstreams)
	}
	if findingByCode(tr.Findings, "trace:upstreams-incomplete") == nil {
		t.Errorf("expected upstreams-incomplete, got %+v", tr.Findings)
	}
}

func TestServiceUpstreams_UnreadableIngressFlagsIncomplete(t *testing.T) {
	f := newFake()
	svc := mkService("api", "team-a", nil)
	f.unreadable["Ingress"] = true
	w := walker{p: f}
	hops, complete := w.serviceUpstreams(context.Background(), svc)
	if len(hops) != 0 || complete {
		t.Errorf("hops=%+v complete=%v, want none and incomplete", hops, complete)
	}
}

func TestServiceUpstreams_AbsentGatewayAPIIsComplete(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "prod", apiLabels))
	f.pods = append(f.pods, mkPod("api-1", "prod", apiLabels, true))
	f.ingresses = append(f.ingresses, ingressTo("web", "prod", "api"))
	f.absent["HTTPRoute"], f.absent["GRPCRoute"] = true, true
	tr := build(t, f, "Service", "prod", "api")
	if findingByCode(tr.Findings, "trace:upstreams-incomplete") != nil {
		t.Error("a kind the cluster doesn't serve can't reference the Service; the list is complete")
	}
	if len(tr.Upstreams) != 1 || tr.Upstreams[0].Resource.Name != "web" {
		t.Errorf("upstreams = %+v", tr.Upstreams)
	}
}

func TestServiceUpstreams_RouteReferencesCrossNamespace(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "team-a", apiLabels))
	f.pods = append(f.pods, mkPod("api-1", "team-a", apiLabels, true))
	r := httpRoute("route-x", "team-x", "gw", map[string]any{"name": "api", "namespace": "team-a", "port": int64(80)})
	setParentStatus(r, "gw", "team-x", "False", "NotAllowedByListeners")
	f.addDynamic(r)
	tr := build(t, f, "Service", "team-a", "api")
	if len(tr.Upstreams) != 1 || tr.Upstreams[0].Resource.Namespace != "team-x" {
		t.Fatalf("upstreams = %+v", tr.Upstreams)
	}
	f0 := findingByCode(tr.Findings, "gwroute:not-accepted")
	if f0 == nil || f0.Hop != "upstreams[0]" || f0.Severity != SeverityCritical || !strings.Contains(f0.Cause, "NotAllowedByListeners") {
		t.Fatalf("not-accepted finding = %+v", f0)
	}
	// The only entry is broken, the Service itself is fine.
	if tr.Verdict != VerdictBroken || tr.BrokenAt != -1 {
		t.Errorf("verdict=%q brokenAt=%d, want broken/-1", tr.Verdict, tr.BrokenAt)
	}
	if !strings.HasPrefix(tr.Headline, "Broken: every entry path") {
		t.Errorf("headline = %q", tr.Headline)
	}
}

func TestServiceUpstreams_Capped(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "prod", apiLabels))
	f.pods = append(f.pods, mkPod("api-1", "prod", apiLabels, true))
	for i := 0; i < maxUpstreams+3; i++ {
		f.ingresses = append(f.ingresses, ingressTo("ing-"+string(rune('a'+i)), "prod", "api"))
	}
	tr := build(t, f, "Service", "prod", "api")
	if len(tr.Upstreams) != maxUpstreams || !tr.Truncated || findingByCode(tr.Findings, "trace:upstreams-truncated") == nil {
		t.Errorf("upstreams=%d truncated=%v", len(tr.Upstreams), tr.Truncated)
	}
}

// --- Ingress entry ---

func TestBuild_IngressMissingBackendIsPartialDegrade(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("echo", "prod", apiLabels))
	f.pods = append(f.pods, mkPod("echo-1", "prod", apiLabels, true))
	f.ingresses = append(f.ingresses, ingressTo("web", "prod", "echo", "ghost"))
	tr := build(t, f, "Ingress", "prod", "web")
	mr := findingByCode(tr.Findings, "missing_ref:backend-service")
	if mr == nil || mr.Hop != "downstream[0]" || !strings.Contains(mr.Message, "prod/ghost") {
		t.Fatalf("missing ref = %+v", mr)
	}
	if tr.Verdict != VerdictDegraded || tr.BrokenAt != 0 {
		t.Errorf("verdict=%q brokenAt=%d, want degraded/0", tr.Verdict, tr.BrokenAt)
	}
	if !strings.HasPrefix(tr.Headline, "Degraded at: Ingress prod/web - ") {
		t.Errorf("headline = %q", tr.Headline)
	}
}

func TestBuild_IngressMissingBackendPort(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("echo", "prod", apiLabels, corev1.ServicePort{Port: 8080}))
	f.pods = append(f.pods, mkPod("echo-1", "prod", apiLabels, true))
	f.ingresses = append(f.ingresses, ingressTo("web", "prod", "echo")) // targets port 80
	tr := build(t, f, "Ingress", "prod", "web")
	if findingByCode(tr.Findings, "missing_ref:backend-port") == nil || tr.Verdict != VerdictBroken {
		t.Errorf("verdict=%q findings=%+v", tr.Verdict, tr.Findings)
	}
}

func TestBuild_IngressBrokenBackendNamesTheBackend(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("a", "prod", map[string]string{"app": "a"}), mkService("b", "prod", map[string]string{"app": "b"}))
	f.pods = append(f.pods, mkPod("a-1", "prod", map[string]string{"app": "a"}, true), crashingPod("b-1", "prod", map[string]string{"app": "b"}))
	f.ingresses = append(f.ingresses, ingressTo("web", "prod", "a", "b"))
	tr := build(t, f, "Ingress", "prod", "web")
	if tr.Verdict != VerdictDegraded {
		t.Fatalf("verdict = %q, want degraded", tr.Verdict)
	}
	if tr.Downstream[tr.BrokenAt].Resource.Name != "b" {
		t.Errorf("brokenAt = %d (%+v), want backend b", tr.BrokenAt, tr.Downstream[tr.BrokenAt].Resource)
	}
	if !strings.HasPrefix(tr.Headline, "Degraded at: Service prod/b - No ready endpoints") {
		t.Errorf("headline = %q", tr.Headline)
	}
}

func TestBuild_IngressBackendsTruncated(t *testing.T) {
	f := newFake()
	var names []string
	for i := 0; i < maxBackendsTraced+2; i++ {
		n := "s" + string(rune('a'+i))
		names = append(names, n)
		f.services = append(f.services, mkService(n, "prod", nil))
	}
	f.ingresses = append(f.ingresses, ingressTo("web", "prod", names...))
	tr := build(t, f, "Ingress", "prod", "web")
	if !tr.Truncated || findingByCode(tr.Findings, "ingress:backends-truncated") == nil {
		t.Errorf("truncated=%v", tr.Truncated)
	}
}

// --- Route entry ---

func TestBuild_RouteNotAcceptedIsBroken(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "prod", apiLabels))
	f.pods = append(f.pods, mkPod("api-1", "prod", apiLabels, true))
	gw := gatewayObject("gw", "prod")
	r := httpRoute("r", "prod", "gw", backend("api", 80))
	setParentStatus(r, "gw", "prod", "False", "NoMatchingListenerHostname")
	f.addDynamic(gw, r)
	tr := build(t, f, "HTTPRoute", "prod", "r")
	if tr.Verdict != VerdictBroken || tr.BrokenAt != 0 {
		t.Fatalf("verdict=%q brokenAt=%d, want broken/0", tr.Verdict, tr.BrokenAt)
	}
	if !strings.HasPrefix(tr.Headline, "Breaks at: HTTPRoute prod/r - Gateway prod/gw has not accepted") {
		t.Errorf("headline = %q", tr.Headline)
	}
	if len(tr.Upstreams) != 1 || tr.Upstreams[0].Config == nil || len(tr.Upstreams[0].Config.Listeners) != 1 {
		t.Errorf("parent gateway hop = %+v", tr.Upstreams)
	}
}

func TestBuild_RouteMissingParentGateway(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "prod", apiLabels))
	f.pods = append(f.pods, mkPod("api-1", "prod", apiLabels, true))
	f.addDynamic(httpRoute("r", "prod", "nogw", backend("api", 80)))
	tr := build(t, f, "HTTPRoute", "prod", "r")
	mp := findingByCode(tr.Findings, "gateway:missing-parent")
	if mp == nil || mp.Hop != "upstreams[0]" {
		t.Fatalf("missing parent = %+v", mp)
	}
	if tr.Verdict != VerdictBroken {
		t.Errorf("verdict = %q, want broken (the only parent is missing)", tr.Verdict)
	}
}

func TestBuild_RouteUnreadableParentIsUnknown(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("api", "prod", apiLabels))
	f.pods = append(f.pods, mkPod("api-1", "prod", apiLabels, true))
	f.addDynamic(httpRoute("r", "prod", "gw", backend("api", 80)))
	w := walker{p: f}
	f.unreadable["Gateway"] = true
	route := f.dynamic["HTTPRoute"][0]
	ups := w.routeParentGateways(route)
	if len(ups) != 1 || ups[0].Meta["endpointSource"] != "unknown" || len(ups[0].Findings) != 0 {
		t.Errorf("unreadable parent = %+v, want an unknown hop, not missing-parent", ups)
	}
}

func TestBuild_RouteDrainedBackend(t *testing.T) {
	f := newFake()
	f.services = append(f.services, mkService("stable", "prod", apiLabels), mkService("canary", "prod", map[string]string{"app": "canary"}))
	f.pods = append(f.pods, mkPod("s-1", "prod", apiLabels, true))
	f.addDynamic(gatewayObject("gw", "prod"), httpRoute("r", "prod", "gw",
		map[string]any{"name": "stable", "port": int64(80), "weight": int64(100)},
		map[string]any{"name": "canary", "port": int64(80), "weight": int64(0)},
	))
	tr := build(t, f, "HTTPRoute", "prod", "r")
	if tr.Verdict != VerdictHealthy {
		t.Fatalf("verdict = %q (%s), want healthy - canary is drained", tr.Verdict, tr.Headline)
	}
	if findingByCode(tr.Findings, "route:drained-weight-zero") == nil {
		t.Error("expected drained finding")
	}
}

func TestBuild_RouteKindNotServed(t *testing.T) {
	f := newFake()
	f.absent["GRPCRoute"] = true
	tr := build(t, f, "grpcroutes", "prod", "r")
	if tr.Verdict != VerdictUnknown || !strings.Contains(tr.Reason, "not served") {
		t.Errorf("verdict=%q reason=%q", tr.Verdict, tr.Reason)
	}
}

func TestRouteBackendDrained(t *testing.T) {
	r := httpRoute("r", "prod", "gw",
		map[string]any{"name": "a", "weight": int64(0)},
		map[string]any{"name": "b"},
	)
	if !routeBackendDrained(r, "prod", "a") {
		t.Error("a is weight 0 beside a live sibling: drained")
	}
	if routeBackendDrained(r, "prod", "b") {
		t.Error("b has no weight: carries traffic")
	}
	solo := httpRoute("r", "prod", "gw", map[string]any{"name": "a", "weight": int64(0)})
	if routeBackendDrained(solo, "prod", "a") {
		t.Error("weight 0 with no live sibling is not a drain")
	}
}

// --- Gateway entry ---

func attachedL4Route(kind, name, namespace, gwName string) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "gateway.networking.k8s.io/v1alpha2",
		"kind":       kind,
		"metadata":   map[string]any{"name": name, "namespace": namespace},
		"spec":       map[string]any{"parentRefs": []any{map[string]any{"name": gwName}}},
	}}
}

func TestBuild_GatewayListsL4RoutesStaticOnly(t *testing.T) {
	f := newFake()
	f.addDynamic(gatewayObject("gw", "ns"), httpRoute("web", "ns", "gw"), attachedL4Route("TCPRoute", "db-route", "ns", "gw"))
	tr := build(t, f, "Gateway", "ns", "gw")
	var l4, http int = -1, -1
	for i, h := range tr.Downstream {
		switch h.Resource.Kind {
		case "TCPRoute":
			l4 = i
		case "HTTPRoute":
			http = i
		}
	}
	if l4 < 0 || http < 0 {
		t.Fatalf("downstream = %+v, want both routes", tr.Downstream)
	}
	f0 := findingByCode(tr.Downstream[l4].Findings, "gateway:l4-route-not-traced")
	if f0 == nil || f0.Severity != SeverityInfo {
		t.Errorf("l4 note = %+v", f0)
	}
	if findingByCode(tr.Downstream[http].Findings, "gateway:l4-route-not-traced") != nil {
		t.Error("HTTPRoute must not carry the l4 note")
	}
	if tr.Verdict != VerdictHealthy {
		t.Errorf("verdict = %q", tr.Verdict)
	}
}

func TestBuild_GatewayPartialRouteRejectionIsDegraded(t *testing.T) {
	f := newFake()
	ok := httpRoute("ok", "ns", "gw")
	bad := httpRoute("bad", "ns", "gw")
	setParentStatus(bad, "gw", "ns", "False", "NotAllowedByListeners")
	setParentStatus(bad, "other", "ns", "True", "Accepted") // another parent's status is not this Gateway's
	f.addDynamic(gatewayObject("gw", "ns"), ok, bad)
	tr := build(t, f, "Gateway", "ns", "gw")
	if tr.Verdict != VerdictDegraded {
		t.Fatalf("verdict = %q, want degraded", tr.Verdict)
	}
	if tr.Downstream[tr.BrokenAt].Resource.Name != "bad" {
		t.Errorf("brokenAt = %+v", tr.Downstream[tr.BrokenAt].Resource)
	}
	if f0 := findingByCode(tr.Findings, "gwroute:not-accepted"); f0 == nil || f0.Severity != SeverityCritical {
		t.Errorf("finding = %+v", f0)
	}
}

func TestBuild_GatewayNotProgrammedIsBroken(t *testing.T) {
	f := newFake()
	gw := gatewayObject("gw", "ns")
	_ = unstructured.SetNestedSlice(gw.Object, []any{map[string]any{"type": "Programmed", "status": "False", "reason": "AddressNotAssigned"}}, "status", "conditions")
	f.addDynamic(gw, httpRoute("web", "ns", "gw"))
	tr := build(t, f, "Gateway", "ns", "gw")
	if tr.Verdict != VerdictBroken || tr.BrokenAt != 0 || findingByCode(tr.Findings, "gateway:not-programmed") == nil {
		t.Errorf("verdict=%q brokenAt=%d findings=%+v", tr.Verdict, tr.BrokenAt, tr.Findings)
	}
}

func TestBuild_GatewayRoutesCapped(t *testing.T) {
	f := newFake()
	f.addDynamic(gatewayObject("gw", "ns"))
	for i := 0; i < gatewayRouteCap+2; i++ {
		f.addDynamic(httpRoute("r"+string(rune('a'+i)), "ns", "gw"))
	}
	tr := build(t, f, "Gateway", "ns", "gw")
	if !tr.Truncated || findingByCode(tr.Findings, "gateway:routes-truncated") == nil {
		t.Errorf("truncated=%v", tr.Truncated)
	}
	if v := tr.Verdict; v != VerdictHealthy {
		t.Errorf("verdict = %q", v)
	}
}

func TestAttachedRoutes_UnreadableIndexNotComplete(t *testing.T) {
	f := newFake()
	f.unreadable["HTTPRoute"] = true
	w := walker{p: f}
	refs, total, complete := w.attachedRoutes(gatewayObject("gw", "ns"))
	if len(refs) != 0 || total != 0 || complete {
		t.Errorf("refs=%v total=%d complete=%v, want an incomplete empty inventory", refs, total, complete)
	}
}

func TestBuild_GatewayAPINotServedIsUnknown(t *testing.T) {
	f := newFake()
	f.absent["Gateway"] = true
	tr := build(t, f, "Gateway", "ns", "gw")
	if tr.Verdict != VerdictUnknown {
		t.Errorf("verdict = %q, want unknown", tr.Verdict)
	}
}

func TestIsEntryKind(t *testing.T) {
	for _, k := range []string{"Service", "services", "ingress", "HTTPRoute", "grpcroutes", "gateway"} {
		if !IsEntryKind(k) {
			t.Errorf("IsEntryKind(%q) = false", k)
		}
	}
	for _, k := range []string{"Pod", "TCPRoute", ""} {
		if IsEntryKind(k) {
			t.Errorf("IsEntryKind(%q) = true", k)
		}
	}
}
