package pathtrace

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

type evalCall struct {
	pods  []string
	port  int32
	proto corev1.Protocol
	ext   bool
}

// scriptedEvaluator answers by pod port and records every call.
func scriptedEvaluator(byPort map[int32]string, calls *[]evalCall) PolicyEvaluator {
	return func(srcExternal bool, dst []*corev1.Pod, port int32, proto corev1.Protocol, _ []*networkingv1.NetworkPolicy) (string, []string) {
		names := make([]string, 0, len(dst))
		for _, p := range dst {
			names = append(names, p.Name)
		}
		*calls = append(*calls, evalCall{pods: names, port: port, proto: proto, ext: srcExternal})
		v := byPort[port]
		if v == "" {
			v = evalAllowed
		}
		var deciding []string
		if v != evalAllowed {
			deciding = []string{"deny-all"}
		}
		return v, deciding
	}
}

func npFixture(ns string) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{ObjectMeta: metav1.ObjectMeta{Name: "deny-all", Namespace: ns}}
}

func policyWalker(verdicts map[int32]string, calls *[]evalCall) (*fakeProvider, Options) {
	f := newFake()
	f.policies = append(f.policies, npFixture("prod"))
	return f, Options{PolicyEvaluator: scriptedEvaluator(verdicts, calls)}
}

func TestPolicyFinding_WouldDeny(t *testing.T) {
	var calls []evalCall
	f, opts := policyWalker(map[int32]string{8080: evalDenied}, &calls)
	f.services = append(f.services, mkService("api", "prod", apiLabels))
	f.pods = append(f.pods, mkPod("api-1", "prod", apiLabels, true))
	tr := Build(t.Context(), f, "Service", "prod", "api", opts)
	wd := findingByCode(tr.Findings, codePolicyWouldDeny)
	if wd == nil || wd.Severity != SeverityWarning || wd.Hop != "downstream[1]" {
		t.Fatalf("would-deny = %+v", wd)
	}
	if wd.Command != "kubectl describe networkpolicy deny-all -n prod" || !strings.Contains(wd.Message, ":80") {
		t.Errorf("would-deny = %+v", wd)
	}
	// A prediction degrades, never breaks.
	if tr.Verdict != VerdictDegraded {
		t.Errorf("verdict = %q, want degraded", tr.Verdict)
	}
	if len(calls) != 1 || calls[0].port != 8080 || calls[0].proto != corev1.ProtocolTCP || calls[0].ext {
		t.Errorf("evaluator calls = %+v, want one call on the pod port 8080/TCP with an unspecified caller", calls)
	}
	if tr.Downstream[1].Meta["policyVerdict"] != "would-deny" {
		t.Errorf("meta = %+v", tr.Downstream[1].Meta)
	}
}

func TestPolicyFinding_AllowedIsSilent(t *testing.T) {
	var calls []evalCall
	f, opts := policyWalker(nil, &calls)
	f.services = append(f.services, mkService("api", "prod", apiLabels))
	f.pods = append(f.pods, mkPod("api-1", "prod", apiLabels, true))
	tr := Build(t.Context(), f, "Service", "prod", "api", opts)
	if findingByCode(tr.Findings, codePolicyWouldDeny) != nil || findingByCode(tr.Findings, codePolicyAdvisory) != nil || tr.Verdict != VerdictHealthy {
		t.Errorf("verdict=%q findings=%+v", tr.Verdict, tr.Findings)
	}
}

func TestPolicyFinding_NoEvaluatorOrNoPolicyIsSilent(t *testing.T) {
	svc := mkService("api", "prod", apiLabels)
	pods := []*corev1.Pod{mkPod("api-1", "prod", apiLabels, true)}
	f := newFake()
	f.policies = append(f.policies, npFixture("prod"))
	if _, _, ok := policyFinding(f, nil, svc, pods); ok {
		t.Error("no evaluator must be silent")
	}
	var calls []evalCall
	eval := scriptedEvaluator(map[int32]string{8080: evalDenied}, &calls)
	if _, _, ok := policyFinding(newFake(), eval, svc, pods); ok || len(calls) != 0 {
		t.Error("no policy in the namespace must be silent and skip the evaluator")
	}
	unreadable := newFake()
	unreadable.unreadable["NetworkPolicy"] = true
	if _, _, ok := policyFinding(unreadable, eval, svc, pods); ok {
		t.Error("unreadable policies must be silent")
	}
}

func TestPolicyFinding_CallerDependentIsAdvisory(t *testing.T) {
	var calls []evalCall
	f, opts := policyWalker(map[int32]string{8080: "unknown"}, &calls)
	svc := mkService("api", "prod", apiLabels)
	fd, _, ok := policyFinding(f, opts.PolicyEvaluator, svc, []*corev1.Pod{mkPod("api-1", "prod", apiLabels, true)})
	if !ok || fd.Code != codePolicyAdvisory || fd.Severity != SeverityInfo {
		t.Fatalf("finding = %+v", fd)
	}
}

func TestPolicyFinding_MixedPodsIsAdvisory(t *testing.T) {
	var calls []evalCall
	f, opts := policyWalker(map[int32]string{8080: evalDenied, 9090: evalAllowed}, &calls)
	svc := mkService("api", "prod", apiLabels, corev1.ServicePort{Port: 80, TargetPort: intstr.FromString("http")})
	a := mkPod("a", "prod", apiLabels, true, corev1.ContainerPort{Name: "http", ContainerPort: 8080})
	b := mkPod("b", "prod", apiLabels, true, corev1.ContainerPort{Name: "http", ContainerPort: 9090})
	fd, _, ok := policyFinding(f, opts.PolicyEvaluator, svc, []*corev1.Pod{a, b})
	if !ok || fd.Code != codePolicyAdvisory || !strings.Contains(fd.Message, "some of these pods") {
		t.Fatalf("finding = %+v", fd)
	}
	if len(calls) != 2 {
		t.Errorf("named targetPort resolving to two pod ports should ask twice, got %+v", calls)
	}
}

func TestPolicyFinding_HostNetworkAndUnresolvedAreAdvisory(t *testing.T) {
	var calls []evalCall
	f, opts := policyWalker(map[int32]string{8080: evalDenied}, &calls)
	svc := mkService("api", "prod", apiLabels)
	hn := mkPod("hn", "prod", apiLabels, true)
	hn.Spec.HostNetwork = true
	fd, _, ok := policyFinding(f, opts.PolicyEvaluator, svc, []*corev1.Pod{hn})
	if !ok || fd.Code != codePolicyAdvisory || !strings.Contains(fd.Message, "host network") {
		t.Errorf("hostNetwork finding = %+v", fd)
	}
	named := mkService("api", "prod", apiLabels, corev1.ServicePort{Port: 80, TargetPort: intstr.FromString("web")})
	fd, _, ok = policyFinding(f, opts.PolicyEvaluator, named, []*corev1.Pod{mkPod("p", "prod", apiLabels, true)})
	if !ok || fd.Code != codePolicyAdvisory || !strings.Contains(fd.Message, "named targetPort") {
		t.Errorf("unresolved finding = %+v", fd)
	}
}

func TestPolicyFinding_OnlyReadyPodsEvaluated(t *testing.T) {
	var calls []evalCall
	f, opts := policyWalker(map[int32]string{8080: evalDenied}, &calls)
	svc := mkService("api", "prod", apiLabels)
	_, _, ok := policyFinding(f, opts.PolicyEvaluator, svc, []*corev1.Pod{mkPod("nr", "prod", apiLabels, false)})
	if ok || len(calls) != 0 {
		t.Errorf("a not-ready pod is outside the data path; got ok=%v calls=%+v", ok, calls)
	}
	svc.Spec.PublishNotReadyAddresses = true
	if _, _, ok := policyFinding(f, opts.PolicyEvaluator, svc, []*corev1.Pod{mkPod("nr", "prod", apiLabels, false)}); !ok {
		t.Error("publishNotReadyAddresses routes to not-ready pods, so they are evaluated")
	}
}

// An upstream route that uses only one Service port scopes the check to it:
// a deny on an unused port must not condemn the path.
func TestPolicyFinding_ScopedToBackendPorts(t *testing.T) {
	var calls []evalCall
	f, opts := policyWalker(map[int32]string{9090: evalDenied}, &calls)
	svc := mkService("api", "prod", apiLabels,
		corev1.ServicePort{Name: "http", Port: 80, TargetPort: intstr.FromInt32(8080)},
		corev1.ServicePort{Name: "admin", Port: 90, TargetPort: intstr.FromInt32(9090)})
	pods := []*corev1.Pod{mkPod("p", "prod", apiLabels, true)}
	if _, _, ok := policyFinding(f, opts.PolicyEvaluator, svc, pods, "80"); ok {
		t.Error("deny on :90 must not surface for a route using :80")
	}
	if _, _, ok := policyFinding(f, opts.PolicyEvaluator, svc, pods, "admin"); !ok {
		t.Error("a route using the admin port must see its deny")
	}
	if _, _, ok := policyFinding(f, opts.PolicyEvaluator, svc, pods); !ok {
		t.Error("a bare Service entry evaluates every port")
	}
}

func TestFilterPortMapsByRef(t *testing.T) {
	all := []PortMap{{Name: "http", Port: 80}, {Name: "grpc", Port: 9000}}
	if got := filterPortMapsByRef(all, nil); len(got) != 2 {
		t.Errorf("no refs: %+v", got)
	}
	if got := filterPortMapsByRef(all, []string{"9000"}); len(got) != 1 || got[0].Name != "grpc" {
		t.Errorf("by number: %+v", got)
	}
	if got := filterPortMapsByRef(all, []string{"nope"}); len(got) != 0 {
		t.Errorf("unmatched refs must yield none: %+v", got)
	}
}

func TestBuild_IngressBackendPolicyScopedToIngressPort(t *testing.T) {
	var calls []evalCall
	f, opts := policyWalker(map[int32]string{8080: evalDenied}, &calls)
	f.services = append(f.services, mkService("api", "prod", apiLabels))
	f.pods = append(f.pods, mkPod("api-1", "prod", apiLabels, true))
	f.ingresses = append(f.ingresses, ingressTo("web", "prod", "api"))
	tr := Build(t.Context(), f, "Ingress", "prod", "web", opts)
	wd := findingByCode(tr.Findings, codePolicyWouldDeny)
	if wd == nil || wd.Hop != "downstream[2]" {
		t.Errorf("would-deny on the backend Pods hop = %+v", wd)
	}
}
