package posture

import (
	"maps"
	"slices"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
)

func TestRunChecksWithNothing(t *testing.T) {
	if r := RunChecks(nil); r == nil || r.Summary.Categories == nil || len(r.Findings) != 0 {
		t.Fatalf("nil input: %+v", r)
	}
	r := RunChecks(&CheckInput{})
	if len(r.Findings) != 0 || len(r.CheckCounts) != 0 || len(r.Checks) != len(CheckRegistry) {
		t.Fatalf("empty input: %d findings, counts %v", len(r.Findings), r.CheckCounts)
	}
	want := []string{
		"serviceaccounts", "deployments", "statefulsets", "daemonsets", "jobs", "cronjobs", "limitranges",
		"horizontalpodautoscalers", "poddisruptionbudgets", "pods", "replicasets", "configmaps", "services",
		"ingresses", "persistentvolumeclaims", "persistentvolumes", "certificates",
	}
	if !slices.Equal(r.MissingInputs, want) {
		t.Errorf("missing\n got %v\nwant %v", r.MissingInputs, want)
	}
	for _, c := range categories {
		if _, ok := r.Summary.Categories[c]; !ok {
			t.Errorf("category %s absent from an empty summary", c)
		}
	}
}

func TestCatalogue(t *testing.T) {
	for id, m := range CheckRegistry {
		if m.ID != id || m.Title == "" || m.Description == "" || m.Remediation == "" || len(m.References) == 0 {
			t.Errorf("%s: incomplete entry %+v", id, m)
		}
		if !slices.Contains(categories, m.Category) {
			t.Errorf("%s: category %q", id, m.Category)
		}
		if m.DefaultSeverity != high && m.DefaultSeverity != medium {
			t.Errorf("%s: default severity %q", id, m.DefaultSeverity)
		}
	}
	for id, want := range map[string]string{"privileged": high, "stuckTerminating": high, "runAsRoot": medium, "orphanPVC": medium} {
		if got := CheckRegistry[id].DefaultSeverity; got != want {
			t.Errorf("%s: default %q, want %q", id, got, want)
		}
	}
	if got := CheckRegistry["readOnlyRootFs"].Frameworks; !slices.Equal(got, []string{FrameworkNSACISA}) {
		t.Errorf("readOnlyRootFs frameworks %v", got)
	}
	if got := CheckRegistry["singleReplica"].Frameworks; got != nil {
		t.Errorf("singleReplica frameworks %v", got)
	}
}

// messy is an input that trips most checks at once.
func messy() *CheckInput {
	bad := tidySpec("api")
	bad.HostPID = true
	bad.Containers[0].Image = "shop/api:latest"
	bad.Containers[0].LivenessProbe = nil
	in := listedEverything()
	in.Deployments = []*appsv1.Deployment{deployment("shop", "api", 3, bad), deployment("tools", "notebook", 1, bad)}
	in.Services = []*corev1.Service{{ObjectMeta: meta("shop", "api"), Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "api"}}}}
	in.ConfigMaps = []*corev1.ConfigMap{{ObjectMeta: meta("cattle-system", "rancher"), Data: map[string]string{"admin_password": "sha256:0"}}}
	return in
}

func TestEveryFindingIsCatalogued(t *testing.T) {
	r := RunChecks(messy())
	if len(r.Findings) < 8 {
		t.Fatalf("fixture trips too little: %v", failing(r))
	}
	for _, f := range r.Findings {
		m, ok := CheckRegistry[f.CheckID]
		if !ok || f.Category != m.Category {
			t.Errorf("%s: category %q, catalogue %+v", f.CheckID, f.Category, m)
		}
	}
	for id := range r.CheckCounts {
		if _, ok := CheckRegistry[id]; !ok {
			t.Errorf("counted an uncatalogued check %s", id)
		}
	}
}

func TestCountsAddUp(t *testing.T) {
	r := RunChecks(messy())
	failed := map[string]int{}
	for _, f := range r.Findings {
		failed[f.CheckID]++
	}
	passing, byCategory := 0, map[string]int{}
	for id, c := range r.CheckCounts {
		if c.Evaluated == 0 || c.Passed != c.Evaluated-failed[id] {
			t.Errorf("%s: %+v with %d failed", id, c, failed[id])
		}
		passing += c.Passed
		byCategory[CheckRegistry[id].Category] += c.Passed
	}
	for id := range failed {
		if _, ok := r.CheckCounts[id]; !ok {
			t.Errorf("%s failed without being counted", id)
		}
	}
	if r.Summary.Passing != passing || r.Summary.Warning+r.Summary.Danger != len(r.Findings) {
		t.Errorf("summary %+v, passing %d, findings %d", r.Summary, passing, len(r.Findings))
	}
	for c, n := range byCategory {
		if r.Summary.Categories[c].Passing != n {
			t.Errorf("%s passing %d, want %d", c, r.Summary.Categories[c].Passing, n)
		}
	}
}

func TestApplySettings(t *testing.T) {
	raw := RunChecks(messy())
	before := maps.Clone(raw.EvaluatedByNamespace["hostPID"])
	total := len(raw.Findings)

	got := ApplySettings(raw, []string{"tools", "cattle-*"}, []string{"livenessProbeMissing"})
	for _, f := range got.Findings {
		if f.Namespace == "tools" || f.Namespace == "cattle-system" || f.CheckID == "livenessProbeMissing" {
			t.Errorf("kept %s on %s/%s", f.CheckID, f.Namespace, f.Name)
		}
	}
	if _, ok := got.CheckCounts["livenessProbeMissing"]; ok {
		t.Error("a disabled check is still counted")
	}
	if c := got.CheckCounts["hostPID"]; c != (CheckCount{Evaluated: 1, Passed: 0}) {
		t.Errorf("hostPID counts %+v: the ignored namespace's subject must leave the denominator", c)
	}
	if _, ok := got.CheckCounts["secretInConfigMap"]; ok {
		t.Error("a check whose only subjects were ignored is still counted")
	}
	if len(raw.Findings) != total || !maps.Equal(raw.EvaluatedByNamespace["hostPID"], before) {
		t.Error("the input result was modified")
	}
	if got.Summary.Danger+got.Summary.Warning != len(got.Findings) || !slices.Equal(got.MissingInputs, raw.MissingInputs) {
		t.Errorf("recount: %+v", got.Summary)
	}

	if same := ApplySettings(raw, nil, nil); same != raw {
		t.Error("no settings should return the result untouched")
	}
	suffix := ApplySettings(raw, []string{"*-system"}, nil)
	if findingNames(suffix.Findings, "secretInConfigMap")["rancher"] {
		t.Error(`"*-system" should match cattle-system`)
	}
	if exact := ApplySettings(raw, []string{"shop"}, nil); len(findingNames(exact.Findings, "hostPID")) != 1 {
		t.Error("an exact name ignores only that namespace")
	}
}

func TestServicesAndIngresses(t *testing.T) {
	in := listedEverything()
	in.Pods = []*corev1.Pod{pod("shop", "api-1", map[string]string{"app": "api", "tier": "web"}, tidySpec("api"))}
	in.Services = []*corev1.Service{
		{ObjectMeta: meta("shop", "api"), Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "api"}}},
		{ObjectMeta: meta("shop", "search"), Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "search"}}},
		{ObjectMeta: meta("staging", "api"), Spec: corev1.ServiceSpec{Selector: map[string]string{"app": "api"}}},
		{ObjectMeta: meta("shop", "external"), Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName, ExternalName: "db.example.org", Selector: map[string]string{"x": "y"}}},
		{ObjectMeta: meta("shop", "manual")},
	}
	path := func(p, svc string) networkingv1.HTTPIngressPath {
		return networkingv1.HTTPIngressPath{Path: p, Backend: networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: svc}}}
	}
	rule := func(paths ...networkingv1.HTTPIngressPath) networkingv1.IngressRule {
		return networkingv1.IngressRule{IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: paths}}}
	}
	in.Ingresses = []*networkingv1.Ingress{
		{ObjectMeta: meta("shop", "web"), Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{rule(path("/", "api"), path("/search", "search"), path("/cart", "cart")), rule(path("/old", "legacy"))}}},
		{ObjectMeta: meta("shop", "fine"), Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{rule(path("/", "api"))}}},
		{ObjectMeta: meta("shop", "rules-only"), Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{Host: "x.example.org"}}}},
	}
	r := RunChecks(in)
	if got := findingNames(r.Findings, "serviceNoMatchingPods"); len(got) != 2 || !got["search"] || !got["api"] {
		t.Errorf("services flagged %v", got)
	}
	if f := findingFor(r, "serviceNoMatchingPods", "api"); f == nil || f.Namespace != "staging" {
		t.Errorf("selectors match within the namespace only: %+v", f)
	}
	if c := r.CheckCounts["serviceNoMatchingPods"]; c != (CheckCount{Evaluated: 3, Passed: 1}) {
		t.Errorf("service counts %+v", c)
	}
	f := findingFor(r, "ingressNoMatchingService", "web")
	if f == nil || !contains(f.Message, `"cart"`) || !contains(f.Message, `"legacy"`) || contains(f.Message, `"search"`) || f.Group != "networking.k8s.io" {
		t.Errorf("ingress finding %+v", f)
	}
	if c := r.CheckCounts["ingressNoMatchingService"]; c != (CheckCount{Evaluated: 2, Passed: 1}) {
		t.Errorf("ingress counts %+v", c)
	}

	in.Pods = nil
	if r := RunChecks(in); len(findingNames(r.Findings, "serviceNoMatchingPods")) != 0 {
		t.Error("without the pod list every Service would look empty")
	}
}
