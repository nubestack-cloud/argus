package clustersummary

import (
	"encoding/json"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func templateLabels(l map[string]string) corev1.PodTemplateSpec {
	return corev1.PodTemplateSpec{ObjectMeta: metav1.ObjectMeta{Labels: l}}
}

func testDeployment(ns, name, app string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       appsv1.DeploymentSpec{Template: templateLabels(map[string]string{"app": app})},
	}
}

func testPolicy(ns, name string, sel metav1.LabelSelector) *networkingv1.NetworkPolicy {
	return &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name},
		Spec:       networkingv1.NetworkPolicySpec{PodSelector: sel},
	}
}

func cniPolicy(apiVersion, kind, ns, name string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetAPIVersion(apiVersion)
	u.SetKind(kind)
	u.SetNamespace(ns)
	u.SetName(name)
	return u
}

func TestNetworkPolicyCoverageMatchesSelectorWithinNamespace(t *testing.T) {
	in := CoverageInput{
		Policies: []*networkingv1.NetworkPolicy{
			testPolicy("ns-a", "frontend", metav1.LabelSelector{MatchLabels: map[string]string{"app": "frontend"}}),
			// Same labels, wrong namespace: must not cover ns-b's backend.
			testPolicy("ns-a", "backend-elsewhere", metav1.LabelSelector{MatchLabels: map[string]string{"app": "backend"}}),
		},
		Deployments: []*appsv1.Deployment{
			testDeployment("ns-a", "frontend", "frontend"),
			testDeployment("ns-b", "backend", "backend"),
		},
		StatefulSets: []*appsv1.StatefulSet{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns-a", Name: "db"},
			Spec:       appsv1.StatefulSetSpec{Template: templateLabels(map[string]string{"app": "db"})},
		}},
	}
	got := ComputeNetworkPolicyCoverage(in)
	if got.Policies != 2 || got.CoveredWorkloads != 1 || got.TotalWorkloads != 3 {
		t.Fatalf("coverage = %+v, want policies=2 covered=1 total=3", got)
	}
}

func TestNetworkPolicyCoverageEmptySelectorCoversNamespace(t *testing.T) {
	got := ComputeNetworkPolicyCoverage(CoverageInput{
		Policies: []*networkingv1.NetworkPolicy{testPolicy("ns-a", "default-deny", metav1.LabelSelector{})},
		Deployments: []*appsv1.Deployment{
			testDeployment("ns-a", "one", "one"),
			testDeployment("ns-a", "two", "two"),
			testDeployment("ns-b", "three", "three"),
		},
		DaemonSets: []*appsv1.DaemonSet{{
			ObjectMeta: metav1.ObjectMeta{Namespace: "ns-a", Name: "agent"},
			Spec:       appsv1.DaemonSetSpec{Template: templateLabels(nil)},
		}},
	})
	if got.CoveredWorkloads != 3 || got.TotalWorkloads != 4 {
		t.Fatalf("coverage = %+v, want covered=3 total=4", got)
	}
}

func TestNetworkPolicyCoverageCountsAWorkloadOnce(t *testing.T) {
	sel := metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}}
	got := ComputeNetworkPolicyCoverage(CoverageInput{
		Policies:    []*networkingv1.NetworkPolicy{testPolicy("ns", "a", sel), testPolicy("ns", "b", sel), testPolicy("ns", "c", metav1.LabelSelector{})},
		Deployments: []*appsv1.Deployment{testDeployment("ns", "web", "web")},
	})
	if got.CoveredWorkloads != 1 || got.TotalWorkloads != 1 {
		t.Fatalf("coverage = %+v, want covered=1 total=1", got)
	}
}

func TestNetworkPolicyCoverageMatchExpressions(t *testing.T) {
	got := ComputeNetworkPolicyCoverage(CoverageInput{
		Policies: []*networkingv1.NetworkPolicy{testPolicy("ns", "tiers", metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: metav1.LabelSelectorOpIn, Values: []string{"api", "web"}}},
		})},
		Deployments: []*appsv1.Deployment{
			testDeployment("ns", "api", "api"),
			testDeployment("ns", "worker", "worker"),
		},
	})
	if got.CoveredWorkloads != 1 {
		t.Fatalf("coverage = %+v, want covered=1", got)
	}
}

func TestNetworkPolicyCoverageInvalidSelectorCoversNothing(t *testing.T) {
	got := ComputeNetworkPolicyCoverage(CoverageInput{
		Policies: []*networkingv1.NetworkPolicy{testPolicy("ns", "broken", metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "app", Operator: "Bogus"}},
		})},
		Deployments: []*appsv1.Deployment{testDeployment("ns", "api", "api")},
	})
	if got.Policies != 1 || got.InvalidPolicies != 1 || got.CoveredWorkloads != 0 {
		t.Fatalf("coverage = %+v, want policies=1 invalid=1 covered=0", got)
	}
}

func TestNetworkPolicyCoverageListsCNIPoliciesAsNotEvaluated(t *testing.T) {
	got := ComputeNetworkPolicyCoverage(CoverageInput{
		Deployments: []*appsv1.Deployment{testDeployment("ns", "api", "api")},
		CNIPolicies: []*unstructured.Unstructured{
			cniPolicy("cilium.io/v2", "CiliumNetworkPolicy", "ns", "a"),
			cniPolicy("cilium.io/v2", "CiliumNetworkPolicy", "ns", "b"),
			cniPolicy("projectcalico.org/v3", "GlobalNetworkPolicy", "", "g"),
			cniPolicy("projectcalico.org/v3", "StagedNetworkPolicy", "ns", "s"),
		},
	})
	// A CNI policy that would select the workload must not raise the figure:
	// its selector language is not evaluated here.
	if got.Policies != 0 || got.CoveredWorkloads != 0 || got.TotalWorkloads != 1 {
		t.Fatalf("coverage = %+v, want CNI policies kept out of the figure", got)
	}
	want := []NotEvaluatedPolicies{
		{Group: "cilium.io", Kind: "CiliumNetworkPolicy", Count: 2},
		{Group: "projectcalico.org", Kind: "GlobalNetworkPolicy", Count: 1},
		{Group: "projectcalico.org", Kind: "StagedNetworkPolicy", Count: 1},
	}
	if len(got.NotEvaluated) != len(want) {
		t.Fatalf("NotEvaluated = %+v, want %+v", got.NotEvaluated, want)
	}
	for i := range want {
		if got.NotEvaluated[i] != want[i] {
			t.Fatalf("NotEvaluated[%d] = %+v, want %+v", i, got.NotEvaluated[i], want[i])
		}
	}
}

func TestNetworkPolicyCoverageSerializesZeroes(t *testing.T) {
	// A cluster with workloads and no policies has measured zero coverage;
	// the zero must be present, not omitted, so a reader can tell it from a
	// summary that was never computed.
	encoded, err := json.Marshal(ComputeNetworkPolicyCoverage(CoverageInput{
		Deployments: []*appsv1.Deployment{testDeployment("ns", "api", "api")},
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"policies":0`, `"coveredWorkloads":0`, `"totalWorkloads":1`} {
		if !strings.Contains(string(encoded), field) {
			t.Fatalf("coverage JSON = %s, missing %s", encoded, field)
		}
	}
}
