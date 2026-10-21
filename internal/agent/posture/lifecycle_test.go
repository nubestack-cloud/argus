package posture

import (
	"slices"
	"strings"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	autoscalingv2 "k8s.io/api/autoscaling/v2"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	policyv1 "k8s.io/api/policy/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDeprecatedAPIs(t *testing.T) {
	served := []string{"apps/v1", "policy/v1beta1", "batch/v1beta1", "scheduling.k8s.io/v1alpha2", "flowcontrol.apiserver.k8s.io/v1beta3"}
	for _, tc := range []struct {
		version string
		flagged []string
	}{
		// 1.20: policy/v1beta1 and batch/v1beta1 are not deprecated until 1.21.
		{"1.20", nil},
		{"v1.21.9", []string{"batch/v1beta1", "policy/v1beta1"}},
		{"1.29", []string{"batch/v1beta1", "flowcontrol.apiserver.k8s.io/v1beta3", "policy/v1beta1"}},
		{"1.36", []string{"batch/v1beta1", "flowcontrol.apiserver.k8s.io/v1beta3", "policy/v1beta1", "scheduling.k8s.io/v1alpha2"}},
		// A version that cannot be read rules nothing out.
		{"next", []string{"batch/v1beta1", "flowcontrol.apiserver.k8s.io/v1beta3", "policy/v1beta1", "scheduling.k8s.io/v1alpha2"}},
	} {
		r := RunChecks(&CheckInput{ServedAPIs: served, ClusterVersion: tc.version})
		var got []string
		for name := range findingNames(r.Findings, "deprecatedAPIVersion") {
			got = append(got, name)
		}
		slices.Sort(got)
		if !slices.Equal(got, tc.flagged) {
			t.Errorf("%s: flagged %v, want %v", tc.version, got, tc.flagged)
		}
		if c := r.CheckCounts["deprecatedAPIVersion"]; c.Evaluated != len(served) || c.Passed != len(served)-len(tc.flagged) {
			t.Errorf("%s: counts %+v", tc.version, c)
		}
	}

	// A group/version with two deprecated kinds is one subject naming both.
	r := RunChecks(&CheckInput{ServedAPIs: []string{"policy/v1beta1"}, ClusterVersion: "1.24"})
	f := findingFor(r, "deprecatedAPIVersion", "policy/v1beta1")
	if f == nil || f.Kind != "APIVersion" || f.Namespace != "" || !strings.Contains(f.Message, "PodDisruptionBudget") || !strings.Contains(f.Message, "PodSecurityPolicy") ||
		!strings.Contains(f.Message, "removed in 1.25") {
		t.Errorf("merged finding %+v", f)
	}
	if len(r.Findings) != 1 || r.Summary.Passing != 0 {
		t.Errorf("one subject, one failure: %+v", r.Summary)
	}

	for _, in := range []*CheckInput{{ServedAPIs: served}, {ClusterVersion: "1.30"}} {
		if r := RunChecks(in); len(r.Findings) != 0 || r.CheckCounts["deprecatedAPIVersion"].Evaluated != 0 {
			t.Error("needs both the served APIs and the cluster version")
		}
	}
}

func TestDeprecationTable(t *testing.T) {
	for _, d := range deprecations {
		if d.groupVersion == "" || d.since == "" || d.gone == "" || d.use == "" {
			t.Errorf("incomplete entry %+v", d)
		}
	}
	if n := len(deprecations); n < 20 {
		t.Errorf("table has %d entries", n)
	}
}

func TestStuckTerminating(t *testing.T) {
	in := &CheckInput{
		Pods:                     []*corev1.Pod{pod("shop", "api-1", nil, tidySpec("api"))},
		Deployments:              []*appsv1.Deployment{deployment("shop", "api", 2, tidySpec("api"))},
		StatefulSets:             []*appsv1.StatefulSet{statefulSet("shop", "db", 2, tidySpec("pg"))},
		DaemonSets:               []*appsv1.DaemonSet{{ObjectMeta: meta("shop", "agent")}},
		Services:                 []*corev1.Service{{ObjectMeta: meta("shop", "api")}},
		Ingresses:                []*networkingv1.Ingress{{ObjectMeta: meta("shop", "web")}},
		HorizontalPodAutoscalers: []*autoscalingv2.HorizontalPodAutoscaler{{ObjectMeta: meta("shop", "api")}},
		PodDisruptionBudgets:     []*policyv1.PodDisruptionBudget{{ObjectMeta: meta("shop", "api")}},
		ConfigMaps:               []*corev1.ConfigMap{configMap("shop", "flags")},
		ServiceAccounts:          []*corev1.ServiceAccount{{ObjectMeta: meta("shop", "api")}},
		Jobs:                     []*batchv1.Job{{ObjectMeta: meta("shop", "backfill")}},
	}
	deletedAgo(&in.Pods[0].ObjectMeta, time.Minute)                                       // still normal
	deletedAgo(&in.Deployments[0].ObjectMeta, 8*time.Minute, "example.io/cleanup")        // warning
	deletedAgo(&in.StatefulSets[0].ObjectMeta, 2*time.Hour, "a.example/x", "b.example/y") // danger
	deletedAgo(&in.Ingresses[0].ObjectMeta, 40*time.Minute)                               // danger, no finalizers
	deletedAgo(&in.ServiceAccounts[0].ObjectMeta, 6*time.Minute)                          // warning
	deletedAgo(&in.Jobs[0].ObjectMeta, 3*time.Hour)                                       // Jobs are not judged
	r := RunChecks(in)

	got := map[string]string{}
	for _, f := range r.Findings {
		if f.CheckID == "stuckTerminating" {
			got[f.Kind] = f.Severity + ": " + f.Message
		}
	}
	want := map[string]string{
		"Deployment":     "warning: deleted 8m ago and still present; waiting on finalizers example.io/cleanup",
		"StatefulSet":    "danger: deleted 2h ago and still present; waiting on finalizers a.example/x, b.example/y",
		"Ingress":        "danger: deleted 40m ago and still present",
		"ServiceAccount": "warning: deleted 6m ago and still present",
	}
	if len(got) != len(want) {
		t.Fatalf("flagged %v", got)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: %q, want %q", k, got[k], w)
		}
	}
	if c := r.CheckCounts["stuckTerminating"]; c != (CheckCount{Evaluated: 10, Passed: 6}) {
		t.Errorf("counts %+v", c)
	}
}

func TestGitOpsCoverage(t *testing.T) {
	marked := func(kind string, labels, annotations map[string]string) metav1.ObjectMeta {
		return metav1.ObjectMeta{Namespace: "shop", Name: kind, Labels: labels, Annotations: annotations}
	}
	flux := map[string]string{"kustomize.toolkit.fluxcd.io/name": "apps", "kustomize.toolkit.fluxcd.io/namespace": "flux-system"}
	helm := map[string]string{"meta.helm.sh/release-name": "redis"}

	ownedSet := statefulSet("shop", "child", 1, tidySpec("x"))
	ownedSet.OwnerReferences = []metav1.OwnerReference{{Kind: "Cluster", Name: "pg", Controller: ptr(true)}}
	in := &CheckInput{
		GitOpsToolsPresent: true,
		ArgoAppNames:       map[string]struct{}{"storefront": {}},
		Deployments: []*appsv1.Deployment{
			{ObjectMeta: marked("by-flux", flux, nil)},
			{ObjectMeta: marked("by-hand", nil, nil)},
			{ObjectMeta: marked("by-helm", map[string]string{"app.kubernetes.io/instance": "redis"}, helm)},
			{ObjectMeta: marked("by-argo-chart", map[string]string{"app.kubernetes.io/instance": "storefront"}, helm)},
		},
		StatefulSets: []*appsv1.StatefulSet{ownedSet},
		DaemonSets:   []*appsv1.DaemonSet{{ObjectMeta: marked("argo-labelled", map[string]string{"app.kubernetes.io/instance": "storefront"}, nil)}},
		CronJobs:     []*batchv1.CronJob{{ObjectMeta: marked("nightly", nil, nil)}},
	}
	r := RunChecks(in)
	var got []string
	for _, f := range failing(r) {
		if strings.HasPrefix(f, "gitops-") {
			got = append(got, f)
		}
	}
	want := []string{
		"gitops-helm-only-workload@Deployment/shop/by-helm",
		"gitops-unmanaged-workload@CronJob/shop/nightly",
		"gitops-unmanaged-workload@Deployment/shop/by-hand",
	}
	if !slices.Equal(got, want) {
		t.Errorf("flagged\n got %v\nwant %v", got, want)
	}
	// Six top-level workloads; each counts once under both checks.
	for _, id := range []string{checkGitOpsUnmanaged, checkGitOpsHelmOnly} {
		if c := r.CheckCounts[id]; c.Evaluated != 6 {
			t.Errorf("%s counts %+v", id, c)
		}
	}

	in.GitOpsToolsPresent = false
	r = RunChecks(in)
	if _, ran := r.CheckCounts[checkGitOpsUnmanaged]; ran || slices.ContainsFunc(r.MissingInputs, func(s string) bool { return strings.Contains(s, "gitops") }) {
		t.Error("without GitOps in use the checks do not apply, and nothing is missing")
	}
}
