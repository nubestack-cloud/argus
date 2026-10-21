package upgradeready

import (
	"slices"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

// outcome writes a check as "status" followed by its findings as sorted
// "level:Kind/name" words (level b, w or r; "-" when the finding names no
// object).
func outcome(c Check) string {
	var fs []string
	for _, f := range c.Findings {
		at := "-"
		if f.Resource != nil {
			at = f.Resource.Kind + "/" + f.Resource.Name
		}
		if w := string(f.Level[0]) + ":" + at; !slices.Contains(fs, w) {
			fs = append(fs, w)
		}
	}
	slices.Sort(fs)
	return strings.TrimSpace(string(c.Status) + " " + strings.Join(fs, " "))
}

func TestOutcomes(t *testing.T) {
	for _, tc := range []struct {
		world    func() *Input
		from, to string
		check    string
		want     string
	}{
		// Health and skew.
		{troubled, "1.36", "1.37", "node-health", "warning w:Node/worker-3"},
		{troubled, "1.36", "1.37", "kubelet-version-skew", "blocked b:Node/worker-3"},
		{troubled, "1.36", "1.37", "kube-proxy-version-skew", "blocked b:DaemonSet/kube-proxy"},
		{googleCluster, "1.34", "1.35", "kubelet-version-skew", "blocked b:Node/cp-1 b:Node/worker-1 b:Node/worker-2"}, // newer than the target
		{proxyVariants, "1.36", "1.37", "kube-proxy-version-skew", "unknown"},                                          // one has no kube-proxy container
		{staticProxy, "1.36", "1.37", "kube-proxy-version-skew", "not_applicable"},
		{blind, "1.36", "1.37", "node-health", "unknown"},

		// 1.35.
		{googleCluster, "1.34", "1.35", "gke-exec-probe-timeout", "blocked b:Deployment/worker r:Deployment/indexer"},
		{calm, "1.34", "1.35", "gke-exec-probe-timeout", "not_applicable"},
		{windowsOnly, "1.34", "1.35", "node-cgroup-v1", "not_applicable"},
		{calm, "1.34", "1.35", "node-cgroup-v1", "unknown"},

		// 1.36.
		{troubled, "1.35", "1.36", "gitrepo-volume-removed", "blocked b:Deployment/docs"},
		{troubled, "1.35", "1.36", "flexvolume-kubeadm-support", "warning w:Deployment/nfs-reader w:PersistentVolume/pv-flex"},
		{googleCluster, "1.35", "1.36", "flexvolume-kubeadm-support", "not_applicable"},
		{troubled, "1.35", "1.36", "service-externalips-deprecated", "review r:Service/legacy-lb"},
		{troubled, "1.35", "1.36", "renamed-control-plane-metrics", "warning w:PrometheusRule/storage"},
		{partialWebhooks, "1.35", "1.36", "renamed-control-plane-metrics", "not_applicable"},
		{windowsOnly, "1.35", "1.36", "container-runtime-support", "not_applicable"},
		{blind, "1.35", "1.36", "gitrepo-volume-removed", "unknown"},

		// 1.37.
		{troubled, "1.36", "1.37", "removed-feature-gates", "blocked b:Pod/kube-apiserver-cp-1 b:Pod/kube-controller-manager-cp-1"},
		{calm, "1.36", "1.37", "removed-feature-gates", "unknown"},
		{troubled, "1.36", "1.37", "removed-component-flags", "blocked b:Pod/kube-apiserver-cp-1 b:Pod/kube-controller-manager-cp-1"},
		{calm, "1.36", "1.37", "removed-component-flags", "passed"},
		{googleCluster, "1.36", "1.37", "removed-component-flags", "not_applicable"},
		{calm, "1.36", "1.37", "removed-kubelet-cadvisor-options", "review r:-"},
		{troubled, "1.36", "1.37", "kubeadm-config-v1beta3", "unknown"},
		{calm, "1.36", "1.37", "kubeadm-config-v1beta3", "not_applicable"},
		{troubled, "1.36", "1.37", "removed-control-plane-metrics", "warning w:PrometheusRule/dra"},
		{sharedVolumes, "1.36", "1.37", "selinux-mount-transition", "warning r:PersistentVolume/pv-labels r:PersistentVolume/pv-shared w:Pod/label-a"},
		{calm, "1.36", "1.37", "selinux-mount-transition", "not_applicable"},
		{blind, "1.36", "1.37", "selinux-mount-transition", "unknown"},

		// kube-proxy mode.
		{troubled, "1.36", "1.37", "kube-proxy-mode-transition", "review r:DaemonSet/kube-proxy"},
		{calm, "1.36", "1.37", "kube-proxy-mode-transition", "passed"},
		{proxyVariants, "1.36", "1.37", "kube-proxy-mode-transition", "review r:DaemonSet/kube-proxy-implicit"},
		{staticProxy, "1.36", "1.37", "kube-proxy-mode-transition", "review r:Pod/kube-proxy-worker-2"},

		// Every upgrade.
		{troubled, "1.36", "1.37", "node-drain-feasibility", "blocked b:PodDisruptionBudget/cart-loose b:PodDisruptionBudget/cart-strict r:Pod/debug-shell w:Pod/debug-shell"},
		{calm, "1.36", "1.37", "node-drain-feasibility", "passed"},
		{troubled, "1.36", "1.37", "admission-webhook-readiness", "blocked b:MutatingWebhookConfiguration/injector r:MutatingWebhookConfiguration/injector w:MutatingWebhookConfiguration/injector"},
		{partialWebhooks, "1.36", "1.37", "admission-webhook-readiness", "unknown"},
		{troubled, "1.36", "1.37", "crd-conversion-webhook-readiness", "blocked b:CustomResourceDefinition/broken.example.org b:CustomResourceDefinition/widgets.example.org r:CustomResourceDefinition/remote.example.org w:CustomResourceDefinition/gadgets.example.org"},
		{calm, "1.36", "1.37", "crd-conversion-webhook-readiness", "not_applicable"},
		{troubled, "1.36", "1.37", "aggregated-apiservice-readiness", "warning w:APIService/v1beta1.custom.metrics.k8s.io"},
		{calm, "1.36", "1.37", "aggregated-apiservice-readiness", "passed"},
	} {
		got := outcome(checkIn(t, mustScan(t, tc.world(), tc.from, tc.to), tc.check))
		if got != tc.want {
			t.Errorf("%s %s→%s:\n got %s\nwant %s", tc.check, tc.from, tc.to, got, tc.want)
		}
	}
}

func findingAt(t *testing.T, c Check, title string) Finding {
	t.Helper()
	for _, f := range c.Findings {
		if strings.Contains(f.Title, title) {
			return f
		}
	}
	t.Fatalf("%s: no finding titled %q in %v", c.ID, title, c.Findings)
	return Finding{}
}

func TestFindingEvidence(t *testing.T) {
	r := mustScan(t, troubled(), "1.36", "1.37")

	gates := checkIn(t, r, "removed-feature-gates")
	sidecar := findingAt(t, gates, "SidecarContainers")
	if sidecar.Evidence.Path != "spec.containers[0].command[--feature-gates].SidecarContainers" || sidecar.Evidence.Detail != "true" || sidecar.References[0].URL != k8sRepo+"pull/137755" {
		t.Errorf("removed gate: %+v", sidecar)
	}
	hostname := findingAt(t, gates, "HostnameOverride")
	if hostname.Evidence.Detail != "false" || !strings.Contains(hostname.Remediation, "HostnameOverride=true") {
		t.Errorf("locked gate: %+v", hostname)
	}
	for _, f := range gates.Findings {
		if strings.Contains(f.Title, "RelaxedServiceNameValidation") {
			t.Error("a gate set to its locked value is fine")
		}
	}
	if dra := findingAt(t, gates, "DRAPrioritizedList"); dra.Evidence.Path != "spec.containers[0].command[--feature-gates].DRAPrioritizedList" {
		t.Errorf("space-separated --feature-gates: %+v", dra.Evidence)
	}

	flags := checkIn(t, r, "removed-component-flags")
	if f := findingAt(t, flags, "--concurrent-service-syncs"); f.Evidence.Detail != "5" {
		t.Errorf("flag value: %+v", f.Evidence)
	}
	if f := findingAt(t, flags, "PodGroupWorkloadExists"); f.Evidence.Path != "spec.containers[0].command[--enable-admission-plugins]" {
		t.Errorf("admission plugin: %+v", f.Evidence)
	}

	drain := checkIn(t, r, "node-drain-feasibility")
	if f := findingAt(t, drain, "more than one"); f.Resource.Name != "cart-loose" || !strings.Contains(f.Evidence.Detail, "shop/cart-strict across 2 active pod(s)") {
		t.Errorf("overlap: %+v", f)
	}
	if !strings.Contains(drain.Caveat, "1 PodDisruptionBudget") {
		t.Errorf("a budget the controller has not caught up with is a caveat: %q", drain.Caveat)
	}

	hooks := checkIn(t, r, "admission-webhook-readiness")
	for title, path := range map[string]string{
		"exactly":                "webhooks[0].matchPolicy",
		"Fail-closed":            "webhooks[0].clientConfig.service",
		"Fail-open":              "webhooks[1].clientConfig.service",
		"outside the cluster":    "webhooks[2].clientConfig.url",
		"authentication reviews": "webhooks[3].rules",
	} {
		if f := findingAt(t, hooks, title); f.Evidence.Path != path {
			t.Errorf("%s: %s", title, f.Evidence.Path)
		}
	}

	api := findingAt(t, checkIn(t, r, "aggregated-apiservice-readiness"), "unavailable")
	if api.Evidence.Detail != "False (FailedDiscoveryCheck): failing or missing response from https://10.43.0.9:443" {
		t.Errorf("condition: %q", api.Evidence.Detail)
	}
	if c := checkIn(t, r, "aggregated-apiservice-readiness"); !strings.Contains(c.Caveat, "v1.external.example.org") {
		t.Errorf("an APIService with no condition is a caveat: %q", c.Caveat)
	}

	metrics := checkIn(t, r, "removed-control-plane-metrics")
	var details []string
	for _, f := range metrics.Findings {
		details = append(details, f.Evidence.Detail)
	}
	slices.Sort(details)
	if !slices.Equal(details, []string{"container_application_requests_total", "container_tasks_state", "resourceclaim_controller_creates_total"}) {
		t.Errorf("metrics %v", details)
	}

	google := mustScan(t, googleCluster(), "1.34", "1.35")
	probe := findingAt(t, checkIn(t, google, "gke-exec-probe-timeout"), "already timing out")
	if probe.Evidence.Path != "spec.template.spec.containers[worker].livenessProbe.timeoutSeconds" || probe.Resource.Name != "worker" {
		t.Errorf("probe: %+v", probe)
	}
}

func TestManagedBy(t *testing.T) {
	c := checkIn(t, mustScan(t, troubled(), "1.35", "1.36"), "flexvolume-kubeadm-support")
	f := findingAt(t, c, "Workload uses FlexVolume")
	if f.ManagedBy == nil || *f.ManagedBy != (ResourceRef{Group: "helm.toolkit.fluxcd.io", Kind: "HelmRelease", Namespace: "flux-system", Name: "readers"}) {
		t.Errorf("managed by %+v", f.ManagedBy)
	}
	// A ReplicaSet stamped from its Deployment's template is the Deployment's
	// business, and so are the pods it runs.
	for _, f := range checkIn(t, mustScan(t, troubled(), "1.35", "1.36"), "gitrepo-volume-removed").Findings {
		if f.Resource.Kind != "Deployment" {
			t.Errorf("judged twice: %+v", f.Resource)
		}
	}
}

func TestOldReplicaSetsJudgedAlone(t *testing.T) {
	in := calm()
	rs := in.ReplicaSets[0].DeepCopy()
	rs.Name = "web-5b7d4"
	rs.Spec.Template.Spec.Volumes = []corev1.Volume{{Name: "src", VolumeSource: corev1.VolumeSource{GitRepo: &corev1.GitRepoVolumeSource{Repository: "https://git.example.org/web.git"}}}}
	in.ReplicaSets = append(in.ReplicaSets, rs)
	c := checkIn(t, mustScan(t, in, "1.35", "1.36"), "gitrepo-volume-removed")
	if outcome(c) != "blocked b:ReplicaSet/web-5b7d4" {
		t.Errorf("an older revision differing from the template: %s", outcome(c))
	}
}
