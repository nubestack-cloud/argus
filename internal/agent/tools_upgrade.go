package agent

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"

	"argus/internal/agent/objcache"
	"argus/internal/agent/upgradeready"
)

// get_upgrade_readiness (docs/CLUSTER_INSIGHT_SPECS.md CI-S5): what would
// break if this cluster's control plane were upgraded to the target minor.
// Inputs the investigate identity cannot collect — API-server metrics, Helm
// release manifests, kubelet runtime evidence via nodes/proxy — stay nil, and
// the checks that need them report unknown with the reason; a scan here can
// therefore never claim "no known blockers" on evidence it did not have.

// upgradeResult keeps the cache's per-kind coverage under its own name:
// ScanResults has a coverage field of its own, and two embedded fields with
// the same JSON name are both dropped by encoding/json.
type upgradeResult struct {
	ObservedAt    time.Time             `json:"observedAt"`
	CacheCoverage []objcache.KindStatus `json:"cacheCoverage,omitempty"`
	*upgradeready.ScanResults
}

func (e *ToolExecutor) getUpgradeReadiness(ctx context.Context, raw json.RawMessage) (json.RawMessage, bool, error) {
	c, err := e.cache()
	if err != nil {
		return nil, false, err
	}
	var a struct {
		TargetVersion string `json:"targetVersion"`
	}
	if err := decodeInsightArgs(raw, &a); err != nil {
		return nil, false, err
	}
	current := ""
	if e.typed != nil {
		if v, err := e.typed.Discovery().ServerVersion(); err == nil {
			current = strings.TrimPrefix(v.GitVersion, "v")
		}
	}
	in := &upgradeready.Input{}
	in.Pods, _ = c.Pods("")
	in.Deployments, _ = c.Deployments("")
	in.ReplicaSets, _ = c.ReplicaSets("")
	in.StatefulSets, _ = c.StatefulSets("")
	in.DaemonSets, _ = c.DaemonSets("")
	in.Jobs, _ = c.Jobs("")
	in.CronJobs, _ = c.CronJobs("")
	in.Services, _ = c.Services("")
	in.WebhookServices = in.Services
	in.ConfigMaps, _ = c.ConfigMaps("")
	in.PersistentVolumeClaims, _ = c.PersistentVolumeClaims("")
	in.PersistentVolumes, _ = c.PersistentVolumes()
	nodes, nodesErr := c.Nodes()
	in.Nodes = nodes
	// The platform is inferred from the cached Nodes; it stays "" (unknown)
	// only when they cannot be read.
	in.Platform = upgradeready.DetectPlatform(nodes, nodesErr == nil)
	in.PodDisruptionBudgets, _ = c.PodDisruptionBudgets("")
	in.EndpointSlices, _ = c.EndpointSlices("")
	in.CSIDrivers, _ = c.CSIDrivers()
	in.Events = e.recentEvents(ctx, 2000)

	var webhooks []*unstructured.Unstructured
	if v, err := c.ValidatingWebhookConfigurations(); err == nil {
		for _, w := range v {
			if u := toUnstructuredObj(w, "admissionregistration.k8s.io/v1", "ValidatingWebhookConfiguration"); u != nil {
				webhooks = append(webhooks, u)
			}
		}
	} else {
		in.AdmissionWebhookUnavailableKinds = append(in.AdmissionWebhookUnavailableKinds, "ValidatingWebhookConfiguration")
	}
	if m, err := c.MutatingWebhookConfigurations(); err == nil {
		for _, w := range m {
			if u := toUnstructuredObj(w, "admissionregistration.k8s.io/v1", "MutatingWebhookConfiguration"); u != nil {
				webhooks = append(webhooks, u)
			}
		}
	} else {
		in.AdmissionWebhookUnavailableKinds = append(in.AdmissionWebhookUnavailableKinds, "MutatingWebhookConfiguration")
	}
	if webhooks == nil && len(in.AdmissionWebhookUnavailableKinds) < 2 {
		webhooks = []*unstructured.Unstructured{}
	}
	in.AdmissionWebhookConfigurations = webhooks
	if crds, err := c.Dynamic("apiextensions.k8s.io", "CustomResourceDefinition", ""); err == nil {
		in.CustomResourceDefinitions = nonNil(crds)
	}
	if svcs, err := c.Dynamic("apiregistration.k8s.io", "APIService", ""); err == nil {
		in.APIServices = nonNil(svcs)
	}
	switch c.State("monitoring.coreos.com", "PrometheusRule") {
	case "synced":
		rules, _ := c.Dynamic("monitoring.coreos.com", "PrometheusRule", "")
		in.PrometheusRules = nonNil(rules)
		in.PrometheusRulesInstalled = true
		in.PrometheusRulesDiscoveryAvailable = true
	case "absent":
		in.PrometheusRules = []*unstructured.Unstructured{}
		in.PrometheusRulesDiscoveryAvailable = true
	}
	res, err := upgradeready.Scan(in, current, a.TargetVersion)
	if err != nil {
		return nil, false, err
	}
	m := e.meta(kindPod, [2]string{"", "Node"}, [2]string{"apiextensions.k8s.io", "CustomResourceDefinition"}, [2]string{"apiregistration.k8s.io", "APIService"})
	return marshalInsight(upgradeResult{ObservedAt: m.ObservedAt, CacheCoverage: m.Coverage, ScanResults: res})
}

func nonNil(in []*unstructured.Unstructured) []*unstructured.Unstructured {
	if in == nil {
		return []*unstructured.Unstructured{}
	}
	return in
}

func toUnstructuredObj(obj runtime.Object, apiVersion, kind string) *unstructured.Unstructured {
	m, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		return nil
	}
	u := &unstructured.Unstructured{Object: m}
	u.SetAPIVersion(apiVersion)
	u.SetKind(kind)
	return u
}

// recentEvents lists the most recent events cluster-wide, live (events are
// not cached), bounded by limit. Nil when the read fails, so checks that
// need events report unknown rather than "no events".
func (e *ToolExecutor) recentEvents(ctx context.Context, limit int64) []*corev1.Event {
	if e.typed == nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	list, err := e.typed.CoreV1().Events("").List(cctx, metav1.ListOptions{Limit: limit})
	if err != nil {
		return nil
	}
	out := make([]*corev1.Event, 0, len(list.Items))
	for i := range list.Items {
		out = append(out, &list.Items[i])
	}
	return out
}
