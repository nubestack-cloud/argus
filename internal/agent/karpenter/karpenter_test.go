package karpenter

import (
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func pool(name string, weight int64, reqs []any, taints []any, limits, used map[string]any) *unstructured.Unstructured {
	o := map[string]any{
		"metadata": map[string]any{"name": name},
		"spec": map[string]any{"weight": weight, "limits": limits,
			"template": map[string]any{"spec": map[string]any{"requirements": reqs, "taints": taints}}},
		"status": map[string]any{"resources": used},
	}
	return &unstructured.Unstructured{Object: o}
}

func TestEvaluate(t *testing.T) {
	gpu := pool("gpu", 10, []any{map[string]any{"key": "karpenter.sh/capacity-type", "operator": "In", "values": []any{"on-demand"}}},
		[]any{map[string]any{"key": "nvidia.com/gpu", "value": "true", "effect": "NoSchedule"}}, nil, nil)
	general := pool("general", 1, []any{map[string]any{"key": "kubernetes.io/arch", "operator": "In", "values": []any{"amd64"}}},
		nil, map[string]any{"cpu": "10"}, map[string]any{"cpu": "9500m"})
	pod := &corev1.Pod{Spec: corev1.PodSpec{NodeSelector: map[string]string{"kubernetes.io/arch": "arm64"}}}
	req := corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("1")}

	got := Evaluate(pod, req, []*unstructured.Unstructured{general, gpu})
	if got[0].Pool != "gpu" {
		t.Fatalf("pools must come in weight order, got %+v", got)
	}
	if got[0].Fits || !strings.Contains(got[0].Reason, "taint nvidia.com/gpu") {
		t.Fatalf("gpu = %+v, want refused for the untolerated taint", got[0])
	}
	if got[1].Fits || !strings.Contains(got[1].Reason, "allows kubernetes.io/arch only in [amd64]") {
		t.Fatalf("general = %+v, want refused for the arch selector", got[1])
	}
	// With the right arch, general is refused only by its reached CPU limit.
	pod.Spec.NodeSelector["kubernetes.io/arch"] = "amd64"
	if v := Evaluate(pod, req, []*unstructured.Unstructured{general})[0]; v.Fits || !strings.Contains(v.Reason, "cpu limit is reached") {
		t.Fatalf("general = %+v, want the limit", v)
	}
	if v := Evaluate(pod, corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("250m")}, []*unstructured.Unstructured{general})[0]; !v.Fits {
		t.Fatalf("a request within the headroom must fit, got %+v", v)
	}
}

func TestLedgers(t *testing.T) {
	general := pool("general", 1, nil, nil, map[string]any{"cpu": "10"}, map[string]any{"cpu": "4", "nodes": "2"})
	claim := func(conds ...string) *unstructured.Unstructured {
		var cs []any
		for _, c := range conds {
			cs = append(cs, map[string]any{"type": c, "status": "True"})
		}
		return &unstructured.Unstructured{Object: map[string]any{
			"metadata": map[string]any{"name": "c", "labels": map[string]any{"karpenter.sh/nodepool": "general"}},
			"status":   map[string]any{"conditions": cs}}}
	}
	l := Ledgers([]*unstructured.Unstructured{general}, []*unstructured.Unstructured{claim("Launched", "Registered", "Initialized", "Ready"), claim("Launched")})
	if len(l) != 1 || l[0].LimitCPU != "10" || l[0].UsedCPU != "4" || *l[0].Nodes != 2 || l[0].Claims["Ready"] != 1 || l[0].Claims["Launched"] != 1 {
		t.Fatalf("ledger = %+v", l)
	}
}
