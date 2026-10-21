package agent

import (
	"context"
	"encoding/json"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"strings"
	"testing"
)

// The canary cluster's prod namespace has a deny-all ingress policy, a
// Service routing port 80 to the pod's named port 8080, a Role binding for
// the payments ServiceAccount, an HPA and a 3-replica Deployment.
func TestInsightToolsAnswerFromTheCache(t *testing.T) {
	exec := canaryCluster(t)
	call := func(tool string, args map[string]any) map[string]any {
		t.Helper()
		b, _ := json.Marshal(args)
		raw, _, err := exec.Execute(context.Background(), tool, b)
		if err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		var out map[string]any
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("%s: %v", tool, err)
		}
		if _, ok := out["observedAt"]; !ok {
			t.Errorf("%s: no observedAt", tool)
		}
		return out
	}

	np := call("evaluate_network_policy", map[string]any{
		"source":      map[string]any{"external": true},
		"destination": map[string]any{"kind": "Service", "namespace": "prod", "name": "payments"},
		"port":        80,
	})
	if v := np["verdict"].(map[string]any)["verdict"]; v != "denied" {
		t.Errorf("deny-all ingress: verdict = %v, want denied (%v)", v, np)
	}
	if np["backends"].(float64) != 1 {
		t.Errorf("backends = %v, want 1 (named targetPort must resolve)", np["backends"])
	}

	perm := call("get_subject_permissions", map[string]any{"kind": "ServiceAccount", "namespace": "prod", "name": "payments"})
	if b, _ := json.Marshal(perm["flat"]); !strings.Contains(string(b), "configmaps") {
		t.Errorf("permissions flat = %s, want the configmaps rule", b)
	}

	hpa := call("diagnose_autoscaler", map[string]any{"namespace": "prod", "name": "payments"})
	if hpa["diagnosis"] == nil {
		t.Error("autoscaler diagnosis missing")
	}

	ro := call("diagnose_rollout", map[string]any{"namespace": "prod", "name": "payments"})
	if ro["verdict"] == "" || ro["verdict"] == nil {
		t.Errorf("rollout verdict missing: %v", ro)
	}
}

func TestInsightToolsWithoutCacheSayWhy(t *testing.T) {
	exec, _ := newTestExecutor()
	_, _, err := exec.Execute(context.Background(), "diagnose_rollout", json.RawMessage(`{"namespace":"a","name":"b"}`))
	if err == nil || !strings.Contains(err.Error(), "object cache") {
		t.Fatalf("err = %v, want the object-cache-unavailable explanation", err)
	}
}

// The canary pod is Running but not Ready, so the path breaks at the Service
// before NetworkPolicy matters — the first broken hop is what the trace names.
func TestTraceServicePathNamesFirstBrokenHop(t *testing.T) {
	exec := canaryCluster(t)
	raw, _, err := exec.Execute(context.Background(), "trace_service_path", json.RawMessage(`{"kind":"Service","namespace":"prod","name":"payments"}`))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	if !strings.Contains(s, `"verdict":"broken"`) || !strings.Contains(s, "svc:no-ready-endpoints") || !strings.Contains(s, "Breaks at: Service prod/payments") {
		t.Errorf("want broken at the Service with svc:no-ready-endpoints:\n%s", s)
	}
	if !strings.Contains(s, `"headline"`) || !strings.Contains(s, `"observedAt"`) {
		t.Errorf("missing headline/observedAt:\n%s", s)
	}
}

// ScanResults carries its own coverage; the cache's coverage must not
// collide with it (encoding/json drops BOTH duplicate embedded fields).
func TestUpgradeReadinessKeepsScanCoverage(t *testing.T) {
	exec := canaryCluster(t)
	raw, _, err := exec.Execute(context.Background(), "get_upgrade_readiness", json.RawMessage(`{"targetVersion":"1.37"}`))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if _, ok := out["coverage"]; !ok {
		t.Fatalf("scan coverage missing from output: %s", raw)
	}
}

func TestComputeCapacitySumsScheduledRequests(t *testing.T) {
	q := func(s string) resource.Quantity { return resource.MustParse(s) }
	node := &corev1.Node{Status: corev1.NodeStatus{Allocatable: corev1.ResourceList{corev1.ResourceCPU: q("4"), corev1.ResourceMemory: q("8Gi")}}}
	pod := func(phase corev1.PodPhase, node, cpu string) *corev1.Pod {
		return &corev1.Pod{Spec: corev1.PodSpec{NodeName: node, Containers: []corev1.Container{{Resources: corev1.ResourceRequirements{Requests: corev1.ResourceList{corev1.ResourceCPU: q(cpu), corev1.ResourceMemory: q("1Gi")}}}}},
			Status: corev1.PodStatus{Phase: phase}}
	}
	c := computeCapacity([]*corev1.Pod{pod(corev1.PodRunning, "n1", "500m"), pod(corev1.PodSucceeded, "n1", "1"), pod(corev1.PodPending, "", "1")}, []*corev1.Node{node, node})
	if c.CPUAllocatableMillicores != 8000 || c.CPURequestedMillicores != 500 || c.PodsCounted != 1 || c.MemoryRequestedBytes != 1<<30 {
		t.Fatalf("capacity = %+v", c)
	}
}
