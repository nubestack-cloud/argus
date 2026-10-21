package agent

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// TestBuildNodeStatusesWithUsage exercises the case a metrics-server-backed
// cluster gets: an entry in the usage map for every node, resulting in
// CPUUsed/MemoryUsed being populated alongside the always-available
// Ready/Allocatable fields.
func TestBuildNodeStatusesWithUsage(t *testing.T) {
	nodes := []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionTrue},
				},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("4"),
					corev1.ResourceMemory: resource.MustParse("16Gi"),
				},
			},
		},
	}
	usage := map[string]nodeUsage{
		"node-1": {cpu: "250m", memory: "1024Mi"},
	}

	statuses := buildNodeStatuses(nodes, usage)
	if len(statuses) != 1 {
		t.Fatalf("expected 1 NodeStatus, got %d", len(statuses))
	}
	ns := statuses[0]
	if ns.Name != "node-1" || !ns.Ready {
		t.Fatalf("unexpected name/ready: %+v", ns)
	}
	if ns.CPUAllocatable != "4" || ns.MemoryAllocatable != "16Gi" {
		t.Fatalf("unexpected allocatable: %+v", ns)
	}
	if ns.CPUUsed == nil || *ns.CPUUsed != "250m" {
		t.Fatalf("expected CPUUsed 250m, got %+v", ns.CPUUsed)
	}
	if ns.MemoryUsed == nil || *ns.MemoryUsed != "1024Mi" {
		t.Fatalf("expected MemoryUsed 1024Mi, got %+v", ns.MemoryUsed)
	}
}

// TestBuildNodeStatusesWithoutMetricsServer exercises the required
// degradation behaviour: a nil usage map (what gatherNodeUsage returns
// whenever metrics.k8s.io isn't available, e.g. no metrics-server
// installed) must never turn into an error or a dropped node — the node
// still reports Ready/Allocatable, with CPUUsed/MemoryUsed simply nil.
func TestBuildNodeStatusesWithoutMetricsServer(t *testing.T) {
	nodes := []corev1.Node{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{
					{Type: corev1.NodeReady, Status: corev1.ConditionFalse},
				},
				Allocatable: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("2"),
					corev1.ResourceMemory: resource.MustParse("8Gi"),
				},
			},
		},
	}

	statuses := buildNodeStatuses(nodes, nil)
	if len(statuses) != 1 {
		t.Fatalf("expected 1 NodeStatus, got %d", len(statuses))
	}
	ns := statuses[0]
	if ns.Ready {
		t.Fatalf("expected Ready: false, got true")
	}
	if ns.CPUAllocatable != "2" || ns.MemoryAllocatable != "8Gi" {
		t.Fatalf("unexpected allocatable: %+v", ns)
	}
	if ns.CPUUsed != nil || ns.MemoryUsed != nil {
		t.Fatalf("expected nil usage fields with no metrics-server, got %+v / %+v", ns.CPUUsed, ns.MemoryUsed)
	}
}
