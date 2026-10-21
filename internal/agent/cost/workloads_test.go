package cost

import (
	"context"
	"strings"
	"testing"
)

func byPod(values map[string]float64) []Sample {
	out := make([]Sample, 0, len(values))
	for pod, v := range values {
		out = append(out, Sample{Labels: map[string]string{"pod": pod}, Value: v})
	}
	return out
}

// samePodResult answers every query with the same per-pod vector.
func samePodResult(values map[string]float64) *scriptedProm {
	return scripted(scriptedCase{contains: "", samples: byPod(values)})
}

func TestComputeWorkloadsGroupsPodsByOwner(t *testing.T) {
	// The same vector answers allocation and usage, so each pod's hourly cost
	// is twice its value (cpu + memory).
	q := samePodResult(map[string]float64{"checkout-5c9b7-q2w8e": 1, "checkout-5c9b7-r4t6y": 1, "nightly-report-29384": 5})
	owners := map[string]WorkloadOwner{
		"checkout-5c9b7-q2w8e": {Name: "checkout", Kind: "Deployment"},
		"checkout-5c9b7-r4t6y": {Name: "checkout", Kind: "Deployment"},
		"nightly-report-29384": {Name: "nightly-report", Kind: "Job"},
	}
	lookup := func(pod string) (WorkloadOwner, bool) { o, ok := owners[pod]; return o, ok }
	got := ComputeWorkloads(context.Background(), q, "default", 0, lookup)
	if !got.Available || len(got.Workloads) != 2 {
		t.Fatalf("got %+v", got)
	}
	w0, w1 := got.Workloads[0], got.Workloads[1]
	if w0.Name != "nightly-report" || w0.Kind != "Job" || w0.Pods != 1 || w0.HourlyCost != 10 {
		t.Errorf("first = %+v, want nightly-report/Job 1 pod at 10", w0)
	}
	if w1.Name != "checkout" || w1.Kind != "Deployment" || w1.Pods != 2 || w1.HourlyCost != 4 {
		t.Errorf("second = %+v, want checkout/Deployment 2 pods at 4", w1)
	}
	for _, w := range got.Workloads {
		if w.CPUAllocationUse == nil || w.MemoryAllocationUse == nil || w.Efficiency == nil {
			t.Errorf("%s: usage fully measured but reported unknown: %+v", w.Name, w)
		}
	}
}

func TestComputeWorkloadsUsageNeedsEveryAllocatedPod(t *testing.T) {
	q := scripted(
		scriptedCase{contains: "container_cpu_usage_seconds_total", samples: byPod(map[string]float64{"api-a": 0.5})},
		scriptedCase{contains: "", samples: byPod(map[string]float64{"api-a": 1, "api-b": 1})},
	)
	lookup := func(string) (WorkloadOwner, bool) { return WorkloadOwner{Name: "api", Kind: "Deployment"}, true }
	got := ComputeWorkloads(context.Background(), q, "default", 0, lookup)
	w := got.Workloads[0]
	if w.CPUAllocationUse != nil || w.CPUUsageCost != nil {
		t.Errorf("CPU usage reported with one of two pods unmeasured: %+v", w)
	}
	if w.MemoryAllocationUse == nil || *w.MemoryAllocationUse == 0 {
		t.Errorf("memory usage fully measured but missing: %+v", w)
	}
	if w.Efficiency != nil || w.IdleCost != nil {
		t.Errorf("combined figures need both resources: %+v", w)
	}
}

func TestComputeWorkloadsZeroUsageIsMeasured(t *testing.T) {
	q := scripted(
		scriptedCase{contains: "container_cpu_usage_seconds_total", samples: byPod(map[string]float64{"api-a": 0})},
		scriptedCase{contains: "container_memory_working_set_bytes", samples: nil},
		scriptedCase{contains: "", samples: byPod(map[string]float64{"api-a": 1})},
	)
	w := ComputeWorkloads(context.Background(), q, "default", 0, nil).Workloads[0]
	if w.CPUAllocationUse == nil || *w.CPUAllocationUse != 0 {
		t.Errorf("a reported zero CPU usage is a measurement: %+v", w.CPUAllocationUse)
	}
	if w.MemoryAllocationUse != nil {
		t.Errorf("memory usage with no sample must be unknown, got %v", *w.MemoryAllocationUse)
	}
}

func TestComputeWorkloadsAllocationUseBeforeRounding(t *testing.T) {
	q := scripted(
		scriptedCase{contains: "container_cpu_usage_seconds_total", samples: byPod(map[string]float64{"api-a": 0.00003})},
		scriptedCase{contains: "container_memory_working_set_bytes", samples: byPod(map[string]float64{"api-a": 0.00002})},
		scriptedCase{contains: "container_cpu_allocation", samples: byPod(map[string]float64{"api-a": 0.00006})},
		scriptedCase{contains: "", samples: byPod(map[string]float64{"api-a": 0.00008})},
	)
	w := ComputeWorkloads(context.Background(), q, "default", 0, nil).Workloads[0]
	if *w.CPUAllocationUse != 50 || *w.MemoryAllocationUse != 25 {
		t.Fatalf("allocation use = %v/%v, want 50/25", *w.CPUAllocationUse, *w.MemoryAllocationUse)
	}
	if *w.CPUUsageCost != 0 || *w.MemoryUsageCost != 0 {
		t.Fatalf("test needs usage costs that round to zero, got %v/%v", *w.CPUUsageCost, *w.MemoryUsageCost)
	}
}

func TestComputeWorkloadsUnresolvedPodsFallBack(t *testing.T) {
	q := samePodResult(map[string]float64{"api-7f8d9c-xyz12": 1, "orphan-pod-6b7d9f-x2k4q": 1})
	lookup := func(pod string) (WorkloadOwner, bool) {
		if pod == "api-7f8d9c-xyz12" {
			return WorkloadOwner{Name: "api", Kind: "Deployment"}, true
		}
		return WorkloadOwner{}, false
	}
	got := ComputeWorkloads(context.Background(), q, "default", 0, lookup)
	var orphan *WorkloadCost
	for i := range got.Workloads {
		if got.Workloads[i].Kind == KindStandalone {
			orphan = &got.Workloads[i]
		}
	}
	if len(got.Workloads) != 2 || orphan == nil || orphan.Name != "orphan-pod" {
		t.Fatalf("workloads = %+v, want the unresolved pod kept as standalone orphan-pod", got.Workloads)
	}

	nilLookup := ComputeWorkloads(context.Background(), samePodResult(map[string]float64{"api-7f8d9c-xyz12": 1}), "default", 0, nil)
	if w := nilLookup.Workloads[0]; w.Name != "api" || w.Kind != KindStandalone {
		t.Fatalf("nil lookup = %+v, want api/standalone", w)
	}
}

func TestComputeWorkloadsNodeOwnedPodIsStaticPod(t *testing.T) {
	q := samePodResult(map[string]float64{"kube-apiserver-node-1": 1})
	lookup := func(string) (WorkloadOwner, bool) { return WorkloadOwner{Name: "node-1", Kind: "Node"}, true }
	w := ComputeWorkloads(context.Background(), q, "kube-system", 0, lookup).Workloads[0]
	if w.Name != "kube-apiserver-node-1" || w.Kind != KindStaticPod {
		t.Fatalf("got %s/%s", w.Name, w.Kind)
	}
}

func TestComputeWorkloadsEmptyIsNoMetrics(t *testing.T) {
	got := ComputeWorkloads(context.Background(), scripted(), "default", 0, nil)
	if got.Available || got.Reason != ReasonNoMetrics || got.Workloads != nil {
		t.Fatalf("got %+v, want unavailable/no_metrics", got)
	}
}

func TestComputeWorkloadsRejectsBadNamespace(t *testing.T) {
	q := scripted()
	got := ComputeWorkloads(context.Background(), q, `x"} or vector(1)`, 0, nil)
	if got.Available || got.Reason != ReasonInvalidRequest || len(q.queries) != 0 {
		t.Fatalf("got %+v after %d queries, want rejection before any query", got, len(q.queries))
	}
}

func TestComputeWorkloadsScopesQueriesToTheNamespace(t *testing.T) {
	q := samePodResult(map[string]float64{"a": 1})
	ComputeWorkloads(context.Background(), q, "shop", 0, nil)
	for _, s := range q.queries {
		if !strings.Contains(s, `"shop"`) {
			t.Errorf("query not scoped to the namespace: %s", s)
		}
	}
}

func TestComputeWorkloadsCapped(t *testing.T) {
	values := map[string]float64{}
	for i := 0; i < MaxWorkloads+3; i++ {
		values[strings.Repeat("p", i+1)] = float64(i + 1)
	}
	got := ComputeWorkloads(context.Background(), samePodResult(values), "default", 0, nil)
	if !got.Truncated || len(got.Workloads) != MaxWorkloads || got.TotalWorkloads != MaxWorkloads+3 {
		t.Fatalf("truncated=%v len=%d total=%d", got.Truncated, len(got.Workloads), got.TotalWorkloads)
	}
}

func TestGuessWorkloadName(t *testing.T) {
	cases := []struct{ pod, want string }{
		{"checkout-5d8f7c9b4-qwx2z", "checkout"},   // Deployment: template hash, then pod suffix
		{"ledger-0", "ledger"},                     // StatefulSet ordinal
		{"report-job-1-9kz4t-abc", "report-job-1"}, // only two segments ever go
		{"Mixed-Case-Name", "Mixed-Case-Name"},     // capitals are not generated
		{"single", "single"},
		{"-odd", "-odd"}, // never emptied
		{"api-v2-service-0", "api-v2-service"},
	}
	for _, c := range cases {
		if got := guessWorkloadName(c.pod); got != c.want {
			t.Errorf("guessWorkloadName(%q) = %q, want %q", c.pod, got, c.want)
		}
	}
}
