package cost

import (
	"context"
	"sort"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
)

// MaxWorkloads caps the workload rows; the most expensive are kept.
const MaxWorkloads = 100

// WorkloadOwner identifies a workload by name and kind.
type WorkloadOwner struct {
	Name string
	Kind string
}

// PodOwnerLookup resolves a pod in the namespace being costed to its
// top-level workload owner (Deployment rather than ReplicaSet). It returns
// false when the pod is unknown — typically because it has since been
// deleted while its cost is still inside the window.
type PodOwnerLookup func(podName string) (WorkloadOwner, bool)

// Workload kinds assigned here rather than by the lookup.
const (
	// KindStandalone groups pods the lookup could not resolve under their
	// name with hash suffixes stripped — a best-effort grouping.
	KindStandalone = "standalone"
	// KindStaticPod marks a pod owned by its Node (a kubelet static pod).
	KindStaticPod = "staticpod"
)

// WorkloadCosts is one namespace's hourly spend broken down by workload.
type WorkloadCosts struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Window    string `json:"window,omitempty"`
	Namespace string `json:"namespace"`

	Workloads      []WorkloadCost `json:"workloads,omitempty"`
	TotalWorkloads int            `json:"totalWorkloads,omitempty"`
	Truncated      bool           `json:"truncated,omitempty"`
	Missing        []string       `json:"missing,omitempty"`
}

// WorkloadCost is one workload's hourly compute spend. Storage is not
// attributed to workloads: a volume belongs to a claim, not to a pod.
type WorkloadCost struct {
	Name       string  `json:"name"`
	Kind       string  `json:"kind"`
	Pods       int     `json:"pods"`
	HourlyCost float64 `json:"hourlyCost"`
	CPUCost    float64 `json:"cpuCost"`
	MemoryCost float64 `json:"memoryCost"`
	// Each usage figure is nil unless every pod allocated that resource was
	// measured: one unmeasured replica would understate the total. CPU and
	// memory are judged separately, so one failed usage query does not hide
	// the other.
	CPUUsageCost    *float64 `json:"cpuUsageCost,omitempty"`
	MemoryUsageCost *float64 `json:"memoryUsageCost,omitempty"`
	// CPUAllocationUse and MemoryAllocationUse are usage as a percentage of
	// allocation, per resource.
	CPUAllocationUse    *float64 `json:"cpuAllocationUse,omitempty"`
	MemoryAllocationUse *float64 `json:"memoryAllocationUse,omitempty"`
	// Efficiency and IdleCost need both resources measured.
	Efficiency *float64 `json:"efficiency,omitempty"`
	IdleCost   *float64 `json:"idleCost,omitempty"`
}

// ComputeWorkloads returns the per-workload cost breakdown for namespace,
// grouping each costed pod under the owner lookup returns.
func ComputeWorkloads(ctx context.Context, q PromQuerier, namespace string, window time.Duration, lookup PodOwnerLookup) *WorkloadCosts {
	if errs := validation.IsDNS1123Label(namespace); len(errs) > 0 {
		return &WorkloadCosts{Namespace: namespace, Reason: ReasonInvalidRequest, Detail: "namespace must be a valid namespace name"}
	}
	w := promWindow(window)
	fail := func(reason, detail string) *WorkloadCosts {
		return &WorkloadCosts{Namespace: namespace, Reason: reason, Detail: detail}
	}

	cpu, err := queryWithFallback(ctx, q, podCPUAllocationQuery(namespace, w), podCPUCostFallbackQuery(namespace, w))
	if err != nil {
		return fail(queryFailure(err, "CPU allocation cost"))
	}
	mem, err := queryWithFallback(ctx, q, podMemAllocationQuery(namespace, w), podMemCostFallbackQuery(namespace, w))
	if err != nil {
		return fail(queryFailure(err, "memory allocation cost"))
	}
	if len(cpu) == 0 && len(mem) == 0 {
		return fail(ReasonNoMetrics, "Prometheus holds no OpenCost allocation metrics for pods in this namespace")
	}

	out := &WorkloadCosts{Available: true, Window: w, Namespace: namespace}
	cpuUsage, cpuUsageErr := q.Query(ctx, podCPUUsageQuery(namespace, w))
	if cpuUsageErr != nil {
		out.Missing = append(out.Missing, "CPU usage")
	}
	memUsage, memUsageErr := q.Query(ctx, podMemUsageQuery(namespace))
	if memUsageErr != nil {
		out.Missing = append(out.Missing, "memory usage")
	}
	podCPUUsage := valuePerLabel(cpuUsage, cpuUsageErr, "pod")
	podMemUsage := valuePerLabel(memUsage, memUsageErr, "pod")

	type podCost struct{ cpu, mem float64 }
	pods := make(map[string]*podCost)
	for _, s := range cpu {
		if p := s.Labels["pod"]; p != "" {
			if pods[p] == nil {
				pods[p] = &podCost{}
			}
			pods[p].cpu = finite(s.Value)
		}
	}
	for _, s := range mem {
		if p := s.Labels["pod"]; p != "" {
			if pods[p] == nil {
				pods[p] = &podCost{}
			}
			pods[p].mem = finite(s.Value)
		}
	}

	type acc struct {
		row                  WorkloadCost
		cpuUsage, memUsage   float64
		cpuMeasured, memMeas bool
	}
	byOwner := make(map[WorkloadOwner]*acc)
	for podName, pc := range pods {
		owner, ok := WorkloadOwner{}, false
		if lookup != nil {
			owner, ok = lookup(podName)
		}
		switch {
		case !ok:
			owner = WorkloadOwner{Name: guessWorkloadName(podName), Kind: KindStandalone}
		case owner.Kind == "Node":
			owner = WorkloadOwner{Name: podName, Kind: KindStaticPod}
		}
		a, exists := byOwner[owner]
		if !exists {
			a = &acc{row: WorkloadCost{Name: owner.Name, Kind: owner.Kind}, cpuMeasured: true, memMeas: true}
			byOwner[owner] = a
		}
		a.row.Pods++
		a.row.CPUCost += pc.cpu
		a.row.MemoryCost += pc.mem
		if u, ok := podCPUUsage[podName]; ok {
			a.cpuUsage += finite(u.value)
		} else if pc.cpu > 0 {
			a.cpuMeasured = false
		}
		if u, ok := podMemUsage[podName]; ok {
			a.memUsage += finite(u.value)
		} else if pc.mem > 0 {
			a.memMeas = false
		}
	}

	workloads := make([]WorkloadCost, 0, len(byOwner))
	for _, a := range byOwner {
		wl := a.row
		alloc := wl.CPUCost + wl.MemoryCost
		wl.HourlyCost = roundTo(alloc, 4)
		// Percentages are taken before rounding: at small costs the rounded
		// figures are zero and would make every ratio meaningless.
		if a.cpuMeasured {
			use := efficiencyPercent(a.cpuUsage, wl.CPUCost)
			wl.CPUAllocationUse = &use
			wl.CPUUsageCost = roundedPtr(a.cpuUsage)
		}
		if a.memMeas {
			use := efficiencyPercent(a.memUsage, wl.MemoryCost)
			wl.MemoryAllocationUse = &use
			wl.MemoryUsageCost = roundedPtr(a.memUsage)
		}
		if a.cpuMeasured && a.memMeas {
			usage := a.cpuUsage + a.memUsage
			eff := efficiencyPercent(usage, alloc)
			wl.Efficiency = &eff
			wl.IdleCost = roundedPtr(idleFromUsage(usage, alloc))
		}
		wl.CPUCost = roundTo(wl.CPUCost, 4)
		wl.MemoryCost = roundTo(wl.MemoryCost, 4)
		workloads = append(workloads, wl)
	}
	sort.Slice(workloads, func(i, j int) bool {
		if workloads[i].HourlyCost != workloads[j].HourlyCost {
			return workloads[i].HourlyCost > workloads[j].HourlyCost
		}
		if workloads[i].Kind != workloads[j].Kind {
			return workloads[i].Kind < workloads[j].Kind
		}
		return workloads[i].Name < workloads[j].Name
	})
	out.TotalWorkloads = len(workloads)
	if len(workloads) > MaxWorkloads {
		workloads = workloads[:MaxWorkloads]
		out.Truncated = true
	}
	out.Workloads = workloads
	return out
}

// guessWorkloadName names the workload of a pod the cache does not know,
// from the pod's name alone: Kubernetes ends generated pod names with one
// generated segment (a StatefulSet ordinal, a Job's suffix) or two (a
// ReplicaSet's template hash, then the pod's own). Trailing segments that
// look generated — short, lowercase letters and digits — are dropped: one
// when the last is all digits, otherwise up to two; the name is never
// emptied.
func guessWorkloadName(pod string) string {
	parts := strings.Split(pod, "-")
	keep := len(parts)
	limit := 2
	if allDigits(parts[keep-1]) {
		limit = 1 // a StatefulSet ordinal or Job index has nothing generated before it
	}
	for dropped := 0; dropped < limit && keep > 1 && looksGenerated(parts[keep-1]); dropped++ {
		keep--
	}
	if name := strings.Join(parts[:keep], "-"); name != "" {
		return name
	}
	return pod
}

func allDigits(seg string) bool {
	for _, r := range seg {
		if r < '0' || r > '9' {
			return false
		}
	}
	return seg != ""
}

func looksGenerated(seg string) bool {
	if seg == "" || len(seg) > 10 {
		return false
	}
	for _, r := range seg {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
