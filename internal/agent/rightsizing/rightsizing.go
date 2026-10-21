// Package rightsizing compares each container's CPU and memory requests with
// what it actually used over a window (PROJECT.md PG8), and recommends a
// request that fits: p95 CPU and p95 memory working set, plus headroom, never
// below the window's peak memory (a request under the peak is an OOM risk the
// moment the pod is packed tightly).
//
// Requests come from the live pod specs, not from kube-state-metrics, so a pod
// sized at pod level (spec.resources, Kubernetes 1.32+) is read as such rather
// than as a pod with no requests. Usage comes from cAdvisor through the
// agent's configured Prometheus. Nothing here changes anything: a
// recommendation becomes a change only as a PatchResourceLimits plan an
// investigation proposes and a person approves.
package rightsizing

import (
	"context"
	"fmt"
	"math"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/validation"

	"argus/internal/agent/cost"
)

const (
	// Headroom over p95 for the recommended request.
	Headroom = 1.2
	// MinCPUMilli and MinMemoryBytes floor a recommendation: below these the
	// saving is noise and the scheduler's own minimums dominate.
	MinCPUMilli    = 10
	MinMemoryBytes = 32 << 20
	// A request is called over-provisioned only when it is at least twice
	// the recommendation AND the gap is material.
	overFactor     = 2.0
	minCPUGapMilli = 100
	minMemGapBytes = 128 << 20
)

// Verdicts.
const (
	VerdictOver  = "over"  // request well above what the container uses
	VerdictUnder = "under" // p95 above the request: the container runs on burst
	VerdictFits  = "fits"
	VerdictNoReq = "noRequest" // no request at all; the recommendation is a starting point
)

// Owner resolves a pod to its workload.
type Owner func(pod *corev1.Pod) (kind, name string)

// Result is one namespace's recommendations.
type Result struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	Window    string `json:"window"`
	Namespace string `json:"namespace"`
	Rows      []Row  `json:"rows"`
}

// Row is one container of one workload. Usage figures are the maximum across
// the workload's pods, so the recommendation fits the busiest replica.
type Row struct {
	Kind      string `json:"kind"`
	Workload  string `json:"workload"`
	Container string `json:"container"`
	Pods      int    `json:"pods"`
	// PodLevel is true when the pod spec carries spec.resources, which
	// bounds the whole pod: the request and limit shown are the pod's, and
	// no per-container recommendation is made.
	PodLevel bool `json:"podLevel,omitempty"`

	CPURequestMilli  *int64   `json:"cpuRequestMilli,omitempty"`
	CPULimitMilli    *int64   `json:"cpuLimitMilli,omitempty"`
	MemRequestBytes  *int64   `json:"memRequestBytes,omitempty"`
	MemLimitBytes    *int64   `json:"memLimitBytes,omitempty"`
	CPUP95Milli      *float64 `json:"cpuP95Milli,omitempty"`
	MemP95Bytes      *float64 `json:"memP95Bytes,omitempty"`
	MemPeakBytes     *float64 `json:"memPeakBytes,omitempty"`
	RecCPUMilli      *int64   `json:"recommendedCpuMilli,omitempty"`
	RecMemBytes      *int64   `json:"recommendedMemBytes,omitempty"`
	CPUVerdict       string   `json:"cpuVerdict,omitempty"`
	MemVerdict       string   `json:"memVerdict,omitempty"`
	MemLimitTooTight bool     `json:"memLimitTooTight,omitempty"`
}

func cpuP95Query(ns, w string) string {
	return fmt.Sprintf(`max by (pod, container) (quantile_over_time(0.95, rate(container_cpu_usage_seconds_total{namespace=%q, container!="", container!="POD"}[5m])[%s:5m]))`, ns, w)
}

func memP95Query(ns, w string) string {
	return fmt.Sprintf(`max by (pod, container) (quantile_over_time(0.95, container_memory_working_set_bytes{namespace=%q, container!="", container!="POD"}[%s]))`, ns, w)
}

func memPeakQuery(ns, w string) string {
	return fmt.Sprintf(`max by (pod, container) (max_over_time(container_memory_working_set_bytes{namespace=%q, container!="", container!="POD"}[%s]))`, ns, w)
}

// Compute queries usage for namespace over window and joins it with pods.
func Compute(ctx context.Context, q cost.PromQuerier, namespace string, window time.Duration, pods []*corev1.Pod, owner Owner) *Result {
	w := promDuration(window)
	r := &Result{Namespace: namespace, Window: w, Rows: []Row{}}
	if errs := validation.IsDNS1123Label(namespace); len(errs) > 0 {
		r.Reason = "namespace must be a valid namespace name"
		return r
	}
	cpu, err := q.Query(ctx, cpuP95Query(namespace, w))
	if err != nil {
		r.Reason = "Prometheus did not answer the CPU usage query: " + err.Error()
		return r
	}
	mem, err := q.Query(ctx, memP95Query(namespace, w))
	if err != nil {
		r.Reason = "Prometheus did not answer the memory usage query: " + err.Error()
		return r
	}
	peak, _ := q.Query(ctx, memPeakQuery(namespace, w))
	r.Available = true
	r.Rows = Join(pods, owner, index(cpu), index(mem), index(peak))
	return r
}

type usage map[[2]string]float64 // (pod, container) -> value

func index(ss []cost.Sample) usage {
	out := usage{}
	for _, s := range ss {
		if !math.IsNaN(s.Value) && !math.IsInf(s.Value, 0) {
			out[[2]string{s.Labels["pod"], s.Labels["container"]}] = s.Value
		}
	}
	return out
}

// Join is the pure half: cpu is in cores, memory in bytes.
func Join(pods []*corev1.Pod, owner Owner, cpu, mem, peak usage) []Row {
	rows := map[string]*Row{}
	for _, p := range pods {
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		kind, name := owner(p)
		podLevel := p.Spec.Resources != nil && (len(p.Spec.Resources.Requests) > 0 || len(p.Spec.Resources.Limits) > 0)
		for _, c := range p.Spec.Containers {
			key := kind + "/" + name + "/" + c.Name
			row := rows[key]
			if row == nil {
				row = &Row{Kind: kind, Workload: name, Container: c.Name, PodLevel: podLevel}
				res := c.Resources
				if podLevel {
					res = corev1.ResourceRequirements{Requests: p.Spec.Resources.Requests, Limits: p.Spec.Resources.Limits}
				}
				row.CPURequestMilli = milli(res.Requests, corev1.ResourceCPU)
				row.CPULimitMilli = milli(res.Limits, corev1.ResourceCPU)
				row.MemRequestBytes = bytesOf(res.Requests, corev1.ResourceMemory)
				row.MemLimitBytes = bytesOf(res.Limits, corev1.ResourceMemory)
				rows[key] = row
			}
			row.Pods++
			k := [2]string{p.Name, c.Name}
			if v, ok := cpu[k]; ok {
				row.CPUP95Milli = maxPtr(row.CPUP95Milli, v*1000)
			}
			if v, ok := mem[k]; ok {
				row.MemP95Bytes = maxPtr(row.MemP95Bytes, v)
			}
			if v, ok := peak[k]; ok {
				row.MemPeakBytes = maxPtr(row.MemPeakBytes, v)
			}
		}
	}
	out := make([]Row, 0, len(rows))
	for _, row := range rows {
		recommend(row)
		out = append(out, *row)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if rank(a) != rank(b) {
			return rank(a) < rank(b)
		}
		return a.Kind+a.Workload+a.Container < b.Kind+b.Workload+b.Container
	})
	return out
}

// recommend fills the recommendation and verdicts. A pod-level row is left
// without one: usage is per container and the request is per pod, and
// splitting either way would be a guess.
func recommend(r *Row) {
	if r.PodLevel {
		return
	}
	if r.CPUP95Milli != nil {
		rec := int64(math.Ceil(*r.CPUP95Milli * Headroom))
		if rec < MinCPUMilli {
			rec = MinCPUMilli
		}
		r.RecCPUMilli = &rec
		r.CPUVerdict = verdict(r.CPURequestMilli, *r.CPUP95Milli, rec, minCPUGapMilli)
	}
	if r.MemP95Bytes != nil {
		need := *r.MemP95Bytes * Headroom
		if r.MemPeakBytes != nil && *r.MemPeakBytes > need {
			need = *r.MemPeakBytes
		}
		rec := roundUpMi(int64(math.Ceil(need)))
		if rec < MinMemoryBytes {
			rec = MinMemoryBytes
		}
		r.RecMemBytes = &rec
		r.MemVerdict = verdict(r.MemRequestBytes, *r.MemP95Bytes, rec, minMemGapBytes)
		if r.MemLimitBytes != nil && r.MemPeakBytes != nil && *r.MemPeakBytes >= 0.9*float64(*r.MemLimitBytes) {
			r.MemLimitTooTight = true
		}
	}
}

func verdict(req *int64, p95 float64, rec, minGap int64) string {
	switch {
	case req == nil || *req == 0:
		return VerdictNoReq
	case p95 > float64(*req):
		return VerdictUnder
	case float64(*req) >= overFactor*float64(rec) && *req-rec >= minGap:
		return VerdictOver
	default:
		return VerdictFits
	}
}

func rank(r Row) int {
	switch {
	case r.CPUVerdict == VerdictUnder || r.MemVerdict == VerdictUnder || r.MemLimitTooTight:
		return 0
	case r.CPUVerdict == VerdictOver || r.MemVerdict == VerdictOver:
		return 1
	case r.CPUVerdict == VerdictNoReq || r.MemVerdict == VerdictNoReq:
		return 2
	}
	return 3
}

func milli(l corev1.ResourceList, n corev1.ResourceName) *int64 {
	if q, ok := l[n]; ok {
		v := q.MilliValue()
		return &v
	}
	return nil
}

func bytesOf(l corev1.ResourceList, n corev1.ResourceName) *int64 {
	if q, ok := l[n]; ok {
		v := q.Value()
		return &v
	}
	return nil
}

func maxPtr(cur *float64, v float64) *float64 {
	if cur == nil || v > *cur {
		return &v
	}
	return cur
}

func roundUpMi(b int64) int64 {
	const mi = 1 << 20
	return (b + mi - 1) / mi * mi
}

// promDuration renders a window as a PromQL duration, defaulting to seven
// days and capped at fourteen.
func promDuration(d time.Duration) string {
	if d <= 0 {
		d = 7 * 24 * time.Hour
	}
	if d > 14*24*time.Hour {
		d = 14 * 24 * time.Hour
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}
