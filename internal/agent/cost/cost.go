// Package cost computes per-namespace and per-workload spend from the
// metrics OpenCost exports to Prometheus: container allocation priced at
// each node's hourly CPU and RAM rates, persistent-volume cost joined to
// claims, and usage priced the same way for idle-versus-allocated.
//
// The package never talks to Prometheus itself; callers supply a PromQuerier
// backed by the agent's metrics proxy.
//
// Figures are in whatever currency OpenCost was configured with. The package
// neither discovers nor converts it: the caller labels the figures from an
// organisation setting.
//
// An unavailable summary carries Available=false and a Reason and no figures
// at all — never zeros. Within an available summary, a figure that could not
// be measured is nil, not zero.
package cost

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

// Sample is one instant-vector element: its label set and value.
type Sample struct {
	Labels map[string]string
	Value  float64
}

// PromQuerier runs an instant PromQL query and returns the vector it
// produced. A scalar result is returned as one Sample with no labels.
type PromQuerier interface {
	Query(ctx context.Context, promql string) ([]Sample, error)
}

// Unavailability reasons. Each names one real case, so a reader never sees
// a "Prometheus answered" reason for a cluster with no Prometheus at all.
const (
	// ReasonNotConfigured: the agent has no Prometheus to query. Set by the
	// caller, which owns that configuration; this package never sees it.
	ReasonNotConfigured = "not_configured"
	// ReasonUnreachable: a Prometheus is configured, but the query could not
	// be delivered or answered (transport failure, proxy or HTTP error) —
	// the querier's error says so through UnreachableError.
	ReasonUnreachable = "unreachable"
	// ReasonNoMetrics: Prometheus answered, but holds no OpenCost allocation
	// metrics (OpenCost is not installed, or not scraped).
	ReasonNoMetrics = "no_metrics"
	// ReasonQueryError: Prometheus answered the allocation queries (and their
	// fallbacks) with an error.
	ReasonQueryError = "query_error"
	// ReasonInvalidRequest: the caller's arguments were rejected.
	ReasonInvalidRequest = "invalid_request"
)

// UnreachableError is implemented by a querier error meaning Prometheus
// itself could not be reached (as opposed to rejecting the query).
type UnreachableError interface {
	error
	Unreachable() bool
}

// IsUnreachable reports whether err (or anything it wraps) says Prometheus
// could not be reached.
func IsUnreachable(err error) bool {
	var u UnreachableError
	return errors.As(err, &u) && u.Unreachable()
}

// Plain-sentence details for the reasons the caller and this package set.
const (
	DetailNotConfigured = "No Prometheus is connected to this cluster's agent, so OpenCost metrics cannot be read."
	DetailUnreachable   = "A Prometheus is connected to this cluster's agent, but it could not be reached to read OpenCost metrics."
)

// queryFailure maps an allocation query failure to its reason and detail.
func queryFailure(err error, what string) (string, string) {
	if IsUnreachable(err) {
		return ReasonUnreachable, DetailUnreachable
	}
	return ReasonQueryError, what + " could not be queried"
}

// Hourly cost bases.
const (
	// BasisAllocated: TotalHourlyCost is the sum of namespace allocations.
	BasisAllocated = "allocated"
	// BasisNodeCapacity: node cost exceeded the allocations, so
	// TotalHourlyCost is node cost. It then already contains unallocated
	// capacity and does not include storage.
	BasisNodeCapacity = "node_capacity"
)

// Window bounds. Every allocation figure is an hourly rate averaged over the
// window; a longer window smooths more and costs Prometheus more to answer
// inside the tool's time budget.
const (
	DefaultWindow = time.Hour
	MinWindow     = 10 * time.Minute
	MaxWindow     = 24 * time.Hour
)

// MaxNamespaces caps the namespace rows; the most expensive are kept.
const MaxNamespaces = 200

// CostSummary is the cluster's hourly spend broken down by namespace.
type CostSummary struct {
	Available bool   `json:"available"`
	Reason    string `json:"reason,omitempty"`
	// Detail says what failed, for a Reason that needs it.
	Detail string `json:"detail,omitempty"`
	Window string `json:"window,omitempty"`
	// Source is where the figures came from: "opencost" (Prometheus) or
	// "kubecost" (its allocation API). Empty from older agents means OpenCost.
	Source string `json:"source,omitempty"`
	// Trend is the cluster's hourly spend over the last 7 days, where the
	// source keeps that history; absent otherwise, never zero-filled.
	Trend []TrendPoint `json:"trend,omitempty"`

	TotalHourlyCost *float64 `json:"totalHourlyCost,omitempty"`
	HourlyCostBasis string   `json:"hourlyCostBasis,omitempty"`
	// TotalAllocatedCost is the sum of the namespace rows (compute plus
	// storage). TotalHourlyCost equals it unless the basis is node_capacity.
	TotalAllocatedCost *float64 `json:"totalAllocatedCost,omitempty"`
	TotalNodeCost      *float64 `json:"totalNodeCost,omitempty"`
	TotalStorageCost   *float64 `json:"totalStorageCost,omitempty"`
	// TotalIdleCost is requested-but-unused compute across the namespaces
	// whose usage was measured, netted at cluster level.
	TotalIdleCost *float64 `json:"totalIdleCost,omitempty"`
	// TotalUnusedRequestCost is the same summed per namespace, so one
	// namespace's overuse does not cancel another's waste.
	TotalUnusedRequestCost *float64 `json:"totalUnusedRequestCost,omitempty"`
	// TotalUnallocatedCost is node capacity no workload requested. Nil when
	// node cost is unknown, an allocation family is missing, or the nodes may
	// carry GPU spend the allocation metrics do not cover.
	TotalUnallocatedCost *float64 `json:"totalUnallocatedCost,omitempty"`
	// ClusterEfficiency is usage/allocation in percent over measured rows.
	ClusterEfficiency *float64 `json:"clusterEfficiency,omitempty"`

	Namespaces      []NamespaceCost `json:"namespaces,omitempty"`
	TotalNamespaces int             `json:"totalNamespaces,omitempty"`
	Truncated       bool            `json:"truncated,omitempty"`
	// Missing names enrichment queries that failed; their figures are nil.
	Missing []string `json:"missing,omitempty"`
}

// NamespaceCost is one namespace's hourly spend.
type NamespaceCost struct {
	Name       string  `json:"name"`
	HourlyCost float64 `json:"hourlyCost"`
	CPUCost    float64 `json:"cpuCost"`
	MemoryCost float64 `json:"memoryCost"`
	// StorageCost is nil when the storage query failed.
	StorageCost *float64 `json:"storageCost,omitempty"`
	// Usage-derived figures are nil when either usage query failed or did not
	// report this namespace: a namespace nobody measured is not one that used
	// nothing.
	CPUUsageCost    *float64 `json:"cpuUsageCost,omitempty"`
	MemoryUsageCost *float64 `json:"memoryUsageCost,omitempty"`
	Efficiency      *float64 `json:"efficiency,omitempty"`
	IdleCost        *float64 `json:"idleCost,omitempty"`
}

func unavailable(reason, detail string) *CostSummary {
	return &CostSummary{Available: false, Reason: reason, Detail: detail}
}

// promWindow renders a duration as whole seconds, which is always valid
// PromQL (time.Duration's "1h0m0s" is not), after clamping it to the bounds.
func promWindow(d time.Duration) string {
	switch {
	case d <= 0:
		d = DefaultWindow
	case d < MinWindow:
		d = MinWindow
	case d > MaxWindow:
		d = MaxWindow
	}
	return fmt.Sprintf("%ds", int(d/time.Second))
}

// ComputeSummary reads OpenCost allocation, usage, storage and node-cost
// metrics and assembles the namespace breakdown.
//
// CPU and memory allocation are required; each falls back to OpenCost's
// cumulative opencost_container_*_cost_total counters when the allocation
// form fails. If both forms fail the summary is unavailable with
// ReasonUnreachable (Prometheus could not be reached) or ReasonQueryError
// (it rejected the queries); if they succeed with no series it is ReasonNoMetrics.
// Usage, storage and node cost are enrichments: a failure is named in
// Missing and leaves its figures nil.
func ComputeSummary(ctx context.Context, q PromQuerier, window time.Duration) *CostSummary {
	w := promWindow(window)

	cpu, err := queryWithFallback(ctx, q, cpuAllocationQuery(w), cpuCostFallbackQuery(w))
	if err != nil {
		return unavailable(queryFailure(err, "CPU allocation cost"))
	}
	mem, err := queryWithFallback(ctx, q, memAllocationQuery(w), memCostFallbackQuery(w))
	if err != nil {
		return unavailable(queryFailure(err, "memory allocation cost"))
	}
	if len(cpu) == 0 && len(mem) == 0 {
		return unavailable(ReasonNoMetrics, "Prometheus holds no OpenCost allocation metrics (container_cpu_allocation, container_memory_allocation_bytes or opencost_container_*_cost_total)")
	}

	out := &CostSummary{Available: true, Window: w, Source: "opencost"}

	cpuUsage, cpuUsageErr := q.Query(ctx, cpuUsageQuery(w))
	memUsage, memUsageErr := q.Query(ctx, memUsageQuery())
	if cpuUsageErr != nil {
		out.Missing = append(out.Missing, "CPU usage")
	}
	if memUsageErr != nil {
		out.Missing = append(out.Missing, "memory usage")
	}
	storage, storageErr := q.Query(ctx, storageQuery())
	if storageErr != nil {
		out.Missing = append(out.Missing, "storage cost")
	}
	cpuUsageMap := valuePerLabel(cpuUsage, cpuUsageErr, "namespace")
	memUsageMap := valuePerLabel(memUsage, memUsageErr, "namespace")
	storageMap := valuePerLabel(storage, storageErr, "namespace")

	type row struct {
		cpu, mem float64
	}
	rows := make(map[string]*row)
	for _, s := range cpu {
		if ns := s.Labels["namespace"]; ns != "" {
			if rows[ns] == nil {
				rows[ns] = &row{}
			}
			rows[ns].cpu = finite(s.Value)
		}
	}
	for _, s := range mem {
		if ns := s.Labels["namespace"]; ns != "" {
			if rows[ns] == nil {
				rows[ns] = &row{}
			}
			rows[ns].mem = finite(s.Value)
		}
	}

	var totalHourly, totalStorage, totalUsage, totalAllocMeasured, computeAlloc, unusedRequest float64
	usageRows := 0
	namespaces := make([]NamespaceCost, 0, len(rows))
	for name, r := range rows {
		nc := NamespaceCost{Name: name, CPUCost: r.cpu, MemoryCost: r.mem, HourlyCost: r.cpu + r.mem}
		if storageErr == nil {
			// The storage query succeeded, so a namespace absent from it has no
			// priced volumes.
			s := finite(storageMap[name].value)
			nc.StorageCost = &s
			nc.HourlyCost += s
			totalStorage += s
		}
		allocCost := r.cpu + r.mem
		computeAlloc += allocCost

		cu, cpuMeasured := cpuUsageMap[name]
		mu, memMeasured := memUsageMap[name]
		// Presence in both usage results is what separates "used nothing" from
		// "was never measured"; a namespace that used nothing still has a
		// series carrying 0. Partial evidence understates use, so it counts as
		// unmeasured.
		if cpuMeasured && memMeasured {
			cuv, muv := finite(cu.value), finite(mu.value)
			usageCost := cuv + muv
			idle := idleFromUsage(usageCost, allocCost)
			eff := efficiencyPercent(usageCost, allocCost)
			nc.CPUUsageCost, nc.MemoryUsageCost = &cuv, &muv
			nc.IdleCost, nc.Efficiency = &idle, &eff
			totalAllocMeasured += allocCost
			totalUsage += usageCost
			unusedRequest += idle
			usageRows++
		}
		totalHourly += nc.HourlyCost
		namespaces = append(namespaces, nc)
	}

	allocated := totalHourly
	out.TotalAllocatedCost = roundedPtr(allocated)
	out.HourlyCostBasis = BasisAllocated
	if storageErr == nil {
		out.TotalStorageCost = roundedPtr(totalStorage)
	}

	nodeSamples, nodeErr := q.Query(ctx, nodeTotalQuery())
	switch {
	case nodeErr != nil:
		out.Missing = append(out.Missing, "node cost")
	case len(nodeSamples) > 0 && isFinite(nodeSamples[0].Value):
		nodeCost := nodeSamples[0].Value
		out.TotalNodeCost = roundedPtr(nodeCost)
		// Node cost includes GPU spend the CPU and memory allocation does not,
		// so on GPU nodes the difference would report allocated GPUs as
		// unallocated; a missing allocation family would be subtracted as zero.
		// Price rounding can put allocation slightly above node cost, hence the
		// clamp.
		if len(cpu) > 0 && len(mem) > 0 && !mayHaveGPUCost(ctx, q) {
			out.TotalUnallocatedCost = roundedPtr(max(nodeCost-computeAlloc, 0))
		}
		if nodeCost > totalHourly {
			totalHourly = nodeCost
			out.HourlyCostBasis = BasisNodeCapacity
		}
	}
	out.TotalHourlyCost = roundedPtr(totalHourly)

	if usageRows > 0 {
		eff := efficiencyPercent(totalUsage, totalAllocMeasured)
		out.ClusterEfficiency = &eff
		out.TotalIdleCost = roundedPtr(idleFromUsage(totalUsage, totalAllocMeasured))
		out.TotalUnusedRequestCost = roundedPtr(unusedRequest)
	}

	for i := range namespaces {
		roundNamespace(&namespaces[i])
	}
	sort.Slice(namespaces, func(i, j int) bool {
		if namespaces[i].HourlyCost != namespaces[j].HourlyCost {
			return namespaces[i].HourlyCost > namespaces[j].HourlyCost
		}
		return namespaces[i].Name < namespaces[j].Name
	})
	out.TotalNamespaces = len(namespaces)
	if len(namespaces) > MaxNamespaces {
		namespaces = namespaces[:MaxNamespaces]
		out.Truncated = true
	}
	out.Namespaces = namespaces
	return out
}

// queryWithFallback runs primary, and fallback only if primary errors.
func queryWithFallback(ctx context.Context, q PromQuerier, primary, fallback string) ([]Sample, error) {
	samples, err := q.Query(ctx, primary)
	if err == nil {
		return samples, nil
	}
	return q.Query(ctx, fallback)
}

// mayHaveGPUCost reports whether node cost may carry GPU spend. Only an
// explicit zero rules it out: a failed query, or an empty result because
// OpenCost was configured not to emit GPU metrics, leaves it unknown.
func mayHaveGPUCost(ctx context.Context, q PromQuerier) bool {
	samples, err := q.Query(ctx, nodeGPUHourlyCostExpr)
	if err != nil || len(samples) == 0 {
		return true
	}
	return samples[0].Value != 0
}

type measured struct{ value float64 }

// valuePerLabel indexes samples by one label. Absence from the map means
// "not reported", which callers must keep distinct from a reported zero.
func valuePerLabel(samples []Sample, err error, label string) map[string]measured {
	out := make(map[string]measured)
	if err != nil {
		return out
	}
	for _, s := range samples {
		if v := s.Labels[label]; v != "" {
			out[v] = measured{value: s.Value}
		}
	}
	return out
}

func roundNamespace(nc *NamespaceCost) {
	nc.HourlyCost = roundTo(nc.HourlyCost, 4)
	nc.CPUCost = roundTo(nc.CPUCost, 4)
	nc.MemoryCost = roundTo(nc.MemoryCost, 4)
	for _, p := range []*float64{nc.StorageCost, nc.CPUUsageCost, nc.MemoryUsageCost, nc.IdleCost} {
		if p != nil {
			*p = roundTo(*p, 4)
		}
	}
}

// efficiencyPercent returns 100 * usage / alloc rounded to one decimal and
// clamped to [0, 100]. Callers only invoke it with measured usage, so a zero
// here is a measured zero.
func efficiencyPercent(usage, alloc float64) float64 {
	if usage <= 0 || alloc <= 0 {
		return 0
	}
	return math.Min(roundTo(usage/alloc*100, 1), 100)
}

// idleFromUsage is max(alloc - usage, 0).
func idleFromUsage(usage, alloc float64) float64 {
	if alloc <= 0 {
		return 0
	}
	return max(alloc-max(usage, 0), 0)
}

// roundTo rounds to places decimals, mapping NaN and ±Inf to 0.
func roundTo(val float64, places int) float64 {
	if !isFinite(val) {
		return 0
	}
	pow := math.Pow(10, float64(places))
	return math.Round(val*pow) / pow
}

func roundedPtr(v float64) *float64 {
	r := roundTo(v, 4)
	return &r
}

func finite(v float64) float64 {
	if !isFinite(v) {
		return 0
	}
	return v
}

func isFinite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
