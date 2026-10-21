package cost

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"time"
)

// Kubecost as a second cost source (PROJECT.md PG22), read from its
// allocation API (`/model/allocation`, Kubecost 1.x and the 2.x/3.x
// aggregator alike) aggregated by namespace. Figures are converted to hourly
// spend by each row's own minutes, so they sit beside OpenCost's on the same
// scale, still in Kubecost's own currency and never converted.

// KubecostGetter fetches one Kubecost API path.
type KubecostGetter func(ctx context.Context, path string, params url.Values) ([]byte, error)

// TrendPoint is the cluster's total hourly spend at one moment.
type TrendPoint struct {
	Time       time.Time `json:"time"`
	HourlyCost float64   `json:"hourlyCost"`
}

type kubecostAllocation struct {
	Name            string  `json:"name"`
	Minutes         float64 `json:"minutes"`
	CPUCost         float64 `json:"cpuCost"`
	RAMCost         float64 `json:"ramCost"`
	PVCost          float64 `json:"pvCost"`
	TotalCost       float64 `json:"totalCost"`
	TotalEfficiency float64 `json:"totalEfficiency"`
	Window          struct {
		Start time.Time `json:"start"`
	} `json:"window"`
}

func kubecostSets(ctx context.Context, get KubecostGetter, window, step time.Duration, accumulate bool) ([]map[string]kubecostAllocation, error) {
	p := url.Values{}
	p.Set("window", fmt.Sprintf("%dh", int(window.Hours())))
	p.Set("aggregate", "namespace")
	if accumulate {
		p.Set("accumulate", "true")
	} else {
		p.Set("step", fmt.Sprintf("%dh", int(step.Hours())))
	}
	raw, err := get(ctx, "model/allocation", p)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Code    int                             `json:"code"`
		Message string                          `json:"message"`
		Data    []map[string]kubecostAllocation `json:"data"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("decode Kubecost response: %w", err)
	}
	if resp.Code != 0 && resp.Code != 200 {
		return nil, fmt.Errorf("kubecost: %s", resp.Message)
	}
	return resp.Data, nil
}

// FromKubecost is the namespace breakdown over window.
func FromKubecost(ctx context.Context, get KubecostGetter, window time.Duration) *CostSummary {
	if window <= 0 {
		window = DefaultWindow
	}
	if window < time.Hour {
		window = time.Hour
	}
	sets, err := kubecostSets(ctx, get, window, 0, true)
	if err != nil {
		return unavailable(ReasonUnreachable, "Kubecost did not answer: "+err.Error())
	}
	out := &CostSummary{Available: true, Window: fmt.Sprintf("%dh", int(window.Hours())), Source: "kubecost", HourlyCostBasis: "allocation"}
	var total float64
	for _, set := range sets {
		for key, a := range set {
			if key == "__idle__" || key == "__unallocated__" || a.Minutes <= 0 {
				continue
			}
			h := a.Minutes / 60
			pv := a.PVCost / h
			eff := a.TotalEfficiency * 100
			row := NamespaceCost{Name: a.Name, HourlyCost: a.TotalCost / h, CPUCost: a.CPUCost / h, MemoryCost: a.RAMCost / h, StorageCost: &pv}
			if a.TotalEfficiency > 0 {
				row.Efficiency = &eff
			}
			total += row.HourlyCost
			out.Namespaces = append(out.Namespaces, row)
		}
	}
	if len(out.Namespaces) == 0 {
		return unavailable(ReasonNoMetrics, "Kubecost reported no namespace allocations in this window")
	}
	sort.Slice(out.Namespaces, func(i, j int) bool { return out.Namespaces[i].HourlyCost > out.Namespaces[j].HourlyCost })
	out.TotalNamespaces = len(out.Namespaces)
	out.TotalHourlyCost, out.TotalAllocatedCost = &total, &total
	return out
}

// KubecostTrend is the cluster's hourly spend for each step of window.
func KubecostTrend(ctx context.Context, get KubecostGetter, window, step time.Duration) ([]TrendPoint, error) {
	sets, err := kubecostSets(ctx, get, window, step, false)
	if err != nil {
		return nil, err
	}
	var out []TrendPoint
	for _, set := range sets {
		var total float64
		var at time.Time
		for _, a := range set {
			if a.Minutes <= 0 {
				continue
			}
			total += a.TotalCost / (a.Minutes / 60)
			if at.IsZero() || a.Window.Start.Before(at) {
				at = a.Window.Start
			}
		}
		if !at.IsZero() {
			out = append(out, TrendPoint{Time: at, HourlyCost: total})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	return out, nil
}

// OpenCostTrendQuery is the cluster's allocated hourly spend as one series,
// for a range query.
var OpenCostTrendQuery = `sum(container_cpu_allocation * on(node) group_left() ` + nodeCPUHourlyCostExpr + `) + sum(container_memory_allocation_bytes / ` + bytesPerGiB + ` * on(node) group_left() ` + nodeRAMHourlyCostExpr + `)`
