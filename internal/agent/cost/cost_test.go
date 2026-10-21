package cost

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// scriptedCase answers every query containing a substring. Cases are tried
// in order and the first match wins; a query no case matches gets an empty
// vector, as Prometheus returns for a metric it does not have.
type scriptedCase struct {
	contains string
	samples  []Sample
	err      error
}

type scriptedProm struct {
	cases   []scriptedCase
	queries []string
}

func (p *scriptedProm) Query(_ context.Context, q string) ([]Sample, error) {
	p.queries = append(p.queries, q)
	for _, c := range p.cases {
		if strings.Contains(q, c.contains) {
			return c.samples, c.err
		}
	}
	return nil, nil
}

func scripted(cases ...scriptedCase) *scriptedProm { return &scriptedProm{cases: cases} }

var errBoom = errors.New("bad_data: boom")

func byNamespace(values map[string]float64) []Sample {
	out := make([]Sample, 0, len(values))
	for ns, v := range values {
		out = append(out, Sample{Labels: map[string]string{"namespace": ns}, Value: v})
	}
	return out
}

func scalar(v float64) []Sample { return []Sample{{Labels: map[string]string{}, Value: v}} }

func val(t *testing.T, what string, p *float64) float64 {
	t.Helper()
	if p == nil {
		t.Fatalf("%s = nil, want a measured value", what)
	}
	return *p
}

func rowsByName(s *CostSummary) map[string]NamespaceCost {
	m := map[string]NamespaceCost{}
	for _, r := range s.Namespaces {
		m[r.Name] = r
	}
	return m
}

func TestComputeSummaryHappyPath(t *testing.T) {
	q := scripted(
		scriptedCase{contains: "container_cpu_allocation", samples: byNamespace(map[string]float64{"checkout": 2.0, "payments": 1.0})},
		scriptedCase{contains: "container_memory_allocation_bytes", samples: byNamespace(map[string]float64{"checkout": 3.0, "payments": 0.5})},
		scriptedCase{contains: "container_cpu_usage_seconds_total", samples: byNamespace(map[string]float64{"checkout": 0.8, "payments": 0.6})},
		scriptedCase{contains: "container_memory_working_set_bytes", samples: byNamespace(map[string]float64{"checkout": 1.2, "payments": 0.25})},
		scriptedCase{contains: "pv_hourly_cost", samples: byNamespace(map[string]float64{"checkout": 0.05})},
		scriptedCase{contains: "node_total_hourly_cost", samples: scalar(8.0)}, // exceeds the namespaces, so it wins
		scriptedCase{contains: "node_gpu_count", samples: scalar(0)},
	)
	got := ComputeSummary(context.Background(), q, 0)
	if !got.Available || got.Window != "3600s" {
		t.Fatalf("summary = %+v", got)
	}
	if val(t, "totalHourlyCost", got.TotalHourlyCost) != 8.0 || got.HourlyCostBasis != BasisNodeCapacity {
		t.Errorf("hourly=%v basis=%q, want 8 from node capacity", *got.TotalHourlyCost, got.HourlyCostBasis)
	}
	if val(t, "totalStorageCost", got.TotalStorageCost) != 0.05 {
		t.Errorf("storage=%v, want 0.05", *got.TotalStorageCost)
	}
	// alloc (2+3)+(1+0.5)=6.5; usage (0.8+1.2)+(0.6+0.25)=2.85 → 43.8%
	if e := val(t, "clusterEfficiency", got.ClusterEfficiency); e != 43.8 {
		t.Errorf("clusterEfficiency=%v, want 43.8", e)
	}
	if idle := val(t, "totalIdleCost", got.TotalIdleCost); idle != 3.65 {
		t.Errorf("totalIdleCost=%v, want 3.65", idle)
	}
	// Node cost 8 minus compute allocation 6.5.
	if u := val(t, "totalUnallocatedCost", got.TotalUnallocatedCost); u != 1.5 {
		t.Errorf("unallocated=%v, want 1.5", u)
	}
	if n := val(t, "totalNodeCost", got.TotalNodeCost); n != 8 {
		t.Errorf("node cost=%v, want 8", n)
	}
	if a := val(t, "totalAllocatedCost", got.TotalAllocatedCost); a != 6.55 {
		t.Errorf("allocated=%v, want 6.55", a)
	}
	var rowIdle float64
	for _, r := range got.Namespaces {
		rowIdle += val(t, r.Name+" idle", r.IdleCost)
	}
	if val(t, "unused", got.TotalUnusedRequestCost) != roundTo(rowIdle, 4) {
		t.Errorf("unused request cost=%v, want the rows' sum %v", *got.TotalUnusedRequestCost, rowIdle)
	}
	if len(got.Namespaces) != 2 || got.Namespaces[0].Name != "checkout" || got.Namespaces[0].HourlyCost != 5.05 {
		t.Fatalf("namespaces = %+v, want checkout (5.05) first", got.Namespaces)
	}
	if val(t, "payments storage", got.Namespaces[1].StorageCost) != 0 {
		t.Errorf("payments has no priced volumes, so a measured 0; got %v", *got.Namespaces[1].StorageCost)
	}
	if len(got.Missing) != 0 {
		t.Errorf("missing = %v", got.Missing)
	}
}

func TestComputeSummaryNoMetricsIsUnavailableNotZero(t *testing.T) {
	got := ComputeSummary(context.Background(), scripted(), time.Hour)
	if got.Available || got.Reason != ReasonNoMetrics {
		t.Fatalf("summary = %+v, want unavailable/no_metrics", got)
	}
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"totalHourlyCost", "totalStorageCost", "totalIdleCost", "namespaces"} {
		if strings.Contains(string(b), field) {
			t.Fatalf("unavailable summary carries %s: %s", field, b)
		}
	}
}

func TestComputeSummaryQueryErrorReason(t *testing.T) {
	q := scripted(scriptedCase{contains: "", err: errBoom})
	got := ComputeSummary(context.Background(), q, 0)
	if got.Available || got.Reason != ReasonQueryError || got.TotalHourlyCost != nil {
		t.Fatalf("summary = %+v, want unavailable/query_error with no figures", got)
	}
}

func TestComputeSummaryFallsBackToOpenCostCostCounters(t *testing.T) {
	q := scripted(
		scriptedCase{contains: "container_cpu_allocation", err: errBoom},
		scriptedCase{contains: "opencost_container_cpu_cost_total", samples: byNamespace(map[string]float64{"checkout": 2.0})},
		scriptedCase{contains: "container_memory_allocation_bytes", samples: byNamespace(map[string]float64{"checkout": 1.0})},
	)
	got := ComputeSummary(context.Background(), q, 0)
	if !got.Available || len(got.Namespaces) != 1 || got.Namespaces[0].CPUCost != 2 {
		t.Fatalf("summary = %+v, want the fallback counters used", got)
	}
}

func TestComputeSummaryRoundsValues(t *testing.T) {
	got := ComputeSummary(context.Background(), scripted(
		scriptedCase{contains: "container_cpu_allocation", samples: byNamespace(map[string]float64{"x": 1.123456789})},
		scriptedCase{contains: "container_memory_allocation_bytes", samples: byNamespace(map[string]float64{"x": 2.987654321})},
	), 0)
	nc := got.Namespaces[0]
	if nc.CPUCost != 1.1235 || nc.MemoryCost != 2.9877 {
		t.Fatalf("rounding: cpu=%v mem=%v", nc.CPUCost, nc.MemoryCost)
	}
}

func TestComputeSummaryStorageQueryDedupesBeforeJoining(t *testing.T) {
	q := scripted(
		scriptedCase{contains: "container_cpu_allocation", samples: byNamespace(map[string]float64{"checkout": 1})},
		scriptedCase{contains: "container_memory_allocation_bytes", samples: byNamespace(map[string]float64{"checkout": 1})},
	)
	ComputeSummary(context.Background(), q, 0)
	var storage string
	for _, s := range q.queries {
		if strings.Contains(s, "pv_hourly_cost") {
			storage = s
		}
	}
	for _, want := range []string{
		"max by (persistentvolume) (pv_hourly_cost)",
		"max by (persistentvolume, namespace)",
		`label_replace(kube_persistentvolume_claim_ref, "namespace", "$1", "claim_namespace", "(.+)")`,
	} {
		if !strings.Contains(storage, want) {
			t.Errorf("storage query %q missing %q", storage, want)
		}
	}
}

func TestComputeSummaryWindowReachesTheQueries(t *testing.T) {
	q := scripted(
		scriptedCase{contains: "container_cpu_allocation", samples: byNamespace(map[string]float64{"a": 1})},
		scriptedCase{contains: "container_memory_allocation_bytes", samples: byNamespace(map[string]float64{"a": 1})},
	)
	got := ComputeSummary(context.Background(), q, 6*time.Hour)
	if got.Window != "21600s" || !strings.Contains(q.queries[0], "[21600s]") {
		t.Fatalf("window=%q first query=%q", got.Window, q.queries[0])
	}
	for in, want := range map[time.Duration]string{0: "3600s", time.Minute: "600s", 48 * time.Hour: "86400s"} {
		if got := promWindow(in); got != want {
			t.Errorf("promWindow(%v) = %s, want %s", in, got, want)
		}
	}
}

func TestPartialUsageFailureLeavesUsageUnknown(t *testing.T) {
	got := ComputeSummary(context.Background(), scripted(
		scriptedCase{contains: "container_cpu_allocation", samples: byNamespace(map[string]float64{"checkout": 2.0})},
		scriptedCase{contains: "container_memory_allocation_bytes", samples: byNamespace(map[string]float64{"checkout": 3.0})},
		scriptedCase{contains: "container_cpu_usage_seconds_total", err: errBoom},
		scriptedCase{contains: "container_memory_working_set_bytes", samples: byNamespace(map[string]float64{"checkout": 2.4})},
	), 0)
	row := got.Namespaces[0]
	if row.Efficiency != nil || row.IdleCost != nil || row.CPUUsageCost != nil {
		t.Errorf("row = %+v: efficiency from half the usage evidence would read as measured", row)
	}
	if got.ClusterEfficiency != nil || got.TotalIdleCost != nil {
		t.Errorf("cluster efficiency/idle = %v/%v, want nil: no row was measured", got.ClusterEfficiency, got.TotalIdleCost)
	}
	if row.HourlyCost != 5.0 {
		t.Errorf("hourlyCost=%v, want 5 — allocation is independent of usage", row.HourlyCost)
	}
	if strings.Join(got.Missing, ",") != "CPU usage" {
		t.Errorf("missing = %v", got.Missing)
	}
}

func TestUnmeasuredNamespaceIsUnknownMeasuredZeroIsNot(t *testing.T) {
	got := ComputeSummary(context.Background(), scripted(
		scriptedCase{contains: "container_cpu_allocation", samples: byNamespace(map[string]float64{"measured": 2.0, "unmeasured": 2.0})},
		scriptedCase{contains: "container_memory_allocation_bytes", samples: byNamespace(map[string]float64{"measured": 1.0, "unmeasured": 1.0})},
		scriptedCase{contains: "container_cpu_usage_seconds_total", samples: byNamespace(map[string]float64{"measured": 0})},
		scriptedCase{contains: "container_memory_working_set_bytes", samples: byNamespace(map[string]float64{"measured": 0})},
	), 0)
	rows := rowsByName(got)
	m := rows["measured"]
	if val(t, "measured efficiency", m.Efficiency) != 0 || val(t, "measured idle", m.IdleCost) != 3 {
		t.Errorf("measured row = %+v: a real zero usage is 0%% efficient and fully idle", m)
	}
	u := rows["unmeasured"]
	if u.Efficiency != nil || u.IdleCost != nil {
		t.Errorf("unmeasured row = %+v: absent from both usage results, so unknown", u)
	}
	// Built only from the measured row: alloc 3, usage 0.
	if val(t, "clusterEfficiency", got.ClusterEfficiency) != 0 || val(t, "totalIdleCost", got.TotalIdleCost) != 3 {
		t.Errorf("cluster eff=%v idle=%v, want 0 / 3 from the measured row alone", *got.ClusterEfficiency, *got.TotalIdleCost)
	}
}

func TestNamespaceMissingFromOneUsageResultIsUnknown(t *testing.T) {
	got := ComputeSummary(context.Background(), scripted(
		scriptedCase{contains: "container_cpu_allocation", samples: byNamespace(map[string]float64{"half": 2.0})},
		scriptedCase{contains: "container_memory_allocation_bytes", samples: byNamespace(map[string]float64{"half": 1.0})},
		scriptedCase{contains: "container_cpu_usage_seconds_total", samples: byNamespace(map[string]float64{"half": 1.0})},
	), 0)
	if got.Namespaces[0].Efficiency != nil {
		t.Fatal("a namespace in only one usage result must not report an efficiency")
	}
}

func TestStorageFailureIsUnknownNotZero(t *testing.T) {
	got := ComputeSummary(context.Background(), scripted(
		scriptedCase{contains: "container_cpu_allocation", samples: byNamespace(map[string]float64{"a": 2.0})},
		scriptedCase{contains: "container_memory_allocation_bytes", samples: byNamespace(map[string]float64{"a": 1.0})},
		scriptedCase{contains: "pv_hourly_cost", err: errBoom},
	), 0)
	if got.TotalStorageCost != nil || got.Namespaces[0].StorageCost != nil {
		t.Fatalf("storage = %v / %v after the storage query failed, want nil", got.TotalStorageCost, got.Namespaces[0].StorageCost)
	}
	if strings.Join(got.Missing, ",") != "storage cost" {
		t.Fatalf("missing = %v", got.Missing)
	}
}

func TestWithoutNodeCostUnallocatedIsUnknown(t *testing.T) {
	got := ComputeSummary(context.Background(), scripted(
		scriptedCase{contains: "container_cpu_allocation", samples: byNamespace(map[string]float64{"checkout": 2.0})},
		scriptedCase{contains: "container_memory_allocation_bytes", samples: byNamespace(map[string]float64{"checkout": 1.0})},
	), 0)
	if got.TotalUnallocatedCost != nil || got.TotalNodeCost != nil {
		t.Errorf("unallocated=%v node=%v, want nil without node cost", got.TotalUnallocatedCost, got.TotalNodeCost)
	}
	if got.HourlyCostBasis != BasisAllocated || *got.TotalHourlyCost != *got.TotalAllocatedCost {
		t.Errorf("basis=%q hourly=%v allocated=%v", got.HourlyCostBasis, *got.TotalHourlyCost, *got.TotalAllocatedCost)
	}
}

func TestUnallocatedClampsAtZero(t *testing.T) {
	got := ComputeSummary(context.Background(), scripted(
		scriptedCase{contains: "container_cpu_allocation", samples: byNamespace(map[string]float64{"checkout": 2.0})},
		scriptedCase{contains: "container_memory_allocation_bytes", samples: byNamespace(map[string]float64{"checkout": 1.0})},
		scriptedCase{contains: "node_total_hourly_cost", samples: scalar(2.9)},
		scriptedCase{contains: "node_gpu_count", samples: scalar(0)},
	), 0)
	if val(t, "unallocated", got.TotalUnallocatedCost) != 0 {
		t.Errorf("unallocated=%v, want 0", *got.TotalUnallocatedCost)
	}
	// Node cost below allocation is still reported, and does not lower the total.
	if *got.TotalNodeCost != 2.9 || *got.TotalHourlyCost != 3 || got.HourlyCostBasis != BasisAllocated {
		t.Errorf("node=%v hourly=%v basis=%q", *got.TotalNodeCost, *got.TotalHourlyCost, got.HourlyCostBasis)
	}
}

func TestUnallocatedUnknownWhenGPUSpendPossible(t *testing.T) {
	base := []scriptedCase{
		{contains: "container_cpu_allocation", samples: byNamespace(map[string]float64{"training": 2.0})},
		{contains: "container_memory_allocation_bytes", samples: byNamespace(map[string]float64{"training": 1.0})},
		{contains: "node_total_hourly_cost", samples: scalar(9.0)},
	}
	for name, gpu := range map[string][]scriptedCase{
		"gpu nodes":          {{contains: "node_gpu_count", samples: scalar(6)}},
		"gpu metrics absent": nil,
		"gpu query failed":   {{contains: "node_gpu_count", err: errBoom}},
	} {
		t.Run(name, func(t *testing.T) {
			got := ComputeSummary(context.Background(), scripted(append(append([]scriptedCase{}, base...), gpu...)...), 0)
			if got.TotalUnallocatedCost != nil {
				t.Errorf("unallocated=%v, want nil", *got.TotalUnallocatedCost)
			}
			if got.HourlyCostBasis != BasisNodeCapacity {
				t.Errorf("basis=%q, want node_capacity", got.HourlyCostBasis)
			}
		})
	}
}

func TestUnallocatedWithheldWhenAnAllocationFamilyIsMissing(t *testing.T) {
	got := ComputeSummary(context.Background(), scripted(
		scriptedCase{contains: "container_cpu_allocation", samples: byNamespace(map[string]float64{"a": 2.0})},
		scriptedCase{contains: "node_total_hourly_cost", samples: scalar(9.0)},
		scriptedCase{contains: "node_gpu_count", samples: scalar(0)},
	), 0)
	if got.TotalUnallocatedCost != nil {
		t.Errorf("unallocated=%v, want nil when memory allocation is absent", *got.TotalUnallocatedCost)
	}
}

func TestUnusedRequestCostDoesNotNetOveruseAgainstWaste(t *testing.T) {
	got := ComputeSummary(context.Background(), scripted(
		scriptedCase{contains: "container_cpu_allocation", samples: byNamespace(map[string]float64{"idle": 4.0, "busy": 1.0})},
		scriptedCase{contains: "container_memory_allocation_bytes", samples: byNamespace(map[string]float64{"idle": 0, "busy": 0})},
		scriptedCase{contains: "container_cpu_usage_seconds_total", samples: byNamespace(map[string]float64{"idle": 1.0, "busy": 4.0})},
		scriptedCase{contains: "container_memory_working_set_bytes", samples: byNamespace(map[string]float64{"idle": 0, "busy": 0})},
	), 0)
	if val(t, "unused", got.TotalUnusedRequestCost) != 3 {
		t.Errorf("unused=%v, want 3 from the idle namespace alone", *got.TotalUnusedRequestCost)
	}
	// The netted figure lets busy's overuse cancel idle's waste: 5 - 5 = 0.
	if val(t, "idle", got.TotalIdleCost) != 0 {
		t.Errorf("netted idle=%v, want 0", *got.TotalIdleCost)
	}
}

func TestNamespacesAreCapped(t *testing.T) {
	values := map[string]float64{}
	for i := 0; i < MaxNamespaces+5; i++ {
		values[string(rune('a'+i%26))+strings.Repeat("x", i/26)] = float64(i)
	}
	got := ComputeSummary(context.Background(), scripted(
		scriptedCase{contains: "container_cpu_allocation", samples: byNamespace(values)},
		scriptedCase{contains: "container_memory_allocation_bytes", samples: byNamespace(values)},
	), 0)
	if !got.Truncated || len(got.Namespaces) != MaxNamespaces || got.TotalNamespaces != MaxNamespaces+5 {
		t.Fatalf("truncated=%v len=%d total=%d", got.Truncated, len(got.Namespaces), got.TotalNamespaces)
	}
	// Totals cover every namespace, not just the rows sent.
	var sent float64
	for _, r := range got.Namespaces {
		sent += r.HourlyCost
	}
	if *got.TotalAllocatedCost <= sent {
		t.Fatalf("allocated %v should exceed the capped rows' %v", *got.TotalAllocatedCost, sent)
	}
}

func TestEfficiencyPercent(t *testing.T) {
	for _, tc := range []struct{ usage, alloc, want float64 }{
		{0, 1, 0}, {1, 0, 0}, {1, 3, 33.3}, {2, 1, 100},
	} {
		if got := efficiencyPercent(tc.usage, tc.alloc); got != tc.want {
			t.Errorf("efficiencyPercent(%v, %v) = %v, want %v", tc.usage, tc.alloc, got, tc.want)
		}
	}
}
