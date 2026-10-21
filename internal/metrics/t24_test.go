package metrics

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"
)

// This file covers the PROJECT.md T24 additions. The existing
// metrics_test.go covers the exposition format itself; these tests are
// about the three things T24 introduced that could be wrong without the
// format being wrong: a per-entity gauge that has to forget, a label that
// must stay bounded, and a cumulative source that has to become a counter
// delta.

// TestReplaceSeriesForgetsAnEntityThatIsGone is the property the whole
// per-cluster gauge rests on. A cluster that is archived or deleted must
// lose its series — otherwise "cluster cl_gone is Disconnected" keeps
// paging somebody about a cluster that does not exist.
func TestReplaceSeriesForgetsAnEntityThatIsGone(t *testing.T) {
	g := NewGauge("test_replace_series", "help", "cluster_id")

	g.ReplaceSeries([]Series{
		{Labels: []string{"cl_a"}, Value: 0},
		{Labels: []string{"cl_b"}, Value: 7},
	})
	out := exposition(g)
	if !strings.Contains(out, `test_replace_series{cluster_id="cl_a"} 0`) ||
		!strings.Contains(out, `test_replace_series{cluster_id="cl_b"} 7`) {
		t.Fatalf("both clusters should be present:\n%s", out)
	}

	// cl_b is decommissioned; the next successful refresh omits it.
	g.ReplaceSeries([]Series{{Labels: []string{"cl_a"}, Value: 4}})
	out = exposition(g)
	if strings.Contains(out, "cl_b") {
		t.Fatalf("cl_b kept its series after being dropped from the refresh:\n%s", out)
	}
	if !strings.Contains(out, `test_replace_series{cluster_id="cl_a"} 4`) {
		t.Fatalf("cl_a should have been updated to 4:\n%s", out)
	}

	// An empty fleet is a real observation, not a failure: every series
	// goes away rather than freezing.
	g.ReplaceSeries(nil)
	if out := exposition(g); out != "" {
		t.Fatalf("an empty replacement should leave the gauge absent, got:\n%s", out)
	}
}

// TestClusterStateCodeRefusesAnUnknownState — a lifecycle state this build
// does not know must not be silently mapped to a number. The caller omits
// the cluster instead; an alert that quietly reports a new state as
// "Active" (or as the worst code) is an alert that lies.
func TestClusterStateCodeRefusesAnUnknownState(t *testing.T) {
	if _, ok := ClusterStateCode("Active"); !ok {
		t.Fatalf("Active should be a known state")
	}
	if code, ok := ClusterStateCode("SomeFutureState"); ok {
		t.Fatalf("an unknown state mapped to %v instead of being refused", code)
	}
	// Severity ordering is the point of the encoding: an operator writes
	// `argus_cluster_state >= 4` and expects that to mean "not healthy".
	active, _ := ClusterStateCode("Active")
	degraded, _ := ClusterStateCode("Degraded")
	disconnected, _ := ClusterStateCode("Disconnected")
	if !(active < degraded && degraded < disconnected) {
		t.Fatalf("codes are not severity-ordered: Active=%v Degraded=%v Disconnected=%v", active, degraded, disconnected)
	}
}

// TestSafeToolLabelBoundsTheLabel — the tool name reaching gateway.CallTool
// is already server-side allowlisted, but a metric label must not inherit
// a safety property from code two packages away.
func TestSafeToolLabelBoundsTheLabel(t *testing.T) {
	for in, want := range map[string]string{
		"get_events":            "get_events",
		"list_nodeport_alloc2":  "list_nodeport_alloc2",
		"":                      "other",
		"Get-Events":            "other",
		"get events":            "other",
		`get_events"} 1 evil{`:  "other",
		strings.Repeat("a", 49): "other",
	} {
		if got := SafeToolLabel(in); got != want {
			t.Errorf("SafeToolLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestObserveSweeperRunOnlyStampsSuccess — the last-success gauge exists so
// an alert can fire on its AGE. A sweeper that ticks every 30 seconds and
// fails every time must not keep refreshing it.
func TestObserveSweeperRunOnlyStampsSuccess(t *testing.T) {
	before := exposition(SweeperLastSuccessTimestampSeconds)

	ObserveSweeperRun("t24_failing_sweeper", 5*time.Millisecond, errBoom{})
	if got := exposition(SweeperLastSuccessTimestampSeconds); got != before {
		t.Fatalf("a failed run stamped the last-success gauge:\n%s", got)
	}
	if got := exposition(SweeperRunDurationSeconds); !strings.Contains(got, `sweeper="t24_failing_sweeper",outcome="error"`) {
		t.Fatalf("a failed run should still be observed in the duration histogram:\n%s", got)
	}

	ObserveSweeperRun("t24_ok_sweeper", 5*time.Millisecond, nil)
	if got := exposition(SweeperLastSuccessTimestampSeconds); !strings.Contains(got, `sweeper="t24_ok_sweeper"`) {
		t.Fatalf("a successful run should stamp the last-success gauge:\n%s", got)
	}
}

// TestRefreshDBPoolMetricsConvertsCumulativeToDelta — pgxpool reports
// process-lifetime totals; a Prometheus counter wants increments. Feeding
// the total in directly would make rate() report the wrong thing forever
// after the first scrape.
func TestRefreshDBPoolMetricsConvertsCumulativeToDelta(t *testing.T) {
	RefreshDBPoolMetrics(DBPoolStat{MaxConns: 25, TotalConns: 3, IdleConns: 2, AcquiredConns: 1,
		AcquireCount: 100, EmptyAcquireCount: 4, AcquireDuration: 2 * time.Second})
	first := seriesValue(t, exposition(DBPoolAcquireTotal), "argus_db_pool_acquire_total")

	RefreshDBPoolMetrics(DBPoolStat{MaxConns: 25, TotalConns: 3, IdleConns: 2, AcquiredConns: 1,
		AcquireCount: 130, EmptyAcquireCount: 4, AcquireDuration: 2 * time.Second})
	second := seriesValue(t, exposition(DBPoolAcquireTotal), "argus_db_pool_acquire_total")

	if second-first != 30 {
		t.Fatalf("expected the counter to advance by the DELTA (30), advanced by %v", second-first)
	}
	if !strings.Contains(exposition(DBPoolConnections), `argus_db_pool_connections{state="idle"} 2`) {
		t.Fatalf("pool connection states not reported:\n%s", exposition(DBPoolConnections))
	}
}

// TestRefreshRuntimeMetricsReportsSomething — a smoke check that the
// runtime half is wired at all. Asserting a specific goroutine count would
// be asserting the test runner's own scheduling, so this only pins that
// the gauges become present and non-zero.
func TestRefreshRuntimeMetricsReportsSomething(t *testing.T) {
	RefreshRuntimeMetrics()
	for _, g := range []*Gauge{GoGoroutines, GoHeapAllocBytes, GoHeapInuseBytes, GoMemstatsSysBytes} {
		out := exposition(g)
		if out == "" {
			t.Errorf("%s produced no series after a refresh", g.name)
			continue
		}
		if v := seriesValue(t, out, g.name); v <= 0 {
			t.Errorf("%s = %v, want a positive value", g.name, v)
		}
	}
}

type errBoom struct{}

func (errBoom) Error() string { return "boom" }

func exposition(f family) string {
	var buf bytes.Buffer
	f.writeExposition(&buf)
	return buf.String()
}

// seriesValue reads the single unlabeled (or first labeled) value for name.
func seriesValue(t *testing.T, out, name string) float64 {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, name) || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		v, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		return v
	}
	t.Fatalf("no series for %s in:\n%s", name, out)
	return 0
}
