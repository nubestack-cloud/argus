package metrics

import (
	"context"
	"runtime"
	"sync"
	"time"
)

// This file holds the small amount of logic that sits between a raw source
// (pgxpool's Stat, the Go runtime, a sweeper's stopwatch) and the metric
// declarations in metrics.go. It deliberately declares no metric names of
// its own — metrics.go stays the one place a name and its label set can be
// reviewed.

// ---------------------------------------------------------------- labels

// clusterStateCodes is the single mapping behind ClusterState's value. See
// that metric's own doc comment for the ordering argument; the names are
// migration 000002's CHECK constraint values verbatim.
var clusterStateCodes = map[string]float64{
	"Active":              0,
	"PendingApproval":     1,
	"Provisioning":        2,
	"Archived":            3,
	"Degraded":            4,
	"IncompatibleVersion": 5,
	"Rejected":            6,
	"Disconnected":        7,
}

// ClusterStateCode maps a cluster lifecycle state to ClusterState's numeric
// value. The second return is false for a state this mapping does not know,
// and the caller must then OMIT that cluster rather than substituting a
// default — a new lifecycle state quietly reported as "Active" (or as the
// worst code) is an alert that lies in one direction or the other.
func ClusterStateCode(state string) (float64, bool) {
	code, ok := clusterStateCodes[state]
	return code, ok
}

// maxToolLabelLen bounds SafeToolLabel. Every real tool name is well under
// this; the bound exists so a bug elsewhere cannot mint a series keyed on
// something long.
const maxToolLabelLen = 48

// SafeToolLabel admits only a short lower_snake_case identifier — the shape
// every tool in the investigation and remediation surface actually has —
// and returns "other" for anything else.
//
// The name reaching gateway.CallTool has already been allowlisted
// server-side (non-negotiable 3: the tool loop checks a model-chosen name
// against the real list before dispatch, in both backends). This is not a
// second authorization check and must not be mistaken for one. It is a
// cardinality and exposition-format guard: a metric label is the wrong
// place to inherit a safety property from code two packages away, and an
// unbounded label value is how a scrape target turns into an incident.
func SafeToolLabel(tool string) string {
	if tool == "" || len(tool) > maxToolLabelLen {
		return "other"
	}
	for i := 0; i < len(tool); i++ {
		c := tool[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_':
		default:
			return "other"
		}
	}
	return tool
}

// -------------------------------------------------------------- sweepers

// ObserveSweeperRun records one background sweeper run: its duration always,
// and its completion time only when it succeeded.
//
// The last-success gauge is deliberately NOT set on a failed run — its
// entire purpose is that an alert on its age fires when a sweeper stops
// making progress, and a sweeper that ticks every 30 seconds and fails
// every time is exactly that case. sweeper is a short fixed name from each
// Run loop's own call site.
func ObserveSweeperRun(sweeper string, d time.Duration, err error) {
	outcome := "success"
	if err != nil {
		outcome = "error"
	}
	SweeperRunDurationSeconds.Observe(d.Seconds(), sweeper, outcome)
	if err == nil {
		SweeperLastSuccessTimestampSeconds.Set(float64(time.Now().Unix()), sweeper)
	}
}

// ------------------------------------------------------------ tool calls

// Tool-call outcomes. A closed set, chosen here rather than at the call
// site so the two callers that classify an error cannot drift apart.
const (
	ToolOutcomeSuccess = "success"
	// ToolOutcomeNotConnected is the cluster having no live tunnel at all —
	// distinct from an error, because it says nothing about the agent's or
	// the cluster's health, only that this hub replica does not hold that
	// cluster's session.
	ToolOutcomeNotConnected = "not_connected"
	// ToolOutcomeTimeout is the agent never answering within the tunnel's
	// own tool-call timeout. Kept apart from a plain error because it is
	// the one outcome that leaves a MUTATION indeterminate — see
	// internal/execution's resolveIndeterminateOutcome.
	ToolOutcomeTimeout = "timeout"
	ToolOutcomeError   = "error"
)

// ObserveToolCall records one tunnel tool call. tool is passed through
// SafeToolLabel here rather than at the call site, so no caller can forget.
func ObserveToolCall(tool, outcome string, d time.Duration) {
	label := SafeToolLabel(tool)
	ToolCallDurationSeconds.Observe(d.Seconds(), label, outcome)
	ToolCallsTotal.Inc(label, outcome)
}

// --------------------------------------------------------- process/pool

// DBPoolStat is the subset of pgxpool.Stat these metrics report.
//
// A struct of plain numbers rather than *pgxpool.Stat so this package keeps
// importing nothing outside the standard library — the whole argument for
// hand-rolling this exposition (see the package doc comment) is that it
// adds no dependency, and taking pgx here for one accessor type would be a
// small, avoidable step back from that. cmd/hub adapts data.DB.Stat() into
// this.
type DBPoolStat struct {
	MaxConns          int32
	TotalConns        int32
	IdleConns         int32
	AcquiredConns     int32
	ConstructingConns int32

	// The four cumulative counters. pgxpool reports these as
	// process-lifetime totals; RefreshDBPoolMetrics converts them to
	// Prometheus counter increments (see cumulative below), because
	// re-Setting a counter is not something a Counter permits and a Gauge
	// holding a monotonic total would be the wrong TYPE for rate().
	AcquireCount         int64
	EmptyAcquireCount    int64
	CanceledAcquireCount int64
	AcquireDuration      time.Duration
}

// cumulative tracks the previous reading of each pool counter so a
// process-lifetime total can be turned into the delta a Prometheus counter
// wants. Guarded because the process collector is one goroutine but nothing
// stops a future second caller.
var cumulative struct {
	mu       sync.Mutex
	acquire  int64
	empty    int64
	canceled int64
	waitNs   int64
	gcCycles uint32
}

// delta returns v - prev and updates prev, clamping a decrease to zero. A
// decrease cannot happen for a pool counter within one process's lifetime,
// but a Counter that ever goes backwards is invalid exposition, so the
// clamp makes the impossible case fail harmlessly rather than being dropped
// with a log line on every tick.
func delta(prev *int64, v int64) float64 {
	if v < *prev {
		*prev = v
		return 0
	}
	d := v - *prev
	*prev = v
	return float64(d)
}

// RefreshDBPoolMetrics publishes one reading of the connection pool.
//
// PROJECT.md P15 tuned the pool and left data.DB.Stat with nothing
// consuming it, saying in that method's own doc comment that T24 is where
// it becomes a metric. This is that call.
func RefreshDBPoolMetrics(s DBPoolStat) {
	DBPoolConnections.Set(float64(s.TotalConns), "total")
	DBPoolConnections.Set(float64(s.IdleConns), "idle")
	DBPoolConnections.Set(float64(s.AcquiredConns), "acquired")
	DBPoolConnections.Set(float64(s.ConstructingConns), "constructing")
	DBPoolMaxConnections.Set(float64(s.MaxConns))

	cumulative.mu.Lock()
	defer cumulative.mu.Unlock()
	DBPoolAcquireTotal.Add(delta(&cumulative.acquire, s.AcquireCount))
	DBPoolEmptyAcquireTotal.Add(delta(&cumulative.empty, s.EmptyAcquireCount))
	DBPoolCanceledAcquireTotal.Add(delta(&cumulative.canceled, s.CanceledAcquireCount))
	DBPoolAcquireWaitSecondsTotal.Add(delta(&cumulative.waitNs, int64(s.AcquireDuration)) / float64(time.Second))
}

// RefreshRuntimeMetrics publishes one reading of this process's goroutine
// count and heap. runtime.ReadMemStats briefly stops the world, which is
// why this is on the collector's own bounded tick rather than computed per
// scrape — a scrape interval is the operator's to choose, and a 1-second
// scrape must not be able to make the hub pause 60 times a minute.
func RefreshRuntimeMetrics() {
	GoGoroutines.Set(float64(runtime.NumGoroutine()))

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	GoHeapAllocBytes.Set(float64(ms.HeapAlloc))
	GoHeapInuseBytes.Set(float64(ms.HeapInuse))
	GoMemstatsSysBytes.Set(float64(ms.Sys))

	cumulative.mu.Lock()
	defer cumulative.mu.Unlock()
	if ms.NumGC >= cumulative.gcCycles {
		GoGCCyclesTotal.Add(float64(ms.NumGC - cumulative.gcCycles))
	}
	cumulative.gcCycles = ms.NumGC
}

// DefaultProcessCollectInterval is how often RunProcessCollector samples.
// 15s is a common Prometheus scrape interval, so a scrape sees at most one
// stale reading; sampling faster would pay for ReadMemStats' stop-the-world
// more often than anything could observe.
const DefaultProcessCollectInterval = 15 * time.Second

// RunProcessCollector ticks until ctx is cancelled, refreshing the runtime
// and connection-pool metrics. Blocks — cmd/hub runs it under startWorker
// like every other background loop, so the shutdown drain waits for it.
//
// poolStat may be nil in a build with no database (there is none today);
// the runtime half still runs. Unlike the DB-backed collectors in
// internal/orchestrator and internal/gateway, neither source here can fail
// — both are in-process reads — so there is no RecordCollectionFailure path
// and no "stale gauge" hazard to meta-monitor.
func RunProcessCollector(ctx context.Context, interval time.Duration, poolStat func() DBPoolStat) {
	if interval <= 0 {
		interval = DefaultProcessCollectInterval
	}
	collect := func() {
		RefreshRuntimeMetrics()
		if poolStat != nil {
			RefreshDBPoolMetrics(poolStat())
		}
	}
	// Once immediately: a hub that has just started should not have an
	// absent heap metric for the first 15 seconds, which is exactly the
	// window in which somebody watching a restart is looking at it.
	collect()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			collect()
		}
	}
}
