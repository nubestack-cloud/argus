package metrics

import (
	"io"
	"log/slog"
	"strings"

	"sync"
)

// Gauge is a point-in-time value, labeled, that can move in either
// direction.
//
// # Never a fabricated zero
//
// A series only appears in this Gauge's exposition once Set has been called
// for it at least once. That is the whole mechanism behind this package's
// "a collection failure must not surface as a zero" requirement
// (PROJECT.md T11): every DB-backed gauge in metrics.go (IncidentsByState,
// ClustersByState) is updated by a refresh function that calls Set for each
// known label value ONLY after its query has actually succeeded — see
// internal/orchestrator.RefreshIncidentStateMetrics and
// internal/gateway.HealthMonitor's own sweep for where that happens. If a
// refresh fails, it skips every Set call for that round and the gauge is
// left holding whatever it last successfully observed (stale, and
// honestly so — never silently reset to 0), while
// CollectorFailuresTotal/CollectorLastSuccessTimestampSeconds (this
// package's own meta-metrics, see metrics.go) record that the failure
// happened, so an alert rule can catch a gauge that has gone stale rather
// than trusting its last value forever.
type Gauge struct {
	name, help string
	labelNames []string

	mu     sync.Mutex
	values map[string]float64
	labels map[string][]string
}

// NewGauge creates and registers a Gauge on DefaultRegistry.
func NewGauge(name, help string, labelNames ...string) *Gauge {
	g := &Gauge{
		name:       name,
		help:       help,
		labelNames: labelNames,
		values:     make(map[string]float64),
		labels:     make(map[string][]string),
	}
	DefaultRegistry.register(g)
	return g
}

func (g *Gauge) labelValues(vals []string) []string {
	if len(vals) != len(g.labelNames) {
		logger.Warn("label value count does not match the metric's declared labels; recording under invalid_labels",
			slog.String("metric", g.name), slog.Int("got", len(vals)), slog.Int("want", len(g.labelNames)),
			slog.String("labels", strings.Join(g.labelNames, ",")))
		out := make([]string, len(g.labelNames))
		for i := range out {
			out[i] = "invalid_labels"
		}
		return out
	}
	return vals
}

// Set records value for the series identified by labelValues, overwriting
// whatever was there before.
func (g *Gauge) Set(value float64, labelValues ...string) {
	vals := g.labelValues(labelValues)
	key := labelKey(vals)

	g.mu.Lock()
	defer g.mu.Unlock()
	g.values[key] = value
	g.labels[key] = vals
}

// Inc/Dec are the in-memory counterparts NewGauge's live, no-DB-query gauges
// use (TunnelConnectionsActive, FindingProcessingInflight) — a running
// process always knows these exactly, so there is no "collection failure"
// case for them at all: Inc/Dec can never disagree with reality the way a
// periodic DB refresh could.
func (g *Gauge) Inc(labelValues ...string) { g.Add(1, labelValues...) }
func (g *Gauge) Dec(labelValues ...string) { g.Add(-1, labelValues...) }

func (g *Gauge) Add(delta float64, labelValues ...string) {
	vals := g.labelValues(labelValues)
	key := labelKey(vals)

	g.mu.Lock()
	defer g.mu.Unlock()
	g.values[key] += delta
	g.labels[key] = vals
}

func (g *Gauge) writeExposition(w io.Writer) {
	g.mu.Lock()
	keys := sortedSeriesKeys(g.labels)
	type snapshot struct {
		labels []string
		value  float64
	}
	snaps := make([]snapshot, 0, len(keys))
	for _, k := range keys {
		snaps = append(snaps, snapshot{labels: g.labels[k], value: g.values[k]})
	}
	g.mu.Unlock()

	if len(snaps) == 0 {
		// Absent, not zero — see this type's own doc comment.
		return
	}

	writeHelpAndType(w, g.name, g.help, "gauge")
	for _, s := range snaps {
		writeSeriesLine(w, g.name, g.labelNames, s.labels, formatFloat(s.value))
	}
}

// Series is one labeled observation, for ReplaceSeries.
type Series struct {
	// Labels are in the same order as the Gauge's declared labelNames.
	Labels []string
	Value  float64
}

// ReplaceSeries atomically replaces EVERY series this gauge holds with the
// given set.
//
// This exists for the per-entity gauges PROJECT.md T24 added (ClusterState,
// ClusterLastHeartbeatTimestampSeconds — one series per cluster). Set alone
// is wrong for those: a cluster that is decommissioned, archived out of the
// query, or deleted would keep reporting its last observed value forever,
// and "cluster cl_x has been Disconnected for six weeks" would keep paging
// somebody about a cluster that no longer exists. A gauge keyed on an
// entity that can disappear has to be able to forget.
//
// The "never a fabricated zero" rule (see this type's doc comment) is
// unchanged and is the caller's responsibility in exactly the same way:
// call this ONLY after the query that produced the full set has actually
// succeeded. On a failed refresh, call nothing — the gauge then holds its
// last successful snapshot, stale and honestly so, with
// CollectorFailuresTotal/CollectorLastSuccessTimestampSeconds recording
// that collection is broken.
//
// Passing an empty slice is meaningful and allowed: a fleet with no
// clusters in it makes every series of this gauge legitimately absent.
func (g *Gauge) ReplaceSeries(series []Series) {
	values := make(map[string]float64, len(series))
	labels := make(map[string][]string, len(series))
	for _, s := range series {
		vals := g.labelValues(s.Labels)
		key := labelKey(vals)
		values[key] = s.Value
		labels[key] = vals
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	g.values = values
	g.labels = labels
}
