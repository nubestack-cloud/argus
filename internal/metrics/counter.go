package metrics

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	"sync"
)

// Counter is a monotonically-increasing value, labeled. Prometheus counters
// are floats (Add accepts a fraction — needed for AnalysisCostUSDTotal,
// which accumulates dollars-and-cents), even though every Inc call in this
// codebase adds exactly 1.
type Counter struct {
	name, help string
	labelNames []string

	mu     sync.Mutex
	values map[string]float64
	labels map[string][]string
}

// NewCounter creates and registers a Counter on DefaultRegistry. Called only
// from package-level var declarations in metrics.go, so there is exactly one
// of each named counter for the lifetime of the process.
func NewCounter(name, help string, labelNames ...string) *Counter {
	c := &Counter{
		name:       name,
		help:       help,
		labelNames: labelNames,
		values:     make(map[string]float64),
		labels:     make(map[string][]string),
	}
	DefaultRegistry.register(c)
	return c
}

// labelValues validates and normalizes vals against c's declared label
// names. A mismatched count is a programming error at the call site (never
// caused by request/cluster/model data — every caller passes fixed Go
// string constants), and this codebase's own convention is to fail loud in
// tests but never crash a live hub over its own instrumentation — so a
// mismatch is logged once and coerced to a fixed, obviously-wrong sentinel
// value rather than panicking or silently mislabeling a different series.
func (c *Counter) labelValues(vals []string) []string {
	if len(vals) != len(c.labelNames) {
		logger.Warn("label value count does not match the metric's declared labels; recording under invalid_labels",
			slog.String("metric", c.name), slog.Int("got", len(vals)), slog.Int("want", len(c.labelNames)),
			slog.String("labels", strings.Join(c.labelNames, ",")))
		out := make([]string, len(c.labelNames))
		for i := range out {
			out[i] = "invalid_labels"
		}
		return out
	}
	return vals
}

// Inc increments the series identified by labelValues by 1. labelValues must
// be given in the same order as NewCounter's labelNames.
func (c *Counter) Inc(labelValues ...string) {
	c.Add(1, labelValues...)
}

// Add increments the series identified by labelValues by delta, which must
// be non-negative — a Prometheus counter that ever decreases is invalid
// exposition (Prometheus's own rate()/increase() assume monotonicity and
// treat a decrease as a reset), so a negative delta is dropped and logged
// rather than silently corrupting the series.
func (c *Counter) Add(delta float64, labelValues ...string) {
	if delta < 0 {
		logger.Warn("dropped a negative Add; a counter must never decrease",
			slog.String("metric", c.name), slog.Float64("delta", delta))
		return
	}
	vals := c.labelValues(labelValues)
	key := labelKey(vals)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.values[key] += delta
	if _, ok := c.labels[key]; !ok {
		c.labels[key] = vals
	}
}

func (c *Counter) writeExposition(w io.Writer) {
	c.mu.Lock()
	keys := sortedSeriesKeys(c.labels)
	type snapshot struct {
		labels []string
		value  float64
	}
	snaps := make([]snapshot, 0, len(keys))
	for _, k := range keys {
		snaps = append(snaps, snapshot{labels: c.labels[k], value: c.values[k]})
	}
	c.mu.Unlock()

	if len(snaps) == 0 {
		// Never a fabricated zero series — see this package's own doc
		// comment and each metric's comment in metrics.go. A counter with
		// no observations yet is simply ABSENT from the scrape, which is
		// what Prometheus expects for a metric that hasn't fired: an absent
		// series and a zero series mean different things to rate()/absent().
		return
	}

	writeHelpAndType(w, c.name, c.help, "counter")
	for _, s := range snaps {
		writeSeriesLine(w, c.name, c.labelNames, s.labels, formatFloat(s.value))
	}
}

// writeSeriesLine writes one `name{k="v",...} value` exposition line —
// shared by Counter and Gauge (Histogram writes its own multi-line shape).
func writeSeriesLine(w io.Writer, name string, labelNames, labelValues []string, value string) {
	if len(labelNames) == 0 {
		fmt.Fprintf(w, "%s %s\n", name, value)
		return
	}
	fmt.Fprintf(w, "%s{%s} %s\n", name, formatLabels(labelNames, labelValues), value)
}

// formatLabels renders labelNames/labelValues as `k1="v1",k2="v2"`.
func formatLabels(labelNames, labelValues []string) string {
	out := ""
	for i, n := range labelNames {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf("%s=\"%s\"", n, escapeLabelValue(labelValues[i]))
	}
	return out
}
