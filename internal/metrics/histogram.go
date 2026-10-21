package metrics

import (
	"fmt"
	"io"
	"log/slog"
	"strings"

	"sort"
	"sync"
)

// Histogram observes a distribution, labeled, as cumulative bucket counts —
// the standard Prometheus histogram shape (`_bucket{le="..."}`, `_sum`,
// `_count`), used here for AnalysisDurationSeconds (metrics.go).
type Histogram struct {
	name, help string
	buckets    []float64 // ascending upper bounds, exclusive of +Inf
	labelNames []string

	mu      sync.Mutex
	series  map[string]*histogramSeries
	seriesL map[string][]string
}

type histogramSeries struct {
	// bucketCounts[i] is how many observations were <= buckets[i]. The
	// implicit +Inf bucket is always equal to count, so it is not stored
	// separately.
	bucketCounts []uint64
	sum          float64
	count        uint64
}

// NewHistogram creates and registers a Histogram on DefaultRegistry. buckets
// must be sorted ascending; NewHistogram does not sort them itself so a
// caller error is visible in the source rather than silently corrected.
func NewHistogram(name, help string, buckets []float64, labelNames ...string) *Histogram {
	if !sort.Float64sAreSorted(buckets) {
		// A panic, not a log line: this is a construction-time programmer error
		// and the comment above is explicit that it must be visible in the
		// source rather than silently corrected. Routing it through the logger
		// would stop it crashing, which is the opposite of the intent.
		panic(fmt.Sprintf("metrics: %s: bucket bounds must be given sorted ascending, got %v", name, buckets))
	}
	h := &Histogram{
		name:       name,
		help:       help,
		buckets:    buckets,
		labelNames: labelNames,
		series:     make(map[string]*histogramSeries),
		seriesL:    make(map[string][]string),
	}
	DefaultRegistry.register(h)
	return h
}

func (h *Histogram) labelValues(vals []string) []string {
	if len(vals) != len(h.labelNames) {
		logger.Warn("label value count does not match the metric's declared labels; recording under invalid_labels",
			slog.String("metric", h.name), slog.Int("got", len(vals)), slog.Int("want", len(h.labelNames)),
			slog.String("labels", strings.Join(h.labelNames, ",")))
		out := make([]string, len(h.labelNames))
		for i := range out {
			out[i] = "invalid_labels"
		}
		return out
	}
	return vals
}

// Observe records one sample (seconds, for every histogram this package
// currently declares) against the series identified by labelValues.
func (h *Histogram) Observe(value float64, labelValues ...string) {
	vals := h.labelValues(labelValues)
	key := labelKey(vals)

	h.mu.Lock()
	defer h.mu.Unlock()
	s, ok := h.series[key]
	if !ok {
		s = &histogramSeries{bucketCounts: make([]uint64, len(h.buckets))}
		h.series[key] = s
		h.seriesL[key] = vals
	}
	for i, bound := range h.buckets {
		if value <= bound {
			s.bucketCounts[i]++
		}
	}
	s.sum += value
	s.count++
}

func (h *Histogram) writeExposition(w io.Writer) {
	h.mu.Lock()
	keys := sortedSeriesKeys(h.seriesL)
	type snapshot struct {
		labels []string
		s      histogramSeries
	}
	snaps := make([]snapshot, 0, len(keys))
	for _, k := range keys {
		src := h.series[k]
		cp := histogramSeries{bucketCounts: append([]uint64(nil), src.bucketCounts...), sum: src.sum, count: src.count}
		snaps = append(snaps, snapshot{labels: h.seriesL[k], s: cp})
	}
	h.mu.Unlock()

	if len(snaps) == 0 {
		// Absent, not a zero-observation histogram — same "never fabricate"
		// rule as Counter/Gauge.
		return
	}

	writeHelpAndType(w, h.name, h.help, "histogram")
	for _, snap := range snaps {
		for i, bound := range h.buckets {
			leLabelNames := append(append([]string{}, h.labelNames...), "le")
			leLabelValues := append(append([]string{}, snap.labels...), formatFloat(bound))
			fmt.Fprintf(w, "%s_bucket{%s} %d\n", h.name, formatLabels(leLabelNames, leLabelValues), snap.s.bucketCounts[i])
		}
		leLabelNames := append(append([]string{}, h.labelNames...), "le")
		leLabelValues := append(append([]string{}, snap.labels...), "+Inf")
		fmt.Fprintf(w, "%s_bucket{%s} %d\n", h.name, formatLabels(leLabelNames, leLabelValues), snap.s.count)

		if len(h.labelNames) == 0 {
			fmt.Fprintf(w, "%s_sum %s\n", h.name, formatFloat(snap.s.sum))
			fmt.Fprintf(w, "%s_count %d\n", h.name, snap.s.count)
		} else {
			fmt.Fprintf(w, "%s_sum{%s} %s\n", h.name, formatLabels(h.labelNames, snap.labels), formatFloat(snap.s.sum))
			fmt.Fprintf(w, "%s_count{%s} %d\n", h.name, formatLabels(h.labelNames, snap.labels), snap.s.count)
		}
	}
}
