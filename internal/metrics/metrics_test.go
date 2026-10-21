package metrics

import (
	"strings"
	"testing"
)

// TestCounterNeverFabricatesZero pins this package's central safety property
// (PROJECT.md T11: "never fabricate a zero") for Counter: a family with no
// observations must be completely absent from the exposition, not present
// with a value of 0.
func TestCounterNeverFabricatesZero(t *testing.T) {
	c := NewCounter("test_never_zero_counter", "help text", "outcome")
	var buf strings.Builder
	c.writeExposition(&buf)
	if buf.Len() != 0 {
		t.Fatalf("expected no output for an unobserved counter, got %q", buf.String())
	}

	c.Inc("ok")
	buf.Reset()
	c.writeExposition(&buf)
	out := buf.String()
	if !strings.Contains(out, `test_never_zero_counter{outcome="ok"} 1`) {
		t.Fatalf("expected an observed series with value 1, got %q", out)
	}
	// A different, never-observed label value must still not appear.
	if strings.Contains(out, `outcome="dropped"`) {
		t.Fatalf("an unobserved label value must not appear in exposition: %q", out)
	}
}

func TestCounterAddRejectsNegative(t *testing.T) {
	c := NewCounter("test_negative_counter", "help", "outcome")
	c.Add(5, "ok")
	c.Add(-3, "ok") // must be dropped, not applied
	var buf strings.Builder
	c.writeExposition(&buf)
	if !strings.Contains(buf.String(), `test_negative_counter{outcome="ok"} 5`) {
		t.Fatalf("negative Add must be rejected, keeping the counter monotonic: %q", buf.String())
	}
}

func TestGaugeSetOverwritesAndCanDecrease(t *testing.T) {
	g := NewGauge("test_gauge", "help", "state")
	g.Set(3, "Active")
	g.Set(1, "Active")
	var buf strings.Builder
	g.writeExposition(&buf)
	if !strings.Contains(buf.String(), `test_gauge{state="Active"} 1`) {
		t.Fatalf("gauge must reflect the last Set value: %q", buf.String())
	}
}

func TestGaugeAbsentUntilSet(t *testing.T) {
	g := NewGauge("test_gauge_absent", "help", "state")
	var buf strings.Builder
	g.writeExposition(&buf)
	if buf.Len() != 0 {
		t.Fatalf("a gauge with no Set call must be entirely absent, got %q", buf.String())
	}
}

// TestGaugeStaleOnFailedRefresh models exactly how IncidentsByState/
// ClustersByState are used: a caller Sets every known label on a successful
// refresh, and simply does not call Set at all on a failed one — the value
// must survive unchanged, never reset to 0.
func TestGaugeStaleOnFailedRefresh(t *testing.T) {
	g := NewGauge("test_gauge_stale", "help", "state")
	g.Set(7, "Detected")
	// Simulate a failed refresh: no Set call at all this round.
	var buf strings.Builder
	g.writeExposition(&buf)
	if !strings.Contains(buf.String(), `test_gauge_stale{state="Detected"} 7`) {
		t.Fatalf("a gauge must keep its last successfully-collected value when a refresh fails, got %q", buf.String())
	}
}

func TestHistogramBucketsAndSumCount(t *testing.T) {
	h := NewHistogram("test_histogram", "help", []float64{1, 5, 10}, "trigger")
	h.Observe(0.5, "manual")
	h.Observe(3, "manual")
	h.Observe(7, "manual")
	h.Observe(100, "manual")

	var buf strings.Builder
	h.writeExposition(&buf)
	out := buf.String()

	cases := []string{
		`test_histogram_bucket{trigger="manual",le="1"} 1`,
		`test_histogram_bucket{trigger="manual",le="5"} 2`,
		`test_histogram_bucket{trigger="manual",le="10"} 3`,
		`test_histogram_bucket{trigger="manual",le="+Inf"} 4`,
		`test_histogram_sum{trigger="manual"} 110.5`,
		`test_histogram_count{trigger="manual"} 4`,
	}
	for _, want := range cases {
		if !strings.Contains(out, want) {
			t.Errorf("expected exposition to contain %q, got:\n%s", want, out)
		}
	}
}

func TestHistogramAbsentUntilObserved(t *testing.T) {
	h := NewHistogram("test_histogram_absent", "help", []float64{1, 5})
	var buf strings.Builder
	h.writeExposition(&buf)
	if buf.Len() != 0 {
		t.Fatalf("an unobserved histogram must be entirely absent, got %q", buf.String())
	}
}

func TestLabelCountMismatchDoesNotPanic(t *testing.T) {
	c := NewCounter("test_mismatch_counter", "help", "a", "b")
	// Wrong number of label values must not panic — it must be coerced to a
	// visible sentinel and logged, never crash the calling request path.
	c.Inc("only_one")
	var buf strings.Builder
	c.writeExposition(&buf)
	if !strings.Contains(buf.String(), "invalid_labels") {
		t.Fatalf("expected a mismatched label count to be recorded under the invalid_labels sentinel, got %q", buf.String())
	}
}

// TestRegistryWriteExpositionIsParseable is a light sanity check that the
// exposition this package writes has the shape Prometheus's own text-format
// parser expects: HELP/TYPE comment lines, and metric lines of the form
// `name{labels} value` or `name value`, with no blank/malformed lines.
func TestRegistryWriteExpositionIsParseable(t *testing.T) {
	r := &Registry{}
	c := &Counter{name: "argus_test_parseable_total", help: "h", labelNames: []string{"outcome"}, values: map[string]float64{}, labels: map[string][]string{}}
	c.values["ok"] = 2
	c.labels["ok"] = []string{"ok"}
	r.register(c)

	var buf strings.Builder
	r.WriteExposition(&buf)
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	for _, line := range lines {
		if line == "" {
			t.Fatalf("blank line in exposition output")
		}
		if strings.HasPrefix(line, "# HELP") || strings.HasPrefix(line, "# TYPE") {
			continue
		}
		if !strings.Contains(line, " ") {
			t.Fatalf("metric line has no value separator: %q", line)
		}
	}
}
