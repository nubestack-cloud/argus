package traffic

import (
	"context"
	"math"
	"regexp"
	"strings"
	"testing"
)

// queryFunc adapts a function to PromQuerier.
type queryFunc func(ctx context.Context, promql string) ([]Sample, error)

func (f queryFunc) Query(ctx context.Context, promql string) ([]Sample, error) { return f(ctx, promql) }

func sample(labels map[string]string, v float64) Sample { return Sample{Labels: labels, Value: v} }

// rawSeries is one per-series rate as Prometheus holds it before any
// aggregation: the full label set the exporter attaches.
type rawSeries struct {
	metric string
	labels map[string]string
	value  float64
}

var sumByRe = regexp.MustCompile(`sum by \(([^)]*)\) \(rate\(([a-z_]+)\{([^}]*)\}`)

// fakeSumBy answers queries by evaluating `sum by (...)` over raw series, so
// a query that groups by fewer labels than its caller keys on returns the
// coarser totals real Prometheus would, instead of whatever a hand-written
// stub said. Equality matchers in the selector filter series; the 5xx regex
// matcher is honoured; `fail` makes any query containing the key error.
func fakeSumBy(raw []rawSeries, fail map[string]error) queryFunc {
	matcherRe := regexp.MustCompile(`([a-z_]+)="([^"]*)"`)
	return func(_ context.Context, query string) ([]Sample, error) {
		for needle, err := range fail {
			if strings.Contains(query, needle) {
				return nil, err
			}
		}
		var out []Sample
		seen := map[string]bool{}
		for _, part := range strings.Split(query, " or ") {
			m := sumByRe.FindStringSubmatch(part)
			if m == nil {
				continue
			}
			var by []string
			for _, l := range strings.Split(m[1], ",") {
				by = append(by, strings.TrimSpace(l))
			}
			metric, selector := m[2], m[3]
			only5xx := strings.Contains(selector, `=~"5.."`)
			eq := matcherRe.FindAllStringSubmatch(selector, -1)

			groups := map[string]*Sample{}
			var order []string
		series:
			for _, r := range raw {
				if r.metric != metric {
					continue
				}
				for _, mm := range eq {
					if mm[1] == "job" {
						continue
					}
					if r.labels[mm[1]] != mm[2] {
						continue series
					}
				}
				if only5xx && !strings.HasPrefix(r.labels["response_code"]+r.labels["http_response_status_code"], "5") {
					continue
				}
				labels := map[string]string{}
				var key []string
				for _, l := range by {
					if v, ok := r.labels[l]; ok {
						labels[l] = v
					}
					key = append(key, r.labels[l])
				}
				k := strings.Join(key, "\x00")
				g, ok := groups[k]
				if !ok {
					g = &Sample{Labels: labels}
					groups[k] = g
					order = append(order, k)
				}
				g.Value += r.value
			}
			for _, k := range order {
				// `or` keeps a right-hand series only when the left lacks its label set.
				if seen[k] {
					continue
				}
				seen[k] = true
				out = append(out, *groups[k])
			}
		}
		return out, nil
	}
}

func approx(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func mustRate(t *testing.T, what string, p *float64) float64 {
	t.Helper()
	if p == nil {
		t.Fatalf("%s = nil, want a measured value", what)
	}
	return *p
}
