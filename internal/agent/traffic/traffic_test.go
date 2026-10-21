package traffic

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// presenceProm answers count() probes with 1 for the metrics listed.
func presenceProm(present ...string) queryFunc {
	return func(_ context.Context, q string) ([]Sample, error) {
		for _, m := range present {
			if strings.HasPrefix(q, "count("+m) {
				return []Sample{{Value: 1}}, nil
			}
		}
		return nil, nil
	}
}

func TestDetectOrder(t *testing.T) {
	for _, tc := range []struct {
		present []string
		want    string
	}{
		{[]string{"istio_requests_total", beylaFlowMetric}, SourceIstio},
		{[]string{"istio_tcp_connections_opened_total"}, SourceIstio},
		{[]string{beylaFlowMetric, obiFlowMetric}, SourceBeyla},
		{[]string{obiFlowMetric}, SourceOBI},
		{nil, ""},
	} {
		got, ok := Detect(context.Background(), presenceProm(tc.present...))
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("present %v: Detect = %q,%v, want %q", tc.present, got, ok, tc.want)
		}
	}
}

func TestProbeSeparatesPrometheusDownFromAbsent(t *testing.T) {
	down := queryFunc(func(context.Context, string) ([]Sample, error) { return nil, errors.New("connection refused") })
	d := Probe(context.Background(), down)
	if d.Source != "" || d.ReasonCode != ReasonUnreachable || !strings.Contains(d.Reason, "could not be queried") || strings.Contains(d.Reason, "connection refused") {
		t.Fatalf("probe = %+v", d)
	}
	d = Probe(context.Background(), presenceProm())
	if d.Source != "" || d.ReasonCode != ReasonNoSource || !strings.Contains(d.Reason, "No Istio") {
		t.Fatalf("probe = %+v", d)
	}
	// A zero count is not presence.
	zero := queryFunc(func(context.Context, string) ([]Sample, error) { return []Sample{{Value: 0}}, nil })
	if _, ok := Detect(context.Background(), zero); ok {
		t.Fatal("a zero count was taken as presence")
	}
}

func TestFlowsRejectsUnknownSourceAndBadNamespace(t *testing.T) {
	if _, err := Flows(context.Background(), presenceProm(), "linkerd", "", 0); !errors.Is(err, ErrUnknownSource) {
		t.Fatalf("err = %v, want ErrUnknownSource", err)
	}
	if _, err := Flows(context.Background(), presenceProm(), SourceIstio, `x"} or vector(1) #`, 0); err == nil {
		t.Fatal("a namespace that is not a DNS label must be rejected before it reaches PromQL")
	}
}

func TestFlowsCapsEdges(t *testing.T) {
	var samples []Sample
	for i := 0; i < MaxEdges+20; i++ {
		samples = append(samples, sample(map[string]string{
			"source_workload": fmt.Sprintf("s%d", i), "source_workload_namespace": "a",
			"destination_workload": "d", "destination_workload_namespace": "b",
			"request_protocol": "http",
		}, float64(i+1)))
	}
	q := queryFunc(func(_ context.Context, query string) ([]Sample, error) {
		if strings.Contains(query, "istio_requests_total") && !strings.Contains(query, "5..") {
			return samples, nil
		}
		return nil, nil
	})
	res, err := Flows(context.Background(), q, SourceIstio, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Edges) != MaxEdges || res.TotalEdges != MaxEdges+20 {
		t.Fatalf("truncated=%v len=%d total=%d", res.Truncated, len(res.Edges), res.TotalEdges)
	}
	if res.Edges[0].Src.Name != fmt.Sprintf("s%d", MaxEdges+19) {
		t.Fatalf("first edge = %s, want the busiest", res.Edges[0].Src.Name)
	}
}

func TestRateWindowFor(t *testing.T) {
	for _, tc := range []struct {
		in   time.Duration
		want string
	}{
		{0, "300s"},
		{30 * time.Second, "300s"},
		{time.Minute, "60s"},
		{15 * time.Minute, "900s"},
		{3 * time.Hour, "3600s"},
	} {
		if got := rateWindowFor(tc.in).promQL; got != tc.want {
			t.Errorf("rateWindowFor(%v) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestUnavailableResultSerializesItsReason(t *testing.T) {
	b, err := json.Marshal(Unavailable(ReasonNoSource, "no traffic source"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if !strings.Contains(s, `"available":false`) || !strings.Contains(s, `"reasonCode":"no_source"`) || !strings.Contains(s, `"reason":"no traffic source"`) || !strings.Contains(s, `"flows":[]`) {
		t.Fatalf("json = %s", s)
	}
}
