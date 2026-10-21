package traffic

import (
	"context"
	"strings"
	"testing"
)

func TestHubble(t *testing.T) {
	labelled := true
	q := queryFunc(func(_ context.Context, promql string) ([]Sample, error) {
		switch {
		case strings.HasPrefix(promql, "count(hubble_flows_processed_total{"):
			if !labelled {
				return nil, nil
			}
			return []Sample{sample(nil, 12)}, nil
		case strings.HasPrefix(promql, "count(hubble_flows_processed_total)"):
			return []Sample{sample(nil, 40)}, nil
		case strings.Contains(promql, "rate(hubble_flows_processed_total"):
			return []Sample{sample(map[string]string{"source_workload": "web", "source_namespace": "shop", "destination_workload": "api",
				"destination_namespace": "shop", "protocol": "TCP"}, 3)}, nil
		}
		return nil, nil // no Istio or Beyla here
	})
	if d := Probe(context.Background(), q); d.Source != SourceHubble {
		t.Fatalf("detection = %+v, want hubble", d)
	}
	res, err := Flows(context.Background(), q, SourceHubble, "shop", 0)
	if err != nil || len(res.Edges) != 1 || res.Edges[0].Src.Name != "web" || res.Edges[0].Dst.Name != "api" || res.Edges[0].Protocol != "tcp" {
		t.Fatalf("flows = %+v, %v", res, err)
	}
	// Without workload labels the source is refused with the setting to change.
	labelled = false
	if d := Probe(context.Background(), q); d.Source != "" || !strings.Contains(d.Reason, "sourceContext=workload-name") {
		t.Fatalf("unlabelled detection = %+v", d)
	}
}
