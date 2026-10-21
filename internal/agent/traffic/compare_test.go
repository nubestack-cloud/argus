package traffic

import (
	"context"
	"strings"
	"testing"
	"time"
)

func flowSeries(src, dst string, v float64) rawSeries {
	return rawSeries{beylaFlowMetric, map[string]string{
		"k8s_src_owner_name": src, "k8s_src_namespace": "shop", "k8s_src_owner_type": "Deployment",
		"k8s_dst_owner_name": dst, "k8s_dst_namespace": "shop", "k8s_dst_owner_type": "Deployment", "direction": "request",
	}, v}
}

// now and an hour ago: one flow holds, one stopped, one is new.
func TestFlowsComparesWithAnEarlierWindow(t *testing.T) {
	now := fakeSumBy([]rawSeries{flowSeries("web", "api", 900), flowSeries("web", "search", 50)}, nil)
	before := fakeSumBy([]rawSeries{flowSeries("web", "api", 3000), flowSeries("api", "db", 400)}, nil)
	var sawOffset bool
	q := queryFunc(func(ctx context.Context, query string) ([]Sample, error) {
		if strings.Contains(query, " offset 3600s") {
			sawOffset = true
			return before(ctx, query)
		}
		return now(ctx, query)
	})
	res, err := Flows(context.Background(), q, SourceBeyla, "", 15*time.Minute, WithComparison(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if !sawOffset || !res.ComparisonAvailable || res.ComparisonSeconds != 3600 {
		t.Fatalf("comparison not run: offset=%v %+v", sawOffset, res)
	}
	got := map[string]Edge{}
	for _, e := range res.Edges {
		got[e.Src.Name+">"+e.Dst.Name] = e
	}
	if e := got["web>api"]; e.Before == nil || derefRate(e.Before.BytesRate) != 3000 || derefRate(e.BytesRate) != 900 || e.Stopped {
		t.Errorf("held flow = %+v", e)
	}
	if e := got["api>db"]; !e.Stopped || e.BytesRate != nil || derefRate(e.Before.BytesRate) != 400 {
		t.Errorf("stopped flow = %+v (current figures must be absent, not zero)", e)
	}
	if e := got["web>search"]; e.Before != nil || e.Stopped {
		t.Errorf("new flow = %+v", e)
	}
}

// A source with no history yet must not make every flow read as new.
func TestComparisonWithNoEarlierTrafficIsUnavailable(t *testing.T) {
	now := fakeSumBy([]rawSeries{flowSeries("web", "api", 900)}, nil)
	q := queryFunc(func(ctx context.Context, query string) ([]Sample, error) {
		if strings.Contains(query, " offset ") {
			return nil, nil
		}
		return now(ctx, query)
	})
	res, err := Flows(context.Background(), q, SourceBeyla, "", 15*time.Minute, WithComparison(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if res.ComparisonAvailable || res.ComparisonReason == "" || res.Edges[0].Before != nil {
		t.Fatalf("result = %+v", res)
	}
}
