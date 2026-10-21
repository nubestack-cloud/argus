package cost

import (
	"context"
	"net/url"
	"testing"
	"time"
)

func TestFromKubecost(t *testing.T) {
	var gotParams url.Values
	get := func(_ context.Context, path string, p url.Values) ([]byte, error) {
		gotParams = p
		if p.Get("accumulate") == "true" {
			// 120 minutes of allocation: totals become per-hour by halving.
			return []byte(`{"code":200,"data":[{
				"shop":{"name":"shop","minutes":120,"cpuCost":2,"ramCost":1,"pvCost":0.5,"totalCost":3.5,"totalEfficiency":0.4},
				"__idle__":{"name":"__idle__","minutes":120,"totalCost":9}}]}`), nil
		}
		return []byte(`{"code":200,"data":[
			{"shop":{"name":"shop","minutes":360,"totalCost":6,"window":{"start":"2026-10-14T06:00:00Z"}}},
			{"shop":{"name":"shop","minutes":360,"totalCost":12,"window":{"start":"2026-10-14T00:00:00Z"}}}]}`), nil
	}
	s := FromKubecost(context.Background(), get, 2*time.Hour)
	if !s.Available || s.Source != "kubecost" || len(s.Namespaces) != 1 {
		t.Fatalf("summary = %+v", s)
	}
	ns := s.Namespaces[0]
	if ns.HourlyCost != 1.75 || ns.CPUCost != 1 || *ns.StorageCost != 0.25 || *ns.Efficiency != 40 {
		t.Fatalf("shop row = %+v; idle must be left out and costs made hourly", ns)
	}
	if gotParams.Get("aggregate") != "namespace" || gotParams.Get("window") != "2h" {
		t.Fatalf("params = %v", gotParams)
	}
	trend, err := KubecostTrend(context.Background(), get, 12*time.Hour, 6*time.Hour)
	if err != nil || len(trend) != 2 || trend[0].HourlyCost != 2 || trend[1].HourlyCost != 1 {
		t.Fatalf("trend = %+v, %v; want oldest first, per hour", trend, err)
	}
}
