package traffic

import (
	"fmt"
	"math"
	"testing"
)

func ep(ns, name string) Endpoint { return Endpoint{Namespace: ns, Name: name, Kind: KindWorkload} }

func TestAggregateFlowsMergesOnePairAndPort(t *testing.T) {
	flows := []Edge{
		{Src: ep("web", "frontend"), Dst: ep("api", "backend"), Port: 8080, Protocol: "http", RequestRate: ratePtr(3), ErrorRate: ratePtr(0.5), BytesRate: ratePtr(100)},
		{Src: ep("web", "frontend"), Dst: ep("api", "backend"), Port: 8080, Protocol: "http", RequestRate: ratePtr(2), ErrorRate: ratePtr(0), BytesRate: ratePtr(50)},
	}
	got := AggregateFlows(flows)
	if len(got) != 1 {
		t.Fatalf("want 1 edge, got %d", len(got))
	}
	e := got[0]
	if !approx(mustRate(t, "requestRate", e.RequestRate), 5) || !approx(mustRate(t, "errorRate", e.ErrorRate), 0.5) || !approx(mustRate(t, "bytesRate", e.BytesRate), 150) {
		t.Fatalf("edge = %+v", e)
	}
	if e.ConnectionRate != nil {
		t.Fatalf("connectionRate = %v, want nil: nothing measured connections", *e.ConnectionRate)
	}
}

func TestAggregateFlowsDifferentPortsStayApart(t *testing.T) {
	got := AggregateFlows([]Edge{
		{Src: ep("a", "x"), Dst: ep("b", "y"), Port: 80, Protocol: "tcp", BytesRate: ratePtr(1)},
		{Src: ep("a", "x"), Dst: ep("b", "y"), Port: 443, Protocol: "tcp", BytesRate: ratePtr(1)},
	})
	if len(got) != 2 {
		t.Fatalf("want 2 edges, got %d", len(got))
	}
}

func TestAggregateFlowsDirectionIsPartOfTheKey(t *testing.T) {
	got := AggregateFlows([]Edge{
		{Src: ep("a", "x"), Dst: ep("b", "y"), Protocol: "tcp", BytesRate: ratePtr(1)},
		{Src: ep("a", "x"), Dst: ep("b", "y"), Protocol: "udp", BytesRate: ratePtr(1), DirectionUnknown: true},
	})
	if len(got) != 2 {
		t.Fatalf("oriented and unoriented traffic merged into %d edge(s)", len(got))
	}
}

func TestAggregateFlowsUnknownStaysUnknown(t *testing.T) {
	got := AggregateFlows([]Edge{
		{Src: ep("a", "x"), Dst: ep("b", "y"), Protocol: "tcp", BytesRate: ratePtr(10)},
		{Src: ep("a", "x"), Dst: ep("b", "y"), Protocol: "tcp", BytesRate: ratePtr(5)},
	})
	if got[0].RequestRate != nil || got[0].ErrorRate != nil {
		t.Fatalf("edge with no L7 data reports requestRate=%v errorRate=%v, want nil", got[0].RequestRate, got[0].ErrorRate)
	}
}

func TestAggregateFlowsProtocolMajority(t *testing.T) {
	got := AggregateFlows([]Edge{
		{Src: ep("a", "x"), Dst: ep("b", "y"), Protocol: "grpc", RequestRate: ratePtr(1)},
		{Src: ep("a", "x"), Dst: ep("b", "y"), Protocol: "http", RequestRate: ratePtr(9)},
	})
	if got[0].Protocol != "http" {
		t.Fatalf("protocol = %q, want the busier http", got[0].Protocol)
	}
}

func TestAggregateFlowsDropsNonFiniteRates(t *testing.T) {
	got := AggregateFlows([]Edge{
		{Src: ep("a", "x"), Dst: ep("b", "y"), Protocol: "http", RequestRate: ratePtr(2), ErrorRate: ratePtr(math.NaN())},
		{Src: ep("a", "x"), Dst: ep("b", "y"), Protocol: "http", RequestRate: ratePtr(math.Inf(1)), ErrorRate: ratePtr(0.1)},
	})
	e := got[0]
	if !approx(mustRate(t, "requestRate", e.RequestRate), 2) || !approx(mustRate(t, "errorRate", e.ErrorRate), 0.1) {
		t.Fatalf("edge = req %v err %v, want 2 / 0.1", *e.RequestRate, *e.ErrorRate)
	}
}

func TestAggregateFlowsEmpty(t *testing.T) {
	if got := AggregateFlows(nil); len(got) != 0 {
		t.Fatalf("got %d edges from no flows", len(got))
	}
}

func TestCapEdgesKeepsBusiestDeterministically(t *testing.T) {
	var edges []Edge
	for i := 0; i < 10; i++ {
		edges = append(edges, Edge{Src: ep("a", fmt.Sprintf("s%d", i)), Dst: ep("b", "d"), RequestRate: ratePtr(float64(i))})
	}
	got, truncated := capEdges(edges, 3)
	if !truncated || len(got) != 3 {
		t.Fatalf("truncated=%v len=%d", truncated, len(got))
	}
	for i, want := range []string{"s9", "s8", "s7"} {
		if got[i].Src.Name != want {
			t.Fatalf("got[%d] = %s, want %s", i, got[i].Src.Name, want)
		}
	}
	if _, truncated := capEdges(got, 3); truncated {
		t.Fatal("a list at the cap is not truncated")
	}
}
