package traffic

import "testing"

// rke2's nebula database (2026-10-15): Beyla reports the pooler's connection
// once at the Service and once at the CloudNativePG pods behind it, and the
// replicas' traffic once pod-to-Service and once pod-to-pod. Folding the
// Service into its workload must count each conversation once.
func TestFoldCountsAServiceAndItsPodsOnce(t *testing.T) {
	ep := func(name, kind string) Endpoint { return Endpoint{Namespace: "nebula", Name: name, Kind: kind} }
	flows := []Edge{
		{Src: ep("nebula-db-pooler-rw", KindWorkload), Dst: ep("nebula-db-rw", KindService), BytesRate: ratePtr(20122)},
		{Src: ep("nebula-db-pooler-rw", KindWorkload), Dst: ep("nebula-db", KindWorkload), BytesRate: ratePtr(20122)},
		{Src: ep("nebula-db", KindWorkload), Dst: ep("nebula-db-rw", KindService), BytesRate: ratePtr(74278), DirectionUnknown: true},
		{Src: ep("nebula-db", KindWorkload), Dst: ep("nebula-db-ro", KindService), BytesRate: ratePtr(74191), DirectionUnknown: true},
		{Src: ep("nebula-api", KindWorkload), Dst: ep("nebula-db-pooler-rw", KindWorkload), BytesRate: ratePtr(136)},
		{Src: ep("nebula-api", KindWorkload), Dst: ep("shared", KindService), BytesRate: ratePtr(10)},
		// One undirected conversation, seen at the Service and at the pod:
		// folding turns the first into db ↔ pooler, the reverse of the second.
		{Src: ep("nebula-db-pooler-rw", KindWorkload), Dst: ep("nebula-db-rw", KindService), BytesRate: ratePtr(2500), DirectionUnknown: true},
		{Src: ep("nebula-db", KindWorkload), Dst: ep("nebula-db-pooler-rw", KindWorkload), BytesRate: ratePtr(2500), DirectionUnknown: true},
	}
	backing := map[string]string{"nebula-db-rw": "nebula-db", "nebula-db-ro": "nebula-db"}
	resolve := func(e Endpoint) (Endpoint, bool) {
		if w, ok := backing[e.Name]; ok && e.Kind == KindService {
			return Endpoint{Namespace: e.Namespace, Name: w, Kind: KindWorkload}, true
		}
		return e, false
	}
	got := map[string]float64{}
	for _, e := range AggregateFlows(foldEndpoints(flows, resolve)) {
		got[e.Src.Name+">"+e.Dst.Name] = derefRate(e.BytesRate)
	}
	want := map[string]float64{
		"nebula-db-pooler-rw>nebula-db":  20122, // the pod attribution, not doubled
		"nebula-db>nebula-db":            74278, // two folded copies: the larger, never the sum
		"nebula-api>nebula-db-pooler-rw": 136,
		"nebula-api>shared":              10,   // a Service nothing resolves stays a Service
		"nebula-db>nebula-db-pooler-rw":  2500, // one undirected edge, in name order, once
	}
	if len(got) != len(want) {
		t.Fatalf("edges = %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v (all: %v)", k, got[k], v, got)
		}
	}
	if len(foldEndpoints(flows, nil)) != len(flows) {
		t.Fatal("no resolver must leave flows untouched")
	}
}
