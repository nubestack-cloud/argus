package traffic

import (
	"fmt"
	"math"
	"sort"
)

// AggregateFlows merges per-series flows into one edge per
// srcNamespace/srcName|dstNamespace/dstName|port|directionUnknown.
//
// Whether the direction is known is part of the identity: a source that
// cannot orient some traffic reports it with port 0 — the same port every
// flow carries when the port attribute is absent — so oriented and
// unoriented traffic between one pair would otherwise land on one edge, and
// any single answer about its direction is wrong for half of it.
//
// Rates are summed. A figure stays nil on the edge unless at least one flow
// behind it measured it, so merging never turns "unknown" into zero. The
// edge's protocol is the one carrying the most traffic, so a pair reached
// over HTTP and gRPC is labelled by what dominates rather than by whichever
// series came first. Endpoint kinds come from the first flow.
func AggregateFlows(flows []Edge) []Edge {
	type acc struct {
		edge  Edge
		votes map[string]float64
	}
	byKey := make(map[string]*acc, len(flows))
	order := make([]string, 0, len(flows))

	for _, f := range flows {
		key := fmt.Sprintf("%s/%s|%s/%s|%d|%t",
			f.Src.Namespace, f.Src.Name, f.Dst.Namespace, f.Dst.Name, f.Port, f.DirectionUnknown)
		a, ok := byKey[key]
		if !ok {
			a = &acc{
				edge: Edge{
					Src: f.Src, Dst: f.Dst, Port: f.Port, Protocol: f.Protocol,
					DirectionUnknown: f.DirectionUnknown,
				},
				votes: make(map[string]float64),
			}
			byKey[key] = a
			order = append(order, key)
		}
		a.edge.RequestRate = addRate(a.edge.RequestRate, f.RequestRate)
		a.edge.ErrorRate = addRate(a.edge.ErrorRate, f.ErrorRate)
		a.edge.ConnectionRate = addRate(a.edge.ConnectionRate, f.ConnectionRate)
		a.edge.BytesRate = addRate(a.edge.BytesRate, f.BytesRate)

		if f.Protocol != "" {
			// A zero-traffic flow still gets a vote so a protocol is never lost.
			weight := 1.0
			switch {
			case f.RequestRate != nil && finiteRate(*f.RequestRate) > 0:
				weight += *f.RequestRate
			case f.ConnectionRate != nil && finiteRate(*f.ConnectionRate) > 0:
				weight += *f.ConnectionRate
			}
			a.votes[f.Protocol] += weight
		}
	}

	out := make([]Edge, 0, len(order))
	for _, key := range order {
		a := byKey[key]
		if len(a.votes) > 0 {
			protos := make([]string, 0, len(a.votes))
			for p := range a.votes {
				protos = append(protos, p)
			}
			// Sorted first so a tie resolves the same way on every call.
			sort.Strings(protos)
			best := protos[0]
			for _, p := range protos[1:] {
				if a.votes[p] > a.votes[best] {
					best = p
				}
			}
			a.edge.Protocol = best
		}
		out = append(out, a.edge)
	}
	return out
}

// capEdges orders edges busiest first and keeps at most limit of them.
// Ordering is fully deterministic so the same data always yields the same
// truncation.
func capEdges(edges []Edge, limit int) ([]Edge, bool) {
	weight := func(e Edge) (float64, float64) {
		var reqs, bytes float64
		if e.RequestRate != nil {
			reqs = *e.RequestRate
		}
		if e.ConnectionRate != nil {
			reqs += *e.ConnectionRate
		}
		if e.BytesRate != nil {
			bytes = *e.BytesRate
		}
		return reqs, bytes
	}
	sort.SliceStable(edges, func(i, j int) bool {
		ri, bi := weight(edges[i])
		rj, bj := weight(edges[j])
		if ri != rj {
			return ri > rj
		}
		if bi != bj {
			return bi > bj
		}
		return edgeKey(edges[i]) < edgeKey(edges[j])
	})
	if len(edges) <= limit {
		return edges, false
	}
	return edges[:limit], true
}

func edgeKey(e Edge) string {
	return fmt.Sprintf("%s/%s|%s/%s|%08d|%t", e.Src.Namespace, e.Src.Name, e.Dst.Namespace, e.Dst.Name, e.Port, e.DirectionUnknown)
}

// addRate sums two optional rates. Nil plus nil stays nil; a non-finite or
// negative operand counts as no measurement.
func addRate(a, b *float64) *float64 {
	if b == nil || !isFinite(*b) {
		return a
	}
	v := finiteRate(*b)
	if a == nil {
		return &v
	}
	sum := *a + v
	return &sum
}

// finiteRate drops a rate that cannot be summed: negative, NaN (a ratio of
// two rates at zero traffic) or infinite.
func finiteRate(rate float64) float64 {
	if rate <= 0 || !isFinite(rate) {
		return 0
	}
	return rate
}

func isFinite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

// usableSample reports whether a series value is traffic. The comparison
// alone is not enough: NaN fails every ordered comparison, so `val <= 0`
// admits it.
func usableSample(val float64) bool {
	return val > 0 && isFinite(val)
}

func ratePtr(v float64) *float64 { return &v }
