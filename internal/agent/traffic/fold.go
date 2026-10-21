package traffic

import (
	"fmt"
	"time"
)

// EndpointResolver maps an endpoint to the one it stands for, reporting false
// to leave it as it is. The agent uses it to fold a Service into the workload
// whose pods back it (tools_insight_more.go).
type EndpointResolver func(Endpoint) (Endpoint, bool)

// Option adjusts Flows.
type Option func(*options)

type options struct {
	resolve   EndpointResolver
	compareTo time.Duration
}

// WithComparison reads the same window `back` earlier and attaches it to
// each edge as Before (Result.ComparisonSeconds).
func WithComparison(back time.Duration) Option { return func(o *options) { o.compareTo = back } }

// WithEndpointResolver folds endpoints before edges are merged.
func WithEndpointResolver(r EndpointResolver) Option { return func(o *options) { o.resolve = r } }

// foldEndpoints rewrites each flow's ends through resolve and drops the copies
// that fold creates. Beyla reports one connection twice, once at the Service
// address and once at the Pod behind it, so after a Service folds into its
// workload the two describe the same bytes: the attribution measured at the
// workload is kept, and a folded copy survives only where nothing else
// describes that pair (then the larger copy, never their sum).
func foldEndpoints(flows []Edge, resolve EndpointResolver) []Edge {
	if resolve == nil {
		return flows
	}
	key := func(e Edge) string {
		return fmt.Sprintf("%s/%s|%s/%s|%d|%t", e.Src.Namespace, e.Src.Name, e.Dst.Namespace, e.Dst.Name, e.Port, e.DirectionUnknown)
	}
	type folded struct {
		edge Edge
		was  bool
	}
	all := make([]folded, 0, len(flows))
	direct := map[string]bool{}
	for _, f := range flows {
		was := false
		if r, ok := resolve(f.Src); ok {
			f.Src, was = r, true
		}
		if r, ok := resolve(f.Dst); ok {
			f.Dst, was = r, true
		}
		// An undirected pair is written in name order (beyla.go), and folding
		// can reverse it; put it back so both copies merge into one edge.
		if was && f.DirectionUnknown && endpointOrderKey(f.Dst) < endpointOrderKey(f.Src) {
			f.Src, f.Dst = f.Dst, f.Src
		}
		all = append(all, folded{f, was})
		if !was {
			direct[key(f)] = true
		}
	}
	out := make([]Edge, 0, len(all))
	best := map[string]int{}
	for _, f := range all {
		k := key(f.edge)
		if !f.was {
			out = append(out, f.edge)
			continue
		}
		if direct[k] {
			continue
		}
		if i, ok := best[k]; ok {
			if derefRate(f.edge.BytesRate) > derefRate(out[i].BytesRate) {
				out[i] = f.edge
			}
			continue
		}
		best[k] = len(out)
		out = append(out, f.edge)
	}
	return out
}

func endpointOrderKey(e Endpoint) string { return e.Namespace + "/" + e.Name }
