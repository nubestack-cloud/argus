package objsearch

import (
	"context"
	"sort"
	"strings"
)

// Limits on the number of hits a search returns.
const (
	DefaultLimit = 50
	MaxLimit     = 50
)

// KindRef names one kind the provider can list.
type KindRef struct {
	Kind       string
	APIGroup   string
	Namespaced bool
}

// Object is the searchable face of one cached object. Providers build it
// from the cache; ObjectFromTyped and ObjectFromUnstructured do that for
// typed and dynamic objects.
type Object struct {
	Kind      string
	APIGroup  string
	Namespace string
	Name      string
	Labels    map[string]string
	Images    []string
	Status    string
}

// Provider is the object cache as search sees it. Kinds is the scan order:
// put the kinds users usually look for first, so a context deadline cuts the
// least useful ones. List with namespace "" lists every namespace (or the
// cluster scope for cluster-scoped kinds). An error marks that kind's
// results incomplete; it does not fail the search.
type Provider interface {
	Kinds() []KindRef
	List(ctx context.Context, kind KindRef, namespace string) ([]Object, error)
}

// Options configures one Search.
type Options struct {
	// Limit caps the hits returned; 0 means DefaultLimit and values above
	// MaxLimit are clamped.
	Limit int
	// Namespaces, when non-empty, restricts namespaced kinds to these
	// namespaces. Cluster-scoped kinds are always listed whole.
	Namespaces []string
}

// Hit is one ranked result.
type Hit struct {
	Score     int      `json:"score"`
	Kind      string   `json:"kind"`
	APIGroup  string   `json:"apiGroup,omitempty"`
	Namespace string   `json:"namespace,omitempty"`
	Name      string   `json:"name"`
	Matched   []string `json:"matched,omitempty"`
	Status    string   `json:"status,omitempty"`
}

// Result is the search tool's output.
type Result struct {
	Hits []Hit `json:"hits"`
	// TotalMatched counts hits before the limit; Truncated is set when the
	// limit dropped some.
	TotalMatched int  `json:"totalMatched"`
	Truncated    bool `json:"truncated,omitempty"`
	// Searched is the number of objects scanned.
	Searched int `json:"searched"`
	// IncompleteKinds names kinds ("Kind" or "Kind.group") that failed to
	// list or were not reached before the context ended; hits for them may
	// be missing.
	IncompleteKinds []string `json:"incompleteKinds,omitempty"`
}

// Search runs q over every kind p offers and returns hits ranked by score,
// then kind, namespace and name.
func Search(ctx context.Context, p Provider, q Query, opts Options) Result {
	limit := opts.Limit
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}

	res := Result{Hits: []Hit{}}
	var hits []Hit
	for _, kr := range p.Kinds() {
		if !shouldScan(kr, q) {
			continue
		}
		if ctx.Err() != nil {
			res.IncompleteKinds = append(res.IncompleteKinds, kindLabel(kr))
			continue
		}
		objs, complete := listKind(ctx, p, kr, opts.Namespaces)
		if !complete {
			res.IncompleteKinds = append(res.IncompleteKinds, kindLabel(kr))
		}
		res.Searched += len(objs)
		for _, o := range objs {
			if o.Kind == "" {
				o.Kind = kr.Kind
			}
			if o.APIGroup == "" {
				o.APIGroup = kr.APIGroup
			}
			score, sites, ok := match(q, o)
			if !ok {
				continue
			}
			hits = append(hits, Hit{
				Score:     score,
				Kind:      o.Kind,
				APIGroup:  o.APIGroup,
				Namespace: o.Namespace,
				Name:      o.Name,
				Matched:   siteNames(sites),
				Status:    o.Status,
			})
		}
	}

	hits = dedupHits(hits)
	sort.SliceStable(hits, func(i, j int) bool {
		a, b := hits[i], hits[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
	res.TotalMatched = len(hits)
	if len(hits) > limit {
		hits = hits[:limit]
		res.Truncated = true
	}
	res.Hits = append(res.Hits, hits...)
	return res
}

func listKind(ctx context.Context, p Provider, kr KindRef, namespaces []string) ([]Object, bool) {
	if !kr.Namespaced || len(namespaces) == 0 {
		objs, err := p.List(ctx, kr, "")
		return objs, err == nil
	}
	var out []Object
	complete := true
	for _, ns := range namespaces {
		if ctx.Err() != nil {
			return out, false
		}
		objs, err := p.List(ctx, kr, ns)
		if err != nil {
			complete = false
			continue
		}
		out = append(out, objs...)
	}
	return out, complete
}

// shouldScan skips Secrets always and Events unless a kind filter asks for
// them: events are high-volume diagnostic records, not objects people look
// up by name.
func shouldScan(kr KindRef, q Query) bool {
	if kr.Kind == "Secret" && kr.APIGroup == "" {
		return false
	}
	if len(q.KindFilter) > 0 {
		return kindMatches(kr.Kind, q.KindFilter)
	}
	return kr.Kind != "Event"
}

// dedupHits keeps the best-scoring hit per (kind, group, namespace, name):
// a provider may reach one object through both a typed and a dynamic list.
func dedupHits(hits []Hit) []Hit {
	type key struct{ kind, group, ns, name string }
	seen := make(map[key]int, len(hits))
	out := hits[:0]
	for _, h := range hits {
		k := key{h.Kind, h.APIGroup, h.Namespace, h.Name}
		if idx, ok := seen[k]; ok {
			if h.Score > out[idx].Score {
				out[idx] = h
			}
			continue
		}
		seen[k] = len(out)
		out = append(out, h)
	}
	return out
}

// siteNames lists the distinct sites the tokens landed on, in token order.
func siteNames(sites []matchedSite) []string {
	if len(sites) == 0 {
		return nil
	}
	out := make([]string, 0, len(sites))
	for _, s := range sites {
		dup := false
		for _, have := range out {
			if have == s.Site {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, s.Site)
		}
	}
	return out
}

func kindLabel(kr KindRef) string {
	if kr.APIGroup == "" {
		return kr.Kind
	}
	return strings.Join([]string{kr.Kind, kr.APIGroup}, ".")
}
