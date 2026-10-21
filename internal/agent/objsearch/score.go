package objsearch

import (
	"slices"
	"strings"
)

// grades is what a token earns on one kind of site: matching the whole
// value, the start of it, or anywhere in it. A zero grade means that kind of
// match is not rewarded there and the next one down is tried.
type grades struct{ whole, start, within int }

// What each site is worth. The name dominates; where an object lives and how
// it is labelled come next; its image and its kind are the weakest signals,
// since many objects share them.
var (
	nameGrades      = grades{whole: 100, start: 60, within: 40}
	namespaceGrades = grades{whole: 30, within: 20}
	labelGrades     = grades{whole: 25, within: 18}
	imageGrades     = grades{whole: 20, within: 20}
	kindGrades      = grades{whole: 10, within: 5}
)

// filterOnlyScore is every hit's score for a query of modifiers alone: all
// that passed the filters rank equal.
const filterOnlyScore = 1

func (g grades) of(value, lowTok string) int {
	v := strings.ToLower(value)
	switch {
	case v == "":
		return 0
	case v == lowTok:
		return g.whole
	case g.start > 0 && strings.HasPrefix(v, lowTok):
		return g.start
	case strings.Contains(v, lowTok):
		return g.within
	}
	return 0
}

// matchedSite records where one free token landed.
type matchedSite struct {
	Token string
	Site  string // "name" | "namespace" | "label:<key>" | "image" | "kind"
	Score int
}

// match runs q against o: the modifiers first, as hard filters, then every
// free token, each scored at its best site and the scores summed. ok is
// false when a filter rejects o or a token lands nowhere.
func match(q Query, o Object) (score int, sites []matchedSite, ok bool) {
	if !passes(q, o) {
		return 0, nil, false
	}
	if len(q.Tokens) == 0 {
		return filterOnlyScore, nil, true
	}
	for _, tok := range q.Tokens {
		best := bestSite(tok, o)
		if best.Score == 0 {
			return 0, nil, false
		}
		score += best.Score
		sites = append(sites, best)
	}
	return score, sites, true
}

func passes(q Query, o Object) bool {
	if len(q.KindFilter) > 0 && !kindMatches(o.Kind, q.KindFilter) {
		return false
	}
	if len(q.NSFilter) > 0 && !slices.ContainsFunc(q.NSFilter, func(ns string) bool { return strings.EqualFold(ns, o.Namespace) }) {
		return false
	}
	for _, want := range q.LabelFilter {
		if v, set := o.Labels[want.Key]; !set || want.Value != "" && v != want.Value {
			return false
		}
	}
	for _, img := range q.ImageFilter {
		if imageGrades.ofAny(o.Images, strings.ToLower(img)) == 0 {
			return false
		}
	}
	return true
}

func (g grades) ofAny(values []string, lowTok string) int {
	best := 0
	for _, v := range values {
		best = max(best, g.of(v, lowTok))
	}
	return best
}

// bestSite is the site tok scores highest on. Sites are tried in a fixed
// order — name, namespace, labels by key, images, kind — and an equal score
// later never displaces an earlier one, so the answer is stable.
func bestSite(tok string, o Object) matchedSite {
	low := strings.ToLower(tok)
	best := matchedSite{Token: tok}
	try := func(site string, score int) {
		if score > best.Score {
			best.Site, best.Score = site, score
		}
	}
	try("name", nameGrades.of(o.Name, low))
	try("namespace", namespaceGrades.of(o.Namespace, low))
	keys := make([]string, 0, len(o.Labels))
	for k := range o.Labels {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		try("label:"+k, labelGrades.of(o.Labels[k], low))
	}
	try("image", imageGrades.ofAny(o.Images, low))
	try("kind", kindGrades.of(o.Kind, low))
	return best
}

// kindMatches accepts a kind by its name or plural in any case: Pod, pod and
// pods all select pods, and a filter written in the plural also matches a
// kind whose name already ends in s. Short names (svc, deploy) are not
// expanded.
func kindMatches(kind string, filters []string) bool {
	k := strings.ToLower(kind)
	return slices.ContainsFunc(filters, func(f string) bool {
		f = strings.ToLower(f)
		return f == k || f == k+"s" || f+"s" == k
	})
}
