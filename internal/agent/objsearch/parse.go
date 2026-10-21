// Package objsearch finds objects in one cluster's object cache by name,
// namespace, label, image or kind (CI-S12). It scans the cache linearly and
// ranks hits by where each query token landed; there is no index to keep in
// step with the cache.
//
// Only identity, labels, container images and a short status string are
// searched. Object bodies (spec, status, ConfigMap data, annotations) are
// not, so search cannot become a way to read values out of the cluster.
package objsearch

import (
	"slices"
	"strings"
	"unicode"
)

// Query is a parsed search request.
//
// Free Tokens are AND'd: a hit must match every token somewhere, and its
// score is the sum of each token's best site. Modifiers are hard filters
// applied before scoring.
type Query struct {
	Tokens      []string  // free tokens
	KindFilter  []string  // kind:Foo, lowercased; matches Kind or its plural
	NSFilter    []string  // ns:foo; any one must equal the namespace
	LabelFilter []LabelEq // label:k=v (or label:k); all must hold
	ImageFilter []string  // image:foo; substring of some container image
	Raw         string    // the original query string
}

// LabelEq is one label filter. An empty Value matches any value of Key.
type LabelEq struct {
	Key   string
	Value string
}

// modifiers are the recognised "key:value" filters, by every spelling of
// the key.
var modifiers = func() map[string]func(*Query, string) {
	m := map[string]func(*Query, string){}
	alias := func(apply func(*Query, string), keys ...string) {
		for _, k := range keys {
			m[k] = apply
		}
	}
	alias(func(q *Query, v string) { q.KindFilter = append(q.KindFilter, strings.ToLower(v)) }, "kind", "k")
	alias(func(q *Query, v string) { q.NSFilter = append(q.NSFilter, v) }, "namespace", "ns", "n")
	alias(func(q *Query, v string) {
		k, val, _ := strings.Cut(v, "=")
		q.LabelFilter = append(q.LabelFilter, LabelEq{Key: k, Value: val})
	}, "label", "l")
	alias(func(q *Query, v string) { q.ImageFilter = append(q.ImageFilter, v) }, "image", "img")
	return m
}()

// Parse splits a query into words — whitespace separates, double quotes hold
// a phrase together — and each word is either a modifier or a free token:
//
//	redis                  Tokens [redis]
//	kind:Pod redis         KindFilter [pod], Tokens [redis]
//	l:app=web img:nginx    LabelFilter [{app web}], ImageFilter [nginx]
//	"my svc" ns:prod       NSFilter [prod], Tokens [my svc]
//
// A word is a modifier only when it is letters, a colon, then something, and
// the letters name a known key. Anything else stays a free token: a port
// (10.0.0.1:443) or an image reference is not a modifier, and a mistyped key
// then matches nothing instead of quietly matching everything.
func Parse(q string) Query {
	out := Query{Raw: q}
	for _, w := range words(q) {
		key, val, found := strings.Cut(w, ":")
		apply := modifiers[strings.ToLower(key)]
		if !found || key == "" || val == "" || strings.IndexFunc(key, func(r rune) bool { return !unicode.IsLetter(r) }) >= 0 || apply == nil {
			out.Tokens = append(out.Tokens, w)
			continue
		}
		apply(&out, val)
	}
	return out
}

// words breaks s at whitespace outside double quotes. The quotes themselves
// are dropped, so `"my pod"` is one word, my pod.
func words(s string) []string {
	const cut = '\x00'
	var b strings.Builder
	quoted := false
	for _, r := range s {
		switch {
		case r == '"':
			quoted = !quoted
		case !quoted && (unicode.IsSpace(r) || r == cut):
			b.WriteRune(cut)
		default:
			b.WriteRune(r)
		}
	}
	return slices.DeleteFunc(strings.Split(b.String(), string(cut)), func(w string) bool { return w == "" })
}
