package objsearch

import (
	"fmt"
	"testing"
)

// show prints only the parts of a query that are set, in a fixed order.
func show(q Query) string {
	var s string
	add := func(name string, v any, set bool) {
		if set {
			s += fmt.Sprintf("%s%v ", name, v)
		}
	}
	add("tok", q.Tokens, q.Tokens != nil)
	add("kind", q.KindFilter, q.KindFilter != nil)
	add("ns", q.NSFilter, q.NSFilter != nil)
	add("label", q.LabelFilter, q.LabelFilter != nil)
	add("image", q.ImageFilter, q.ImageFilter != nil)
	return s
}

func TestParse(t *testing.T) {
	for in, want := range map[string]string{
		"":                 "",
		"   ":              "",
		"payments worker":  "tok[payments worker] ",
		"kind:StatefulSet": "kind[statefulset] ",
		// Every modifier, and an image reference whose own colon is kept.
		"ns:billing kind:Pod label:tier=db image:postgres:16.4": "kind[pod] ns[billing] label[{tier db}] image[postgres:16.4] ",
		// Short and long spellings, repeated namespaces, a key-only label.
		"k:job n:etl namespace:batch l:team img:spark": "kind[job] ns[etl batch] label[{team }] image[spark] ",
		"KIND:Service":        "kind[service] ",
		`"order api" ns:shop`: "tok[order api] ns[shop] ",
		`say"s two"x`:         "tok[says twox] ",
		// Not modifiers: an unknown key (cluster: is not in the agent's
		// grammar), an address, a key with no value, a value with no key.
		"cluster:west redis": "tok[cluster:west redis] ",
		"10.42.0.7:8443":     "tok[10.42.0.7:8443] ",
		"kind: ns":           "tok[kind: ns] ",
		":pod":               "tok[:pod] ",
	} {
		q := Parse(in)
		if got := show(q); got != want {
			t.Errorf("Parse(%q) = %q, want %q", in, got, want)
		}
		if q.Raw != in {
			t.Errorf("Raw = %q, want %q", q.Raw, in)
		}
	}
}
