// Package render answers the second of the two promises F26 (BACKLOG.md) names
// about a proposed repository change: not "these are the files, in full, as
// proposed" (internal/gitops already proves that) but "this produces the
// intended change in the cluster" — which nothing before this package could
// prove, because nobody rendered anything.
//
// The package is split in two along exactly that seam:
//
//   - This file and diff.go are pure, deterministic comparison logic: given
//     two already-rendered manifest sets, decide whether they describe the
//     same live objects. No filesystem, no subprocess, no cluster. This is
//     what evaluate_test.go's unit tests exercise directly, and what proves
//     the Helm values-file-precedence case: an edit that a later values file
//     overrides renders identically either way, and this is where that
//     equality is actually checked.
//   - evaluate.go's RenderFunc seam is where the untrusted part happens —
//     actually invoking `helm template`/`kustomize build` against
//     model-proposed, otherwise-untrusted repository content. Nothing in this
//     file or diff.go executes anything. sandbox/ is the one implementation
//     of RenderFunc meant to run in production; it exists precisely because
//     that execution needs to happen in a sandbox, not on the hub — see its
//     package comment and lld/09-repo-gitops-design.md §2.
package render

import (
	"bytes"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Object is one rendered Kubernetes manifest document, decoded generically —
// render-diff never needs typed access to a field, only whether two objects
// with the same identity are equal, so there is no reason to depend on
// k8s.io/api here.
type Object struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	// Data is the whole document, decoded to plain Go values (map[string]any,
	// []any, scalars) — comparison walks this, never the raw bytes, so
	// comment/whitespace/key-order differences between two renders are never
	// mistaken for an effective change.
	Data map[string]any
}

// Key identifies an object independent of its content — what two renders'
// object lists are matched up by.
func (o Object) Key() string {
	ns := o.Namespace
	if ns == "" {
		ns = "-"
	}
	return fmt.Sprintf("%s/%s %s/%s", o.APIVersion, o.Kind, ns, o.Name)
}

// String is the identity in the form a reviewer reads, e.g.
// "apps/v1/Deployment argus-gitops-rke2/cache".
func (o Object) String() string {
	ns := o.Namespace
	if ns == "" {
		ns = "-"
	}
	return fmt.Sprintf("%s/%s %s/%s", o.APIVersion, o.Kind, ns, o.Name)
}

// ParseManifests decodes a multi-document YAML render (what `helm template` or
// `kustomize build`/`kubectl kustomize` writes to stdout) into Objects.
//
// Empty documents (a template that rendered nothing for some input — an `if`
// block that didn't fire, a `---` separator with nothing after it, which Helm
// emits constantly for multi-template charts) are skipped rather than
// reported as a change with no identity: they carry no object, so they cannot
// carry a difference either.
//
// A document that fails to decode at all is reported as an error rather than
// silently dropped — a renderer producing something that isn't YAML at all is
// exactly the "detect and refuse" case lld/09 §2 calls out for exec-plugins,
// not something to paper over here.
func ParseManifests(rendered []byte) ([]Object, error) {
	dec := yaml.NewDecoder(bytes.NewReader(rendered))
	var out []Object
	docIndex := 0
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, fmt.Errorf("render: decode document %d: %w", docIndex, err)
		}
		docIndex++
		root := &doc
		if doc.Kind == yaml.DocumentNode {
			if len(doc.Content) == 0 {
				continue
			}
			root = doc.Content[0]
		}
		decoded, err := decodeYAMLNode(root)
		if err != nil {
			return nil, fmt.Errorf("render: decode document %d: %w", docIndex, err)
		}
		raw, ok := decoded.(map[string]any)
		if !ok || len(raw) == 0 {
			continue
		}
		obj, ok := objectFromMap(raw)
		if !ok {
			// Has content but no recognisable kind/apiVersion/name — e.g. a
			// bare NOTES.txt fragment a template emitted outside its own
			// document. Kept out of the comparison rather than erroring the
			// whole render: it carries no object identity to compare, and a
			// hard refusal here would make one malformed template block the
			// evidence for every well-formed one in the same chart.
			continue
		}
		out = append(out, obj)
	}
	return out, nil
}

// decodeYAMLNode walks a *yaml.Node tree into plain Go values itself, rather
// than decoding straight into a map[string]any the way ParseManifests used
// to — because yaml.v3's own map-target decode path unconditionally REJECTS
// a mapping with a repeated key ("mapping key ... already defined at line
// ..."), and real Kubernetes YAML tooling does not: kubectl/helm's actual
// parse path (sigs.k8s.io/yaml, which round-trips through encoding/json)
// tolerates a duplicate key with last-value-wins, the same as JSON. A live
// chart caught this exact gap 2026-09-09 (BACKLOG.md F30's own live
// verification): a real, currently-`helm install`-able chart's Ingress
// template set the same annotation key twice across two merged annotation
// blocks, and ParseManifests refused the whole render — reporting "could not
// verify" for a chart that a real cluster accepts every day. Walking the
// node tree by hand and merging last-value-wins on a duplicate key matches
// what the cluster itself actually does, instead of a stricter rule this
// package invented on its own.
func decodeYAMLNode(node *yaml.Node) (any, error) {
	switch node.Kind {
	case yaml.MappingNode:
		out := make(map[string]any, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			var key string
			if err := node.Content[i].Decode(&key); err != nil {
				return nil, err
			}
			val, err := decodeYAMLNode(node.Content[i+1])
			if err != nil {
				return nil, err
			}
			out[key] = val // last-value-wins on a duplicate key, matching real cluster tooling — see this function's own doc comment
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, len(node.Content))
		for i, c := range node.Content {
			v, err := decodeYAMLNode(c)
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	case yaml.AliasNode:
		return decodeYAMLNode(node.Alias)
	default:
		var v any
		if err := node.Decode(&v); err != nil {
			return nil, err
		}
		return v, nil
	}
}

func objectFromMap(raw map[string]any) (Object, bool) {
	apiVersion, _ := raw["apiVersion"].(string)
	kind, _ := raw["kind"].(string)
	if apiVersion == "" || kind == "" {
		return Object{}, false
	}
	meta, _ := raw["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	if name == "" {
		return Object{}, false
	}
	ns, _ := meta["namespace"].(string)
	return Object{APIVersion: apiVersion, Kind: kind, Namespace: ns, Name: name, Data: raw}, true
}

// deepEqual compares two decoded YAML values for semantic equality — the same
// notion ParseManifests' map[string]any values need, without pulling in
// reflect.DeepEqual's stricter numeric-type sensitivity (yaml.v3 can decode
// the same literal as int or float64 depending on formatting used across two
// otherwise-identical renders, and that must not read as an effective
// change).
func deepEqual(a, b any) bool {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, aval := range av {
			bval, ok := bv[k]
			if !ok || !deepEqual(aval, bval) {
				return false
			}
		}
		return true
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !deepEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	default:
		return numericAwareEqual(a, b)
	}
}

func numericAwareEqual(a, b any) bool {
	af, aok := asFloat(a)
	bf, bok := asFloat(b)
	if aok && bok {
		return af == bf
	}
	return fmt.Sprint(a) == fmt.Sprint(b) && sameStringiness(a, b)
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case float64:
		return n, true
	default:
		return 0, false
	}
}

// sameStringiness stops "true" (string) and true (bool) — or "1" and 1 —
// comparing equal just because fmt.Sprint renders them the same way. A real
// type change between two renders of the same key is exactly the kind of
// surprising effective change this package exists to surface, not hide.
func sameStringiness(a, b any) bool {
	return fmt.Sprintf("%T", a) == fmt.Sprintf("%T", b)
}

// yamlScalar renders a decoded value back to a short, human-readable form for
// a diff line — never the full sub-tree, which is diffPaths' job for a
// nested change.
func yamlScalar(v any) string {
	switch v.(type) {
	case map[string]any, []any:
		b, err := yaml.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return "{" + strings.TrimSpace(strings.ReplaceAll(string(b), "\n", "; ")) + "}"
	case nil:
		return "<absent>"
	default:
		return fmt.Sprintf("%v", v)
	}
}
