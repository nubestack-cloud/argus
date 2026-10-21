package render

import (
	"fmt"
	"sort"
)

// ObjectDiff is one object's difference between the original and proposed
// render.
type ObjectDiff struct {
	// Object identifies what changed, e.g. "apps/v1/Deployment ns/name".
	Object string
	// Status is "added", "removed", or "changed".
	Status string
	// FieldDiffs is one line per differing leaf field, e.g.
	// "spec.replicas: 3 -> 5" — empty for "added"/"removed", where the whole
	// object is the difference.
	FieldDiffs []string
}

// Result is what render-diff found comparing two renders of the same
// chart/overlay — one against the repository content at the pinned commit,
// one against that content with the proposed edit applied.
type Result struct {
	// RendererKind is "helm" or "kustomize" — recorded because a PR body or
	// audit record naming which renderer ran is part of the claim being made.
	RendererKind string
	// ObjectsTotal is how many distinct objects were compared (the union of
	// both renders' object sets) — so "0 changed" can be told apart from
	// "0 changed of 0 objects", which is a renderer that produced nothing and
	// should read as degraded, not as a clean verification.
	ObjectsTotal int
	// Changed lists every object that differs, in deterministic (sorted)
	// order.
	Changed []ObjectDiff
	// Effective is true when at least one object differs. False is the
	// values-file-precedence finding this package exists to catch: a real
	// edit to a real file that a later values file or chart default still
	// overrides ends up here, because the two renders are byte-for-byte
	// the same objects even though the source files differ.
	Effective bool
	// Summary is one sentence, already worded for a reviewer — quoted
	// verbatim into the PR body and audit record so the claim is made once
	// and read everywhere consistently.
	Summary string
}

// CompareManifests renders the second promise checkable: given the ORIGINAL
// render (repository content at the pinned commit) and the PROPOSED render
// (same content with the edit applied), decide whether the edit changes
// anything a cluster would actually end up running.
//
// This function is the whole of "the render-diff comparison logic" the F26
// entry asks be unit tested without a cluster or a renderer — it takes
// already-rendered YAML, which is exactly what evaluate_test.go's fixture
// tests feed it directly, and what evaluate.go feeds it after calling a
// RenderFunc.
func CompareManifests(rendererKind string, original, proposed []byte) (Result, error) {
	origObjs, err := ParseManifests(original)
	if err != nil {
		return Result{}, fmt.Errorf("render: parsing the ORIGINAL render: %w", err)
	}
	propObjs, err := ParseManifests(proposed)
	if err != nil {
		return Result{}, fmt.Errorf("render: parsing the PROPOSED render: %w", err)
	}

	origByKey := make(map[string]Object, len(origObjs))
	for _, o := range origObjs {
		origByKey[o.Key()] = o
	}
	propByKey := make(map[string]Object, len(propObjs))
	for _, o := range propObjs {
		propByKey[o.Key()] = o
	}

	allKeys := make(map[string]struct{}, len(origByKey)+len(propByKey))
	for k := range origByKey {
		allKeys[k] = struct{}{}
	}
	for k := range propByKey {
		allKeys[k] = struct{}{}
	}

	var diffs []ObjectDiff
	for key := range allKeys {
		o, hasOrig := origByKey[key]
		p, hasProp := propByKey[key]
		switch {
		case hasOrig && !hasProp:
			diffs = append(diffs, ObjectDiff{Object: o.String(), Status: "removed"})
		case !hasOrig && hasProp:
			diffs = append(diffs, ObjectDiff{Object: p.String(), Status: "added"})
		default:
			if fields := diffPaths("", o.Data, p.Data); len(fields) > 0 {
				diffs = append(diffs, ObjectDiff{Object: o.String(), Status: "changed", FieldDiffs: fields})
			}
		}
	}
	sort.Slice(diffs, func(i, j int) bool { return diffs[i].Object < diffs[j].Object })

	res := Result{
		RendererKind: rendererKind,
		ObjectsTotal: len(allKeys),
		Changed:      diffs,
		Effective:    len(diffs) > 0,
	}
	res.Summary = summarize(res)
	return res, nil
}

func summarize(r Result) string {
	if r.ObjectsTotal == 0 {
		return "the render produced no objects to compare — this is not a clean verification, it is an empty one"
	}
	if !r.Effective {
		return fmt.Sprintf("rendered %d object(s) from both the original and proposed content and found them identical — this edit does not change what the cluster would run", r.ObjectsTotal)
	}
	return fmt.Sprintf("rendered %d object(s) and found %d differ between the original and proposed content — this edit changes what the cluster would run", r.ObjectsTotal, len(r.Changed))
}

// diffPaths walks two decoded YAML values in lock-step and returns one line
// per leaf field that differs, dotted-path style ("spec.replicas: 3 -> 5").
// A nested map/list only gets its OWN summary line when comparing it whole
// would be uninformative (a list whose length changed); otherwise it recurses
// so a one-field change inside a ten-key map reports as one line, not ten.
func diffPaths(prefix string, a, b any) []string {
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			return []string{fmt.Sprintf("%s: %s -> %s", pathOrRoot(prefix), yamlScalar(a), yamlScalar(b))}
		}
		var out []string
		keys := make(map[string]struct{}, len(av)+len(bv))
		for k := range av {
			keys[k] = struct{}{}
		}
		for k := range bv {
			keys[k] = struct{}{}
		}
		sortedAll := make([]string, 0, len(keys))
		for k := range keys {
			sortedAll = append(sortedAll, k)
		}
		sort.Strings(sortedAll)
		for _, k := range sortedAll {
			childPrefix := k
			if prefix != "" {
				childPrefix = prefix + "." + k
			}
			out = append(out, diffPaths(childPrefix, av[k], bv[k])...)
		}
		return out
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return []string{fmt.Sprintf("%s: %s -> %s", pathOrRoot(prefix), yamlScalar(a), yamlScalar(b))}
		}
		var out []string
		for i := range av {
			out = append(out, diffPaths(fmt.Sprintf("%s[%d]", prefix, i), av[i], bv[i])...)
		}
		return out
	default:
		if deepEqual(a, b) {
			return nil
		}
		return []string{fmt.Sprintf("%s: %s -> %s", pathOrRoot(prefix), yamlScalar(a), yamlScalar(b))}
	}
}

func pathOrRoot(p string) string {
	if p == "" {
		return "(root)"
	}
	return p
}
