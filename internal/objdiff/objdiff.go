// Package objdiff computes a field-level diff between two Kubernetes objects.
//
// It exists for BACKLOG.md F13: an approver cannot safely wave through a change
// they cannot see, and "scale to 3" is the only kind of plan a risk badge and an
// action name adequately describe. Once ARGUS proposes arbitrary structured
// changes (F11), the diff *is* the review surface.
//
// # Why a field diff and not a text diff of two YAML documents
//
// A unified text diff looks familiar — it looks like `kubectl diff` — and is the
// wrong tool here. The "after" side of this comparison comes from a server-side
// dry run, so it carries whatever the API server did along the way: a bumped
// generation, rewritten managedFields, defaulted fields materialising for the
// first time. In a text diff those land as ordinary-looking hunks interleaved
// with the real change, and the reviewer's job becomes reading a diff rather
// than judging a change. A field diff can classify each entry instead, which is
// the whole point of the next section.
//
// # The distinction this package exists to draw
//
// Changes are split into two sets, and the second is the valuable one:
//
//   - **Requested** — fields the plan's own patch asked for. What an approver
//     expects to see, and what the action name already implied.
//   - **Additional** — everything else that changed. This is the cluster acting
//     on its own: API-server defaulting, and mutating admission webhooks
//     rewriting the submitted object. A reviewer approving "set memory limit to
//     512Mi" genuinely needs to know that a webhook will also attach a sidecar
//     or rewrite the image registry.
//
// That split is only computable because the "after" state comes from the API
// server rather than from applying the patch hub-side. A hub-side simulation
// would reproduce the requested set exactly and be blind to the entire
// additional set — which is to say, blind to everything a reviewer could not
// have predicted for themselves.
package objdiff

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Change is one differing leaf.
type Change struct {
	// Path is a human-readable field path, e.g.
	// `spec.template.spec.containers[web].resources.limits.memory`. List
	// elements are keyed by name where Kubernetes' merge key allows it — see
	// listKey — because `containers[web]` is reviewable and `containers[0]` is
	// a lookup task.
	Path string `json:"path"`
	// Before and After are the leaf values. Nil where Added/Removed says the
	// field did not exist on that side, which is distinguishable from a real
	// null only by checking those flags — hence both.
	Before any `json:"before,omitempty"`
	After  any `json:"after,omitempty"`
	// Added and Removed distinguish "this field appeared" and "this field went
	// away" from "its value changed". Defaulting shows up as Added, and an
	// approver reads those differently from a value change.
	Added   bool `json:"added,omitempty"`
	Removed bool `json:"removed,omitempty"`
}

// Result is the classified diff.
type Result struct {
	// Requested is what the plan's patch asked to change.
	Requested []Change `json:"requested"`
	// Additional is what the cluster changed as well — defaulting and mutating
	// webhooks. Empty is the common case and the reassuring one.
	Additional []Change `json:"additional"`
	// Suppressed names the entries dropped as server bookkeeping.
	//
	// Paths rather than a count, deliberately. "3 bookkeeping fields were
	// hidden" asks a reviewer to trust the filter; naming them lets the
	// reviewer check it, which is the same standard the rest of ARGUS holds
	// itself to. It also makes the filter debuggable — the first live run
	// reported one more suppression than the fields that visibly differed, and
	// a bare count gave no way to find out which.
	Suppressed []string `json:"suppressed"`
}

// Empty reports whether anything meaningful changed. A dry run that produces an
// empty diff is worth surfacing loudly rather than rendering as a blank panel:
// it means the change would be a no-op, which is usually a stale plan.
func (r Result) Empty() bool { return len(r.Requested) == 0 && len(r.Additional) == 0 }

// suppressedPaths are server-maintained bookkeeping fields that change on
// essentially every write and mean nothing to a reviewer.
//
// Kept deliberately short. Over-suppression is the more dangerous failure here:
// the whole value of the Additional set is showing changes nobody asked for, and
// a generous denylist would filter out exactly those. In particular `status` is
// NOT suppressed — ARGUS only ever patches spec and metadata, so a status
// difference appearing in a dry run is surprising, and surprising is what a
// reviewer most needs to see.
var suppressedPaths = []string{
	"metadata.resourceVersion",
	"metadata.generation",
	"metadata.managedFields",
	"metadata.annotations.kubectl.kubernetes.io/last-applied-configuration",
}

// suppressedLeaf names fields suppressed wherever they occur, at any depth.
// creationTimestamp is here because the API server emits `creationTimestamp:
// null` inside pod templates, which otherwise appears as a change on every
// single patch.
var suppressedLeaf = map[string]bool{"creationTimestamp": true}

// suppressedLeafSuffix names leaves suppressed by SUFFIX rather than by exact
// name, which today means exactly one thing: the relative-time siblings ARGUS
// injects into every observed object itself.
//
// `annotateRelativeTimestamps` (internal/agent/relative_time.go) adds a
// `<field>SecondsSince` / `<field>SecondsUntil` sibling next to each RFC3339
// timestamp, computed against the tool call's single snapshot of now, so the
// model can reason about elapsed time without doing clock arithmetic. They are
// not Kubernetes fields and never exist in the cluster.
//
// They therefore differ between ANY two observations taken at different
// instants — which is precisely what a dry-run before/after comparison is — so
// they cannot ever represent a change the cluster would make. Before this,
// approving a two-field resource patch on a live incident showed a reviewer
// "3 additional changes": `metadata.creationTimestampSecondsSince` and two
// `status.conditions[N].lastTransitionTimeSecondsSince`. All three were ARGUS's
// own instrumentation, and on a screen whose whole job is to show what nobody
// asked for, that teaches the reviewer to skip the section.
//
// This is NOT the over-suppression the note above warns against, because it
// removes ARGUS's own additions rather than anything the cluster did. A real
// Kubernetes field ending in these exact suffixes would be caught by the same
// rule, which is why they stay long and specific ("Seconds" alone would eat
// `terminationGracePeriodSeconds`), and why every drop is still named in
// Suppressed for the reviewer to check.
var suppressedLeafSuffix = []string{"SecondsSince", "SecondsUntil"}

// Compute diffs before against after, classifying each change by whether patch
// asked for it.
//
// A nil or unparseable patch is not an error: it yields a diff with everything
// in Additional. That degradation is deliberate — an unclassified diff is still
// a diff, and refusing to show one because the classification input was missing
// would trade the reviewer's whole view for a detail of its presentation.
func Compute(before, after, patch json.RawMessage) (Result, error) {
	var beforeObj, afterObj map[string]any
	if err := json.Unmarshal(before, &beforeObj); err != nil {
		return Result{}, fmt.Errorf("objdiff: decode the live object: %w", err)
	}
	if err := json.Unmarshal(after, &afterObj); err != nil {
		return Result{}, fmt.Errorf("objdiff: decode the dry-run result: %w", err)
	}

	var requestedPaths []string
	if len(patch) > 0 {
		var patchObj map[string]any
		if err := json.Unmarshal(patch, &patchObj); err == nil {
			for _, p := range leafPaths(patchObj, "") {
				// The precondition is machinery, not a requested change: every
				// patch embeds it, and it is suppressed from the diff anyway.
				if p != "metadata.resourceVersion" {
					requestedPaths = append(requestedPaths, p)
				}
			}
		}
	}

	// Initialised non-nil so the JSON carries `[]` rather than `null`. A client
	// rendering a diff should never have to tell "nothing changed" from "the
	// field was omitted", and every consumer would otherwise need the same
	// null guard.
	res := Result{Requested: []Change{}, Additional: []Change{}, Suppressed: []string{}}
	for _, c := range walk(beforeObj, afterObj, "") {
		if suppressed(c.Path) {
			res.Suppressed = append(res.Suppressed, c.Path)
			continue
		}
		if requestedChange(c.Path, requestedPaths) {
			res.Requested = append(res.Requested, c)
		} else {
			res.Additional = append(res.Additional, c)
		}
	}
	sort.Slice(res.Requested, func(i, j int) bool { return res.Requested[i].Path < res.Requested[j].Path })
	sort.Slice(res.Additional, func(i, j int) bool { return res.Additional[i].Path < res.Additional[j].Path })
	sort.Strings(res.Suppressed)
	return res, nil
}

// requestedChange reports whether a change at changePath was asked for by a
// patch whose leaves are requestedPaths.
//
// Matching runs in BOTH directions, and both are needed for real patches:
//
//   - A requested path can be a prefix of the change. A patch that replaces a
//     whole subtree (`spec.template.spec.containers[web].resources` set to a new
//     map) produces one requested leaf per value inside it, but the diff may
//     report the change at a deeper path still.
//   - A change path can be a prefix of the requested path. This is the common
//     one and the easy one to miss: when a patch sets
//     `...resources.limits.memory` on a container that had no `resources` at
//     all, the diff reports a single Added at `...resources` — the whole new
//     subtree — while the requested leaf is three levels deeper. Exact matching
//     would file the plan's own change under "the cluster did this too", which
//     is the most misleading output this package could produce.
//
// Boundaries are checked explicitly so `spec.replicas` never claims
// `spec.replicasHistory`, and a list index/key opens with `[` rather than `.`.
func requestedChange(changePath string, requestedPaths []string) bool {
	for _, r := range requestedPaths {
		if changePath == r || isUnder(changePath, r) || isUnder(r, changePath) {
			return true
		}
	}
	return false
}

// isUnder reports whether child is a strict descendant path of parent.
func isUnder(child, parent string) bool {
	if !strings.HasPrefix(child, parent) || len(child) == len(parent) {
		return false
	}
	switch child[len(parent)] {
	case '.', '[':
		return true
	default:
		return false
	}
}

func suppressed(path string) bool {
	for _, p := range suppressedPaths {
		// isUnder rather than a `p+"."` prefix test, because a suppressed
		// subtree can continue with a list index as well as a field name:
		// `metadata.managedFields[0].manager` is under `metadata.managedFields`
		// and a dot-only check misses every entry inside it. Caught by a test
		// asserting no bookkeeping field reaches the reviewer, which is the
		// only reason it was noticed.
		if path == p || isUnder(path, p) {
			return true
		}
	}
	for seg := range suppressedLeaf {
		if path == seg || strings.HasSuffix(path, "."+seg) {
			return true
		}
	}
	for _, suf := range suppressedLeafSuffix {
		// Matched against the whole path because a path always ends with its
		// leaf key, so this is a leaf-name test without having to re-split it.
		if strings.HasSuffix(path, suf) {
			return true
		}
	}
	return false
}

// walk recursively compares two values, emitting one Change per differing leaf.
func walk(before, after any, path string) []Change {
	switch b := before.(type) {
	case map[string]any:
		a, ok := after.(map[string]any)
		if !ok {
			return []Change{{Path: path, Before: before, After: after}}
		}
		return walkMap(b, a, path)
	case []any:
		a, ok := after.([]any)
		if !ok {
			return []Change{{Path: path, Before: before, After: after}}
		}
		return walkList(b, a, path)
	default:
		if equalScalar(before, after) {
			return nil
		}
		return []Change{{Path: path, Before: before, After: after}}
	}
}

func walkMap(before, after map[string]any, path string) []Change {
	var out []Change
	for _, k := range sortedKeys(before, after) {
		bv, inB := before[k]
		av, inA := after[k]
		child := join(path, k)
		switch {
		case inB && !inA:
			out = append(out, Change{Path: child, Before: bv, Removed: true})
		case !inB && inA:
			out = append(out, Change{Path: child, After: av, Added: true})
		default:
			out = append(out, walk(bv, av, child)...)
		}
	}
	return out
}

// walkList matches elements by their merge key where one exists, and by
// position otherwise.
//
// Matching by key rather than by index is what keeps a diff honest when a
// mutating webhook INSERTS an element — a sidecar injector prepending a
// container, say. By index, every subsequent container would appear to have had
// every field rewritten, burying the one real change in a wall of noise. By key,
// the inserted container shows up as exactly one added element.
func walkList(before, after []any, path string) []Change {
	key := listKey(before, after)
	if key == "" {
		return walkListByIndex(before, after, path)
	}

	index := func(items []any) (map[string]any, []string) {
		byKey, order := map[string]any{}, []string(nil)
		for _, item := range items {
			m, ok := item.(map[string]any)
			if !ok {
				return nil, nil // heterogeneous; fall back to positional
			}
			name, ok := m[key].(string)
			if !ok {
				return nil, nil
			}
			byKey[name] = item
			order = append(order, name)
		}
		return byKey, order
	}
	beforeByKey, beforeOrder := index(before)
	afterByKey, afterOrder := index(after)
	if beforeByKey == nil || afterByKey == nil {
		return walkListByIndex(before, after, path)
	}

	var out []Change
	seen := map[string]bool{}
	for _, name := range append(beforeOrder, afterOrder...) {
		if seen[name] {
			continue
		}
		seen[name] = true
		child := fmt.Sprintf("%s[%s]", path, name)
		bv, inB := beforeByKey[name]
		av, inA := afterByKey[name]
		switch {
		case inB && !inA:
			out = append(out, Change{Path: child, Before: bv, Removed: true})
		case !inB && inA:
			out = append(out, Change{Path: child, After: av, Added: true})
		default:
			out = append(out, walk(bv, av, child)...)
		}
	}
	return out
}

func walkListByIndex(before, after []any, path string) []Change {
	var out []Change
	for i := 0; i < max(len(before), len(after)); i++ {
		child := fmt.Sprintf("%s[%d]", path, i)
		switch {
		case i >= len(after):
			out = append(out, Change{Path: child, Before: before[i], Removed: true})
		case i >= len(before):
			out = append(out, Change{Path: child, After: after[i], Added: true})
		default:
			out = append(out, walk(before[i], after[i], child)...)
		}
	}
	return out
}

// listKey picks the field to match list elements on.
//
// `name` covers essentially every list ARGUS can touch — containers, volumes,
// volumeMounts, env, ports, initContainers — and is Kubernetes' own
// patchMergeKey for all of them. Requiring EVERY element on both sides to carry
// it means a list where the key is absent or non-unique falls back to positional
// matching rather than silently mis-pairing elements.
// listKeyCandidates are the merge keys tried, in order, before falling back to
// positional paths.
//
// `name` covers containers, volumes, named ports and most of what ARGUS
// patches. `type` was added after a live preflight rendered
// `status.conditions[0].lastTransitionTime` — a Kubernetes condition's merge
// key is `type`, not `name`, so conditions fell through to index paths, and by
// this file's own standard `conditions[0]` is "a lookup task" where
// `conditions[Available]` is reviewable. Order matters only for a list
// carrying both, where `name` is the more specific identifier.
//
// Deliberately short. A wrong merge key is worse than a positional path: it
// would pair up two elements that are not the same thing and render their
// differences as one element changing.
var listKeyCandidates = []string{"name", "type"}

func listKey(before, after []any) string {
	if len(before) == 0 && len(after) == 0 {
		return ""
	}
	for _, key := range listKeyCandidates {
		if usableAsListKey(before, after, key) {
			return key
		}
	}
	return ""
}

// usableAsListKey reports whether every element on both sides carries `key` as
// a non-empty string AND it is unique within each side — the conditions under
// which keying is safe. Uniqueness is checked per side, not across both,
// because an element appearing on one side only is exactly the add/remove this
// package exists to report.
func usableAsListKey(before, after []any, key string) bool {
	for _, items := range [][]any{before, after} {
		seen := map[string]bool{}
		for _, item := range items {
			m, ok := item.(map[string]any)
			if !ok {
				return false
			}
			name, ok := m[key].(string)
			if !ok || name == "" {
				return false
			}
			if seen[name] {
				return false // duplicate within a side; positional is safer
			}
			seen[name] = true
		}
	}
	return true
}

// leafPaths enumerates every leaf path in a patch body, which is how the
// requested set is derived. A patch's leaves ARE the fields it asks to change,
// so this needs no knowledge of action types.
func leafPaths(v any, path string) []string {
	switch t := v.(type) {
	case map[string]any:
		var out []string
		for k, child := range t {
			out = append(out, leafPaths(child, join(path, k))...)
		}
		return out
	case []any:
		// Recursed with the SAME key-based path format walkList produces, so a
		// patch naming one container yields
		// `...containers[web].resources.limits.memory` and matches the diff
		// entry for exactly that container. Claiming the whole `containers`
		// list instead would be much simpler and actively harmful: a sidecar
		// injector's change to `containers[istio-proxy].image` would then count
		// as "requested" and be filed under what the approver already expected,
		// which is precisely the change they most need to see.
		var out []string
		for i, item := range t {
			child := fmt.Sprintf("%s[%d]", path, i)
			if m, ok := item.(map[string]any); ok {
				if name, ok := m["name"].(string); ok && name != "" {
					child = fmt.Sprintf("%s[%s]", path, name)
				}
			}
			out = append(out, leafPaths(item, child)...)
		}
		return out
	default:
		if path == "" {
			return nil
		}
		return []string{path}
	}
}

func sortedKeys(maps ...map[string]any) []string {
	set := map[string]bool{}
	for _, m := range maps {
		for k := range m {
			set[k] = true
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// equalScalar compares two JSON scalars. Numbers need care: encoding/json
// decodes every number into float64 for `any`, but a value that arrived through
// a different path (a typed struct, a re-marshal) can be an int64 or a
// json.Number, and comparing those with == would report a spurious change for
// two identical numbers.
func equalScalar(a, b any) bool {
	if af, aok := asFloat(a); aok {
		if bf, bok := asFloat(b); bok {
			return af == bf
		}
		return false
	}
	return a == b
}

func asFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	default:
		return 0, false
	}
}
