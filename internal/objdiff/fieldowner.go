package objdiff

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Field-level ownership from `metadata.managedFields`.
//
// DESIGN.md §11.2 rung 4: "which field manager last set the fields we intend to
// change. Weaker signal, but excellent for detecting *contention* — a controller
// you didn't tell me about also owns this field." BACKLOG.md F16 item 1 calls it
// "the one that matters", and says to build it with F11 rather than after.
//
// # Why this is a different question from the ownership ARGUS already answers
//
// `get_gitops_ownership` answers "who owns this OBJECT" — an Argo CD Application,
// a Flux Kustomization, a Helm release. That is the right question for "where does
// the durable fix live", and it is the wrong question for "will this patch stick".
// A Deployment can be Argo-managed while the specific field ARGUS wants to change
// is owned by nobody — a `replicas` the chart does not set, an annotation added by
// hand — and in that case an in-place patch holds perfectly well.
//
// So today's guardrail is imprecise in both directions. It refuses (pending
// confirmation) every patch to an Argo-managed object, including the ones that
// would have held; and when it does refuse, it can only say "this object is
// GitOps-managed" rather than "`spec.replicas` is managed by
// `argocd-application-controller`, so this patch is reverted on the next sync".
//
// # The encoding, which is the whole difficulty
//
// `fieldsV1` is a nested set, not a list of paths. Keys are prefixed:
//
//	f:spec → the field "spec"
//	k:{"name":"web"} → the list element whose merge key matches this JSON
//	v:"value" → a set element identified by its own value
//	i:3 → a list element by index (only for lists with no merge key)
//
// A manager owning a whole subtree is represented by owning its parent key with an
// empty object beneath, so ownership of `spec.replicas` can appear as
// `{"f:spec":{"f:replicas":{}}}` — and ownership of everything under `spec` as
// `{"f:spec":{}}`. Both must count as owning `spec.replicas`, which is why this
// walks rather than string-matches.

// FieldOwner is one manager's claim on a path.
type FieldOwner struct {
	// Manager is the field manager's name, e.g. "argocd-controller",
	// "kube-controller-manager", "argus-remediate".
	Manager string
	// Operation is "Apply" or "Update". Worth carrying because they mean
	// different things about what happens next: an Apply manager will reassert
	// its value on every sync, while an Update manager merely set it once.
	Operation string
	// Exact is true when the manager claims this leaf specifically, false when it
	// claims an ancestor and therefore this path by containment. Both are real
	// ownership; the distinction is useful in a message ("owns spec.replicas" vs
	// "owns everything under spec").
	Exact bool
}

// OwnersOf returns every manager claiming path, most specific first.
//
// path is in this package's own notation — the one Diff produces and the preflight
// response already shows an operator: dotted, with keyed list elements as
// `containers[web]`. Reusing it means a caller can hand a Change.Path straight
// here without translating, and there is one path grammar in the product rather
// than two.
//
// Returns nil when nothing claims the path, which is a real and common answer: it
// means an in-place patch to that field will hold.
func OwnersOf(object map[string]any, path string) []FieldOwner {
	entries, _ := nestedSlice(object, "metadata", "managedFields")
	if len(entries) == 0 {
		return nil
	}
	segments := parsePath(path)
	if len(segments) == 0 {
		return nil
	}

	var owners []FieldOwner
	for _, raw := range entries {
		entry, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		manager, _ := entry["manager"].(string)
		operation, _ := entry["operation"].(string)
		if manager == "" {
			continue
		}
		fields, ok := entry["fieldsV1"].(map[string]any)
		if !ok {
			continue
		}
		if exact, owns := claims(fields, segments); owns {
			owners = append(owners, FieldOwner{Manager: manager, Operation: operation, Exact: exact})
		}
	}
	// Exact claims first, then alphabetical, so a message names the manager that
	// actually set this field before one that owns an ancestor — and so the order
	// is stable for tests and for anything that renders it.
	sort.SliceStable(owners, func(i, j int) bool {
		if owners[i].Exact != owners[j].Exact {
			return owners[i].Exact
		}
		return owners[i].Manager < owners[j].Manager
	})
	return owners
}

// claims walks a fieldsV1 set against a parsed path.
//
// Returns (exact, owns). An empty node means "everything below here", so the walk
// stops there and reports ownership by containment rather than continuing into
// segments the set does not mention.
func claims(node map[string]any, segments []pathSegment) (bool, bool) {
	for i, seg := range segments {
		if len(node) == 0 {
			// The manager owns this whole subtree. Every remaining segment is
			// covered — by containment, not exactly.
			return false, true
		}
		child, ok := node[seg.key()]
		if !ok {
			return false, false
		}
		next, ok := child.(map[string]any)
		if !ok {
			// A non-object value here means the set is malformed. Treated as not
			// owning: an unreadable claim must not be reported as ownership, since
			// a false positive would refuse a patch that would have been fine.
			return false, false
		}
		if i == len(segments)-1 {
			return true, true
		}
		node = next
	}
	return false, false
}

// pathSegment is one step of a dotted path, with the list key if it had one.
type pathSegment struct {
	field string
	// listKey is the value inside brackets: `containers[web]` → "web". Empty for
	// a plain field.
	listKey string
}

// key renders this segment in fieldsV1's own encoding.
func (s pathSegment) key() string {
	if s.listKey == "" {
		return "f:" + s.field
	}
	// A keyed list element. Kubernetes writes the merge key as canonical JSON,
	// and for every list this product patches the merge key is `name` — pod
	// containers, ports, volumes, env. Marshalled rather than concatenated so the
	// quoting and escaping match what the API server wrote.
	keyJSON, err := json.Marshal(map[string]string{"name": s.listKey})
	if err != nil {
		return "f:" + s.field
	}
	return "k:" + string(keyJSON)
}

// parsePath splits this package's dotted notation into segments.
//
// A keyed element becomes TWO segments — the list field itself, then the element —
// because that is how fieldsV1 nests them: `f:containers` then `k:{"name":"web"}`.
func parsePath(path string) []pathSegment {
	var out []pathSegment
	for _, part := range strings.Split(path, ".") {
		if part == "" {
			continue
		}
		open := strings.Index(part, "[")
		if open < 0 || !strings.HasSuffix(part, "]") {
			out = append(out, pathSegment{field: part})
			continue
		}
		field := part[:open]
		key := part[open+1 : len(part)-1]
		if field == "" || key == "" {
			out = append(out, pathSegment{field: part})
			continue
		}
		out = append(out, pathSegment{field: field}, pathSegment{field: field, listKey: key})
	}
	return out
}

// DescribeContention names which manager owns the field, or returns "" when
// nothing does.
//
// Written here rather than at the call site because the *interesting* case is the
// negative one and it is easy to get backwards: no owner means an in-place patch
// has nothing contesting it, which is the opposite of what "no ownership
// information" sounds like. Callers get a sentence or an empty string, and an
// empty string means "nothing contends", never "we could not tell".
//
// # It deliberately does NOT predict whether the value comes back
//
// The first version of this drew that conclusion from the `operation` field:
// Apply meant "a controller reconciling from desired state, so it will reassert
// this", Update meant "a one-off write". Live data on a real Argo CD installation
// disproved it — `argocd-controller` claims `spec.replicas` with operation
// **Update**, and WORKLOG §145's Phase 7 run watched Argo revert exactly that
// field within twenty seconds.
//
// The reason is that reversion is a property of the CONTROLLER, not of the field
// management operation: Argo's self-heal is a reconcile loop that compares live
// against Git and corrects the difference, whichever apply mode wrote the field.
// So predicting reversion from `operation` is unsound in the dangerous direction —
// it would have told an operator their patch merely "overwrites another manager's
// value" about a field that gets rewritten a few seconds later.
//
// Whether a reconciler owns the object is something the caller already knows from
// DESIGN.md §11.2's higher rungs (Argo tracking metadata, Flux labels, Helm
// release), and it is the caller that says the reversion part. This function's job
// is the part only managedFields can answer: which field, and which manager.
// Operation is still carried on FieldOwner because it is real information; nothing
// concludes from it any more.
func DescribeContention(path string, owners []FieldOwner, ignore ...string) string {
	skip := map[string]bool{}
	for _, m := range ignore {
		skip[m] = true
	}
	var named []string
	for _, o := range owners {
		if skip[o.Manager] {
			continue
		}
		named = append(named, o.Manager)
	}
	if len(named) == 0 {
		return ""
	}
	return fmt.Sprintf("%s is currently managed by %s", path, strings.Join(named, ", "))
}

// nestedSlice reads a []any at a path, mirroring unstructured's helper without
// depending on it: this package deliberately has no Kubernetes imports, so it
// stays testable against plain decoded JSON.
func nestedSlice(obj map[string]any, fields ...string) ([]any, bool) {
	var cur any = obj
	for _, f := range fields {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[f]
		if !ok {
			return nil, false
		}
	}
	s, ok := cur.([]any)
	return s, ok
}
