package gitopsinsight

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// DriftOp is how a field differs between the desired and the live object.
type DriftOp string

const (
	DriftOpAdded   DriftOp = "added"   // only live has it
	DriftOpRemoved DriftOp = "removed" // only desired has it
	DriftOpChanged DriftOp = "changed" // both have it, with different values
)

// DriftSource is where the desired side of a comparison came from.
type DriftSource string

const (
	// DriftSourceRepository: the desired object was read from the bound
	// repository at the synced revision and compared with DiffObjects.
	DriftSourceRepository DriftSource = "repository"
	// DriftSourceLastApplied: the desired object is the one recorded in the
	// kubectl.kubernetes.io/last-applied-configuration annotation.
	DriftSourceLastApplied DriftSource = "lastApplied"
)

// DriftEntryCap is the most entries one object reports: enough for a field
// table a person can read, and a bound on the payload. Anyone who needs every
// difference reads the two manifests.
const DriftEntryCap = 50

// DriftEntry is one differing field. Path joins keys with dots and writes a
// list index in brackets — spec.template.spec.containers.[0].image — and
// Desired and Live are that field's value on each side as one-line JSON
// (strings stay quoted), empty on the side that lacks it.
//
// Values are copied as found. Whether one is sensitive depends on its path
// (env[*].value, ConfigMap data), and redacting it before it leaves the
// process is the caller's job.
type DriftEntry struct {
	Path    string  `json:"path"`
	Op      DriftOp `json:"op"`
	Desired string  `json:"desired,omitempty"`
	Live    string  `json:"live,omitempty"`
}

// Drift is one object's drift as a tool returns it. UnavailableReason is set,
// with no entries, when drift could not be worked out at all — which is not
// the same as having worked it out and found nothing.
type Drift struct {
	Source            DriftSource  `json:"source,omitempty"`
	Entries           []DriftEntry `json:"entries"`
	Truncated         bool         `json:"truncated,omitempty"`
	UnavailableReason string       `json:"unavailableReason,omitempty"`
	// Controller is the GitOps controller's own verdict on the object where
	// it keeps one. Argo CD compares each managed resource with the rendered
	// desired state and records Synced or OutOfSync for it: whether the
	// object drifted, not which fields, but it also covers objects applied
	// server-side or by Helm, which last-applied drift cannot see.
	Controller *ControllerSync `json:"controller,omitempty"`
}

// ControllerSync is one resource's sync verdict from its GitOps controller.
type ControllerSync struct {
	Controller  string `json:"controller"`  // "Argo CD"
	Application string `json:"application"` // namespace/name
	Status      string `json:"status"`      // Synced, OutOfSync, Unknown
	Health      string `json:"health,omitempty"`
}

// ArgoResourceSync looks one object up in an Argo CD Application's
// status.resources; ok is false when the Application does not list it.
func ArgoResourceSync(app map[string]any, group, kind, namespace, name string) (ControllerSync, bool) {
	text := func(m map[string]any, key string) string { s, _ := m[key].(string); return s }
	meta, _ := app["metadata"].(map[string]any)
	appID := text(meta, "name")
	if ns := text(meta, "namespace"); ns != "" {
		appID = ns + "/" + appID
	}
	status, _ := app["status"].(map[string]any)
	resources, _ := status["resources"].([]any)
	for _, item := range resources {
		r, _ := item.(map[string]any)
		if text(r, "group") != group || text(r, "kind") != kind || text(r, "namespace") != namespace || text(r, "name") != name {
			continue
		}
		verdict := ControllerSync{Controller: "Argo CD", Application: appID, Status: "Unknown"}
		if s := text(r, "status"); s != "" {
			verdict.Status = s
		}
		if h, _ := r["health"].(map[string]any); h != nil {
			verdict.Health = text(h, "status")
		}
		return verdict, true
	}
	return ControllerSync{}, false
}

// DiffObjects compares a desired and a live manifest field by field, keeping
// to what a person declares: `status` is the controller's observation and is
// skipped, and of `metadata` only labels and annotations are compared — the
// rest (uid, resourceVersion, generation, managedFields, timestamps) is the
// server's and is never drift. The result is sorted by path and cut at
// DriftEntryCap, truncated saying whether anything was cut.
func DiffObjects(desired, live map[string]any) (entries []DriftEntry, truncated bool) {
	var d differ
	for _, key := range keysOf(desired, live) {
		switch key {
		case "status":
		case "metadata":
			want, _ := desired["metadata"].(map[string]any)
			have, _ := live["metadata"].(map[string]any)
			d.walk("metadata.labels", want["labels"], have["labels"])
			d.walk("metadata.annotations", want["annotations"], have["annotations"])
		default:
			d.walk(key, desired[key], live[key])
		}
	}
	return capped(d.found)
}

// capped sorts entries by path and then cuts them at DriftEntryCap, so which
// entries survive the cut never depends on map order. Both drift sources end
// here, so they cannot disagree on either.
func capped(entries []DriftEntry) ([]DriftEntry, bool) {
	slices.SortStableFunc(entries, func(a, b DriftEntry) int { return strings.Compare(a.Path, b.Path) })
	if len(entries) <= DriftEntryCap {
		return entries, false
	}
	return entries[:DriftEntryCap], true
}

// differ collects the differences between two decoded JSON trees.
type differ struct{ found []DriftEntry }

// walk compares want (desired) with have (live) at path. Objects are compared
// key by key over both sides' keys, and lists element by element at the same
// index — Kubernetes keeps list order between what was applied and what it
// reports, so a lengthened or shortened list shows its extra or missing
// elements at their index. A value present on only one side is one entry at
// that path, not one per field beneath it; anything else is compared by its
// JSON encoding.
func (d *differ) walk(path string, want, have any) {
	switch {
	case absent(want) && absent(have):
		return
	case absent(want):
		d.note(DriftEntry{Path: path, Op: DriftOpAdded, Live: encode(have)})
		return
	case absent(have):
		d.note(DriftEntry{Path: path, Op: DriftOpRemoved, Desired: encode(want)})
		return
	}
	if wm, ok := want.(map[string]any); ok {
		if hm, ok := have.(map[string]any); ok {
			for _, k := range keysOf(wm, hm) {
				d.walk(child(path, k), wm[k], hm[k])
			}
			return
		}
	}
	if wl, ok := want.([]any); ok {
		if hl, ok := have.([]any); ok {
			for i := range max(len(wl), len(hl)) {
				d.walk(child(path, strconv.Itoa(i)), at(wl, i), at(hl, i))
			}
			return
		}
	}
	// Scalars, or a shape that changed between the two (a schema change).
	if w, h := encode(want), encode(have); w != h {
		d.note(DriftEntry{Path: path, Op: DriftOpChanged, Desired: w, Live: h})
	}
}

func (d *differ) note(e DriftEntry) { d.found = append(d.found, e) }

func at(list []any, i int) any {
	if i < len(list) {
		return list[i]
	}
	return nil
}

// keysOf is the sorted union of two objects' keys.
func keysOf(a, b map[string]any) []string {
	all := maps.Clone(a)
	if all == nil {
		all = map[string]any{}
	}
	maps.Copy(all, b)
	return slices.Sorted(maps.Keys(all))
}

// child extends a path by one key, or by one list index written "[i]".
func child(path, segment string) string {
	switch {
	case path == "":
		return segment
	case segment != "" && strings.Trim(segment, "0123456789") == "":
		return path + ".[" + segment + "]"
	}
	return path + "." + segment
}

// absent counts nil, {}, [] and "" as the same nothing, so a field one side
// defaulted to an empty value is not a difference.
func absent(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case map[string]any:
		return len(x) == 0
	case []any:
		return len(x) == 0
	case string:
		return x == ""
	}
	return false
}

// encode is a value as stable one-line JSON: object keys sorted (as
// encoding/json does), strings quoted so "true" and true stay different.
func encode(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// dotPath turns an RFC 6901 JSON pointer (/spec/containers/0) into the path
// form entries use (spec.containers.[0]).
func dotPath(pointer string) string {
	path := ""
	for _, seg := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		path = child(path, strings.NewReplacer("~1", "/", "~0", "~").Replace(seg))
	}
	return path
}

// filterIgnoredPaths drops the entries at or beneath any of the JSON
// pointers, matching whole segments only: /spec/replic does not touch
// spec.replicas. The input slice is left as it was.
func filterIgnoredPaths(entries []DriftEntry, pointers []string) []DriftEntry {
	var roots []string
	for _, p := range pointers {
		if p = strings.TrimSpace(p); p != "" {
			roots = append(roots, dotPath(p))
		}
	}
	if len(roots) == 0 {
		return entries
	}
	under := func(e DriftEntry) bool {
		return slices.ContainsFunc(roots, func(r string) bool { return e.Path == r || strings.HasPrefix(e.Path, r+".") })
	}
	return slices.DeleteFunc(slices.Clone(entries), under)
}
