package objdiff

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// find returns the change at path, or fails.
func find(t *testing.T, changes []Change, path string) Change {
	t.Helper()
	for _, c := range changes {
		if c.Path == path {
			return c
		}
	}
	var got []string
	for _, c := range changes {
		got = append(got, c.Path)
	}
	t.Fatalf("no change at %q; got %v", path, got)
	return Change{}
}

func paths(changes []Change) []string {
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		out = append(out, c.Path)
	}
	return out
}

func TestCompute_RequestedChangeIsClassifiedAsRequested(t *testing.T) {
	before := json.RawMessage(`{"spec":{"replicas":2}}`)
	after := json.RawMessage(`{"spec":{"replicas":5}}`)
	patch := json.RawMessage(`{"metadata":{"resourceVersion":"100"},"spec":{"replicas":5}}`)

	res, err := Compute(before, after, patch)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if len(res.Additional) != 0 {
		t.Errorf("a plain requested change produced unrequested entries: %v", paths(res.Additional))
	}
	c := find(t, res.Requested, "spec.replicas")
	if fmt.Sprint(c.Before) != "2" || fmt.Sprint(c.After) != "5" {
		t.Errorf("spec.replicas: before=%v after=%v, want 2 -> 5", c.Before, c.After)
	}
}

// The whole reason this package classifies rather than just diffs. A mutating
// webhook rewriting something nobody asked for is the highest-value thing a
// dry run can reveal, and it must not be filed under "what you asked for".
func TestCompute_WhatTheClusterAlsoDidIsSeparatedOut(t *testing.T) {
	before := json.RawMessage(`{"spec":{"replicas":2,"template":{"spec":{"containers":[{"name":"web","image":"app:1.0"}]}}}}`)
	// The cluster honoured the scale AND a webhook rewrote the image registry
	// and injected a sidecar.
	after := json.RawMessage(`{"spec":{"replicas":5,"template":{"spec":{"containers":[
		{"name":"web","image":"internal.registry/app:1.0"},
		{"name":"istio-proxy","image":"proxy:1.2"}]}}}}`)
	patch := json.RawMessage(`{"spec":{"replicas":5}}`)

	res, err := Compute(before, after, patch)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if got := paths(res.Requested); len(got) != 1 || got[0] != "spec.replicas" {
		t.Errorf("requested = %v, want exactly [spec.replicas]", got)
	}

	img := find(t, res.Additional, "spec.template.spec.containers[web].image")
	if img.After != "internal.registry/app:1.0" {
		t.Errorf("rewritten image: after=%v", img.After)
	}
	side := find(t, res.Additional, "spec.template.spec.containers[istio-proxy]")
	if !side.Added {
		t.Error("an injected sidecar was not reported as an addition")
	}
}

// Matching list elements by name rather than index is what keeps an insertion
// from looking like a rewrite of every element after it.
func TestCompute_AnInsertedListElementDoesNotRewriteItsNeighbours(t *testing.T) {
	before := json.RawMessage(`{"spec":{"containers":[{"name":"web","image":"app:1"},{"name":"log","image":"log:1"}]}}`)
	// A sidecar injector PREPENDS. By index every field of every element moved.
	after := json.RawMessage(`{"spec":{"containers":[{"name":"proxy","image":"proxy:1"},{"name":"web","image":"app:1"},{"name":"log","image":"log:1"}]}}`)

	res, err := Compute(before, after, nil)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	all := append(paths(res.Requested), paths(res.Additional)...)
	if len(all) != 1 {
		t.Fatalf("an insertion produced %d changes (%v); by name it should be exactly one", len(all), all)
	}
	if all[0] != "spec.containers[proxy]" {
		t.Errorf("the single change is %q, want spec.containers[proxy]", all[0])
	}
}

// The over-claiming hazard: a patch naming ONE container must not claim a
// webhook's change to a DIFFERENT container as something the approver asked for.
func TestCompute_APatchOnOneContainerDoesNotClaimAnother(t *testing.T) {
	before := json.RawMessage(`{"spec":{"containers":[
		{"name":"web","resources":{"limits":{"memory":"256Mi"}}},
		{"name":"side","image":"side:1"}]}}`)
	after := json.RawMessage(`{"spec":{"containers":[
		{"name":"web","resources":{"limits":{"memory":"512Mi"}}},
		{"name":"side","image":"side:2"}]}}`)
	patch := json.RawMessage(`{"spec":{"containers":[{"name":"web","resources":{"limits":{"memory":"512Mi"}}}]}}`)

	res, err := Compute(before, after, patch)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if got := paths(res.Requested); len(got) != 1 || got[0] != "spec.containers[web].resources.limits.memory" {
		t.Errorf("requested = %v, want only the patched container's memory limit", got)
	}
	if got := paths(res.Additional); len(got) != 1 || got[0] != "spec.containers[side].image" {
		t.Errorf("additional = %v, want only the sibling container's image", got)
	}
}

// The bidirectional-prefix case, and the easy one to get wrong: the patch sets a
// leaf three levels below where the diff reports the change, because the whole
// subtree is new. Exact matching files the plan's own change under "the cluster
// did this too" — the most misleading output this package could produce.
func TestCompute_AWhollyNewSubtreeIsStillRequested(t *testing.T) {
	before := json.RawMessage(`{"spec":{"containers":[{"name":"web","image":"app:1"}]}}`)
	after := json.RawMessage(`{"spec":{"containers":[{"name":"web","image":"app:1","resources":{"limits":{"memory":"512Mi"}}}]}}`)
	patch := json.RawMessage(`{"spec":{"containers":[{"name":"web","resources":{"limits":{"memory":"512Mi"}}}]}}`)

	res, err := Compute(before, after, patch)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if len(res.Additional) != 0 {
		t.Errorf("the plan's own change was reported as something the cluster did: %v", paths(res.Additional))
	}
	c := find(t, res.Requested, "spec.containers[web].resources")
	if !c.Added {
		t.Error("a newly-created subtree was not marked Added")
	}
}

func TestCompute_ServerBookkeepingIsSuppressedAndCounted(t *testing.T) {
	before := json.RawMessage(`{"metadata":{"resourceVersion":"100","generation":4,"managedFields":[{"manager":"a"}],"name":"web"},"spec":{"replicas":2}}`)
	after := json.RawMessage(`{"metadata":{"resourceVersion":"101","generation":5,"managedFields":[{"manager":"b"}],"name":"web"},"spec":{"replicas":5}}`)

	res, err := Compute(before, after, json.RawMessage(`{"spec":{"replicas":5}}`))
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	all := append(paths(res.Requested), paths(res.Additional)...)
	for _, p := range all {
		if strings.HasPrefix(p, "metadata.resourceVersion") || strings.HasPrefix(p, "metadata.generation") ||
			strings.HasPrefix(p, "metadata.managedFields") {
			t.Errorf("bookkeeping field %q reached the reviewer", p)
		}
	}
	// Named, not counted: a reviewer must be able to check the filter rather
	// than trust it.
	if len(res.Suppressed) == 0 {
		t.Fatal("nothing reported as suppressed; a filtered diff must say what it filtered, or a filter bug reads as a clean diff")
	}
	for _, want := range []string{"metadata.generation", "metadata.resourceVersion"} {
		found := false
		for _, got := range res.Suppressed {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%q is not named in the suppressed list %v", want, res.Suppressed)
		}
	}
}

// status is deliberately NOT suppressed: ARGUS only patches spec and metadata,
// so a status difference in a dry run is surprising, and surprising is exactly
// what a reviewer needs to see.
func TestCompute_StatusIsNotSuppressed(t *testing.T) {
	before := json.RawMessage(`{"status":{"replicas":2}}`)
	after := json.RawMessage(`{"status":{"replicas":5}}`)
	res, err := Compute(before, after, nil)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	find(t, res.Additional, "status.replicas")
}

func TestCompute_CreationTimestampNoiseIsSuppressedAtAnyDepth(t *testing.T) {
	before := json.RawMessage(`{"spec":{"template":{"metadata":{"creationTimestamp":null}}}}`)
	after := json.RawMessage(`{"spec":{"template":{"metadata":{"creationTimestamp":"2026-08-22T00:00:00Z"}}}}`)
	res, err := Compute(before, after, nil)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if !res.Empty() {
		t.Errorf("nested creationTimestamp noise was not suppressed: %v", append(paths(res.Requested), paths(res.Additional)...))
	}
}

// A no-op diff is a real signal — usually a stale plan whose change is already
// applied — so callers need to be able to detect it rather than render a blank.
func TestCompute_IdenticalObjectsAreEmpty(t *testing.T) {
	obj := json.RawMessage(`{"spec":{"replicas":2,"containers":[{"name":"web","image":"app:1"}]}}`)
	res, err := Compute(obj, obj, nil)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if !res.Empty() {
		t.Errorf("identical objects produced a diff: %v", append(paths(res.Requested), paths(res.Additional)...))
	}
}

// Numbers arriving by different routes must not read as changes. encoding/json
// gives float64 for `any`, but a value that came through a typed struct or a
// re-marshal can be an int64, and `==` on `any` would call those different.
func TestCompute_NumbersAreComparedByValueNotByGoType(t *testing.T) {
	res := walk(map[string]any{"replicas": int64(3)}, map[string]any{"replicas": float64(3)}, "")
	if len(res) != 0 {
		t.Errorf("int64(3) and float64(3) were reported as a change: %+v", res)
	}
	if changed := walk(map[string]any{"replicas": int64(3)}, map[string]any{"replicas": float64(4)}, ""); len(changed) != 1 {
		t.Errorf("a real numeric change was missed: %+v", changed)
	}
}

// Degradation, not failure: a missing patch means the classification input is
// absent, which is a presentation detail. Refusing to show the diff at all
// would trade the reviewer's whole view for it.
func TestCompute_AMissingPatchStillProducesADiff(t *testing.T) {
	before := json.RawMessage(`{"spec":{"replicas":2}}`)
	after := json.RawMessage(`{"spec":{"replicas":5}}`)
	for name, patch := range map[string]json.RawMessage{
		"nil":          nil,
		"unparseable":  json.RawMessage(`not json`),
		"empty object": json.RawMessage(`{}`),
	} {
		t.Run(name, func(t *testing.T) {
			res, err := Compute(before, after, patch)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			if res.Empty() {
				t.Fatal("the diff was lost along with the classification")
			}
			find(t, res.Additional, "spec.replicas")
		})
	}
}

func TestCompute_RejectsAnUnreadableObject(t *testing.T) {
	if _, err := Compute(json.RawMessage(`nope`), json.RawMessage(`{}`), nil); err == nil {
		t.Error("an unreadable live object was accepted")
	}
	if _, err := Compute(json.RawMessage(`{}`), json.RawMessage(`nope`), nil); err == nil {
		t.Error("an unreadable dry-run result was accepted")
	}
}

// A list whose elements lack a usable merge key must fall back to positional
// matching rather than silently mis-pairing elements.
func TestCompute_ListsWithoutAMergeKeyFallBackToPosition(t *testing.T) {
	cases := map[string]struct{ before, after string }{
		"scalars":         {`{"a":["x","y"]}`, `{"a":["x","z"]}`},
		"no name field":   {`{"a":[{"k":1},{"k":2}]}`, `{"a":[{"k":1},{"k":9}]}`},
		"duplicate names": {`{"a":[{"name":"n","v":1},{"name":"n","v":2}]}`, `{"a":[{"name":"n","v":1},{"name":"n","v":9}]}`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			res, err := Compute(json.RawMessage(tc.before), json.RawMessage(tc.after), nil)
			if err != nil {
				t.Fatalf("Compute: %v", err)
			}
			all := append(paths(res.Requested), paths(res.Additional)...)
			if len(all) != 1 || !strings.Contains(all[0], "[1]") {
				t.Errorf("expected one positional change at index 1, got %v", all)
			}
		})
	}
}

// Path-boundary checking: a prefix match must not let one field claim a
// differently-named sibling that merely starts with the same letters.
func TestRequestedChange_RespectsPathBoundaries(t *testing.T) {
	requested := []string{"spec.replicas"}
	if !requestedChange("spec.replicas", requested) {
		t.Error("an exact path did not match")
	}
	if requestedChange("spec.replicasHistory", requested) {
		t.Error("spec.replicas claimed spec.replicasHistory")
	}
	if !requestedChange("spec.replicas.nested", requested) {
		t.Error("a descendant by dot did not match")
	}
	if !requestedChange("spec.replicas[0]", requested) {
		t.Error("a descendant by index did not match")
	}
}

// The restart_pod shape, which is the one real action whose patch writes into
// metadata rather than spec — worth pinning so a metadata path is not
// accidentally caught by the bookkeeping suppression list.
func TestCompute_RolloutRestartAnnotationIsRequestedNotSuppressed(t *testing.T) {
	before := json.RawMessage(`{"spec":{"template":{"metadata":{"annotations":{"a":"1"}}}}}`)
	after := json.RawMessage(`{"spec":{"template":{"metadata":{"annotations":{"a":"1","argus.io/restartedAt":"2026-08-22T10:00:00Z"}}}}}`)
	patch := json.RawMessage(`{"metadata":{"resourceVersion":"7"},"spec":{"template":{"metadata":{"annotations":{"argus.io/restartedAt":"2026-08-22T10:00:00Z"}}}}}`)

	res, err := Compute(before, after, patch)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if len(res.Additional) != 0 {
		t.Errorf("the restart annotation was not recognised as requested: %v", paths(res.Additional))
	}
	c := find(t, res.Requested, "spec.template.metadata.annotations.argus.io/restartedAt")
	if !c.Added {
		t.Error("a newly-added annotation was not marked Added")
	}
}

// TestCompute_ArgusOwnRelativeTimeFieldsAreSuppressed reproduces exactly what a
// reviewer saw on a live incident before this filter existed.
//
// Approving a two-field PatchResourceLimits on argus-e2e-rke2/checkout-oom
// rendered "3 additional changes" on the preflight screen:
// metadata.creationTimestampSecondsSince and two
// status.conditions[N].lastTransitionTimeSecondsSince. Every one was ARGUS's
// own relative-time annotation (internal/agent/relative_time.go), which is
// recomputed against `now` on each observation and so differs between the two
// halves of any dry-run comparison by construction. None was a change the
// cluster would have made.
//
// The failure mode this guards is not a wrong number, it is a reviewer learning
// that the "additional" section is noise and skipping it — on the one screen
// whose entire purpose is to show what nobody asked for.
func TestCompute_ArgusOwnRelativeTimeFieldsAreSuppressed(t *testing.T) {
	before := json.RawMessage(`{
		"metadata":{"creationTimestamp":"2026-09-19T13:30:12Z","creationTimestampSecondsSince":330},
		"spec":{"replicas":1},
		"status":{"conditions":[
			{"type":"Available","lastTransitionTime":"2026-09-19T13:30:40Z","lastTransitionTimeSecondsSince":302}]}}`)
	// Same object observed a few seconds later: every injected counter has
	// moved, the real timestamps have not, and the patch landed.
	after := json.RawMessage(`{
		"metadata":{"creationTimestamp":"2026-09-19T13:30:12Z","creationTimestampSecondsSince":338},
		"spec":{"replicas":3},
		"status":{"conditions":[
			{"type":"Available","lastTransitionTime":"2026-09-19T13:30:40Z","lastTransitionTimeSecondsSince":310}]}}`)
	patch := json.RawMessage(`{"spec":{"replicas":3}}`)

	res, err := Compute(before, after, patch)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if len(res.Additional) != 0 {
		t.Errorf("ARGUS's own relative-time annotations reached the reviewer as cluster changes: %v", paths(res.Additional))
	}
	// Dropped, but still named — the package's own standard is that a reviewer
	// can audit the filter rather than trust it.
	for _, want := range []string{
		"metadata.creationTimestampSecondsSince",
		// Keyed by `type`: a condition's Kubernetes merge key is `type`, which
		// listKeyCandidates now tries after `name`.
		"status.conditions[Available].lastTransitionTimeSecondsSince",
	} {
		found := false
		for _, s := range res.Suppressed {
			if s == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was filtered without being named in Suppressed; got %v", want, res.Suppressed)
		}
	}
	// The real change must survive, or the filter has eaten the point.
	find(t, res.Requested, "spec.replicas")
}

// TestCompute_ASecondsFieldThatIsNotAnAnnotationSurvives is the other half: the
// suffixes are long and specific on purpose. Kubernetes has real spec fields
// ending in "Seconds", and suppressing those would hide genuine cluster
// defaulting — the exact over-suppression objdiff's own comment warns about.
func TestCompute_ASecondsFieldThatIsNotAnAnnotationSurvives(t *testing.T) {
	before := json.RawMessage(`{"spec":{"template":{"spec":{"terminationGracePeriodSeconds":30}}}}`)
	after := json.RawMessage(`{"spec":{"template":{"spec":{"terminationGracePeriodSeconds":60}}}}`)
	patch := json.RawMessage(`{"spec":{"replicas":3}}`)

	res, err := Compute(before, after, patch)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	find(t, res.Additional, "spec.template.spec.terminationGracePeriodSeconds")
}
