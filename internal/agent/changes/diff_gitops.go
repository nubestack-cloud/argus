package changes

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"argus/internal/gitopsinsight"
)

// sides reads the same field from both snapshots.
type sides struct{ was, is map[string]any }

func sidesOf(a, b *unstructured.Unstructured) sides { return sides{a.Object, b.Object} }

// status is the pair of status blocks.
func (s sides) status() sides {
	a, _, _ := unstructured.NestedMap(s.was, "status")
	b, _, _ := unstructured.NestedMap(s.is, "status")
	return sides{a, b}
}

func (s sides) str(path ...string) (string, string) {
	a, _, _ := unstructured.NestedString(s.was, path...)
	b, _, _ := unstructured.NestedString(s.is, path...)
	return a, b
}

func (s sides) num(path ...string) (int64, int64) {
	a, _, _ := unstructured.NestedInt64(s.was, path...)
	b, _, _ := unstructured.NestedInt64(s.is, path...)
	return a, b
}

func (s sides) strs(path ...string) ([]string, []string) {
	a, _, _ := unstructured.NestedStringSlice(s.was, path...)
	b, _, _ := unstructured.NestedStringSlice(s.is, path...)
	return a, b
}

func (s sides) count(path ...string) (int, int) {
	a, _, _ := unstructured.NestedSlice(s.was, path...)
	b, _, _ := unstructured.NestedSlice(s.is, path...)
	return len(a), len(b)
}

// moved records a string field that changed to something set, with the
// "label: a→b" summary; set on both sides is required when both is true.
func (d *delta) moved(path, label, a, b string, both bool) {
	if a == b || b == "" || both && a == "" {
		return
	}
	d.add(path, a, b, fmt.Sprintf("%s: %s→%s", label, a, b))
}

// revision records a revision that moved to a new one, shortened by short;
// the first revision seen reads "label: new".
func (d *delta) revision(path, label, a, b string, short func(string) string) {
	if a == b || b == "" {
		return
	}
	text := label + ": " + short(b)
	if a != "" {
		text = label + ": " + short(a) + "→" + short(b)
	}
	d.add(path, short(a), short(b), text)
}

// diffApplication covers an Argo CD Application: sync and health, the synced
// revision, sync operations, the auto-sync policy, where it deploys, its
// conditions, and images rolled.
func diffApplication(oldObj, newObj any) ([]FieldChange, []string) {
	oldApp, newApp, ok := unstructuredPair(oldObj, newObj)
	if !ok {
		return nil, nil
	}
	app := sidesOf(oldApp, newApp)
	st := app.status()
	var d delta

	a, b := st.str("sync", "status")
	d.moved("status.sync.status", "sync", a, b, true)
	a, b = st.str("health", "status")
	d.moved("status.health.status", "health", a, b, true)
	a, b = st.str("sync", "revision")
	d.revision("status.sync.revision", "revision", a, b, truncateRevision)
	d.operation(st)

	_, wasAuto, _ := unstructured.NestedMap(oldApp.Object, "spec", "syncPolicy", "automated")
	_, isAuto, _ := unstructured.NestedMap(newApp.Object, "spec", "syncPolicy", "automated")
	if wasAuto != isAuto {
		d.add("spec.syncPolicy.automated", wasAuto, isAuto, map[bool]string{true: "auto-sync enabled", false: "auto-sync disabled"}[isAuto])
	}
	a, b = app.str("spec", "source", "targetRevision")
	d.moved("spec.source.targetRevision", "target", a, b, false)
	a, b = app.str("spec", "destination", "namespace")
	d.moved("spec.destination.namespace", "destination ns", a, b, false)

	// Argo's own conditions (SyncError, ComparisonError, the
	// *ResourceWarnings) flip on configuration problems that neither sync
	// nor health shows. New and changed ones first, then the cleared.
	before, after := getConditionMap(st.was, "conditions"), getConditionMap(st.is, "conditions")
	for _, t := range slices.Sorted(maps.Keys(after)) {
		if before[t] != after[t] {
			d.add("status.conditions["+t+"]", before[t], after[t], fmt.Sprintf("%s: %s→%s", t, before[t], after[t]))
		}
	}
	for _, t := range slices.Sorted(maps.Keys(before)) {
		if _, still := after[t]; !still {
			d.add("status.conditions["+t+"]", before[t], nil, t+" cleared")
		}
	}

	// An app already Synced and Healthy rolls new images through auto-sync
	// without either moving; the image list is what shows the deploy.
	was, is := st.strs("summary", "images")
	if !slices.Equal(was, is) {
		added, removed := diffStringSlices(is, was), diffStringSlices(was, is)
		text := "images changed"
		switch {
		case len(added) > 0 && len(removed) == 0:
			text = fmt.Sprintf("images +%d", len(added))
		case len(removed) > 0 && len(added) == 0:
			text = fmt.Sprintf("images -%d", len(removed))
		}
		d.add("status.summary.images", was, is, text)
	}
	return d.result()
}

// operation records the Application's sync operation starting, finishing,
// failing (with its error, unwrapped from gRPC) or being cleared mid-run.
func (d *delta) operation(st sides) {
	oldOp, hadOp, _ := unstructured.NestedMap(st.was, "operationState")
	newOp, hasOp, _ := unstructured.NestedMap(st.is, "operationState")
	phaseOf := func(op map[string]any) string { p, _, _ := unstructured.NestedString(op, "phase"); return p }
	failure := func(op map[string]any) []string {
		if msg, _, _ := unstructured.NestedString(op, "message"); msg != "" {
			return []string{"error: " + truncateMessage(gitopsinsight.CleanArgoControllerMessage(msg))}
		}
		return nil
	}
	was, is := phaseOf(oldOp), phaseOf(newOp)
	switch {
	case !hadOp && hasOp:
		d.add("status.operationState.phase", nil, is)
		switch is {
		case "":
		case "Running":
			d.note("sync started")
		default:
			d.note("operation: " + is)
		}
		if is == "Failed" {
			d.note(failure(newOp)...)
		}
	case hadOp && hasOp && was != is && is != "":
		words := map[string]string{"Succeeded": "sync completed", "Failed": "sync failed", "Running": "sync in progress"}
		d.add("status.operationState.phase", was, is, cmp.Or(words[is], "operation: "+is))
		if is == "Failed" {
			d.note(failure(newOp)...)
		}
	case hadOp && !hasOp && was == "Running":
		d.add("status.operationState", "Running", nil, "operation cleared")
	}
}

func diffKustomization(oldObj, newObj any) ([]FieldChange, []string) {
	oldKs, newKs, ok := unstructuredPair(oldObj, newObj)
	if !ok {
		return nil, nil
	}
	ks := sidesOf(oldKs, newKs)
	st := ks.status()
	var d delta
	d.merge(fluxReadyChange(st.was, st.is))
	switch was, is := fluxCondition(st.was, "Reconciling"), fluxCondition(st.is, "Reconciling"); {
	case was == is:
	case is == "True":
		d.note("reconciling")
	case was == "True" && is == "False":
		d.note("reconcile completed")
	}
	// Stalled=True: Flux has stopped retrying, a dead end Ready alone hides.
	d.merge(fluxConditionChanges(st.was, st.is, "Stalled"))
	a, b := st.str("lastAppliedRevision")
	d.revision("status.lastAppliedRevision", "revision", a, b, truncateRevision)
	if x, y := st.count("inventory", "entries"); x != y {
		d.add("status.inventory.entries", x, y, fmt.Sprintf("resources: %d→%d", x, y))
	}
	d.merge(suspendChange(oldKs, newKs))
	a, b = ks.str("spec", "sourceRef", "name")
	d.moved("spec.sourceRef.name", "source", a, b, false)
	a, b = ks.str("spec", "path")
	d.moved("spec.path", "path", a, b, false)
	return d.result()
}

func diffFluxHelmRelease(oldObj, newObj any) ([]FieldChange, []string) {
	oldHR, newHR, ok := unstructuredPair(oldObj, newObj)
	if !ok {
		return nil, nil
	}
	hr := sidesOf(oldHR, newHR)
	st := hr.status()
	var d delta
	d.merge(fluxReadyChange(st.was, st.is))
	// Released=False is how a Helm install failure shows; Stalled=True is
	// Flux giving up.
	d.merge(fluxConditionChanges(st.was, st.is, "Released", "Stalled"))
	appliedWas, appliedIs := st.num("lastAppliedRevision")
	if appliedWas != appliedIs && appliedIs != 0 {
		d.add("status.lastAppliedRevision", appliedWas, appliedIs, fmt.Sprintf("revision: %d→%d", appliedWas, appliedIs))
	}
	if a, b := st.num("lastReleaseRevision"); a != b && b != 0 {
		d.add("status.lastReleaseRevision", a, b)
		// Said only when the applied revision did not already say it.
		if appliedWas == appliedIs {
			d.note(fmt.Sprintf("released: rev %d→%d", a, b))
		}
	}
	d.merge(suspendChange(oldHR, newHR))
	a, b := hr.str("spec", "chart", "spec", "version")
	d.moved("spec.chart.spec.version", "chart", a, b, false)
	for _, f := range [][2]string{{"installFailures", "install failures"}, {"upgradeFailures", "upgrade failures"}} {
		if a, b := st.num(f[0]); b > a {
			d.add("status."+f[0], a, b, fmt.Sprintf("%s: %d", f[1], b))
		}
	}
	return d.result()
}

func fluxSourceDiffer(kind string) kindDiffFunc {
	return func(oldObj, newObj any) ([]FieldChange, []string) { return diffFluxSource(oldObj, newObj, kind) }
}

// diffFluxSource covers GitRepository, OCIRepository and HelmRepository.
func diffFluxSource(oldObj, newObj any, kind string) ([]FieldChange, []string) {
	oldSrc, newSrc, ok := unstructuredPair(oldObj, newObj)
	if !ok {
		return nil, nil
	}
	src := sidesOf(oldSrc, newSrc)
	st := src.status()
	var d delta
	d.merge(fluxReadyChange(st.was, st.is))
	// A failing fetch flips Stalled or FetchFailed without Ready moving the
	// same way.
	d.merge(fluxConditionChanges(st.was, st.is, "Stalled", "FetchFailed"))
	a, b := st.str("artifact", "revision")
	d.revision("status.artifact.revision", "artifact", a, b, truncateSourceRevision)
	d.merge(suspendChange(oldSrc, newSrc))
	if kind == "GitRepository" || kind == "HelmRepository" {
		if a, b := src.str("spec", "url"); a != b && b != "" {
			d.add("spec.url", a, b, "url changed")
		}
	}
	if kind == "GitRepository" {
		a, b := src.str("spec", "ref", "branch")
		d.moved("spec.ref.branch", "branch", a, b, false)
	}
	return d.result()
}

// fluxReadyChange is a Ready flip, reported only between two known states.
func fluxReadyChange(was, is map[string]any) ([]FieldChange, []string) {
	a, b := fluxCondition(was, "Ready"), fluxCondition(is, "Ready")
	if a == b || a == "" || b == "" {
		return nil, nil
	}
	return []FieldChange{{Path: "status.conditions[Ready]", OldValue: a, NewValue: b}}, []string{fmt.Sprintf("ready: %s→%s", a, b)}
}

// fluxConditionChanges reports each listed condition whose status moved,
// appearing and disappearing included.
func fluxConditionChanges(was, is map[string]any, types ...string) ([]FieldChange, []string) {
	var d delta
	for _, t := range types {
		if a, b := fluxCondition(was, t), fluxCondition(is, t); a != b {
			d.add("status.conditions["+t+"]", a, b, fmt.Sprintf("%s: %s→%s", t, a, b))
		}
	}
	return d.result()
}

func suspendChange(oldU, newU *unstructured.Unstructured) ([]FieldChange, []string) {
	a, _, _ := unstructured.NestedBool(oldU.Object, "spec", "suspend")
	b, _, _ := unstructured.NestedBool(newU.Object, "spec", "suspend")
	if a == b {
		return nil, nil
	}
	return []FieldChange{{Path: "spec.suspend", OldValue: a, NewValue: b}}, []string{map[bool]string{true: "suspended", false: "resumed"}[b]}
}

func fluxCondition(status map[string]any, t string) string {
	return getConditionMap(status, "conditions")[t]
}

// truncateSourceRevision shortens a Flux revision. Of "branch@sha1:<commit>"
// it keeps the branch and seven characters of the commit; anything else is
// cut to twelve.
func truncateSourceRevision(rev string) string {
	branch, rest, hasBranch := strings.Cut(rev, "@")
	if !hasBranch {
		return rev[:min(len(rev), 12)]
	}
	if _, sha, hasAlgo := strings.Cut(rest, ":"); hasAlgo {
		rest = sha
	}
	return branch + "@" + rest[:min(len(rest), 7)]
}
