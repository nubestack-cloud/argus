package gitopsinsight

import (
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// FluxState is the sync/health pair derived from a Flux object's conditions.
type FluxState struct {
	Sync   string
	Health string
	// Reconciling reports that a pass is executing right now. It is activity,
	// not sync or health, and never influences either; it is carried so a
	// wedged controller can be shown next to an otherwise-correct Synced.
	Reconciling bool
}

// fluxFacts is what FluxStatus reads off a Flux object.
type fluxFacts struct {
	ready, readyReason string // the Ready condition
	healthy            string // the Healthy condition, on kinds that have one
	retrying           bool   // a Reconciling=True condition whose reason is a retry
	reconciling        bool
	stalled            bool
	suspended          bool
	// drifted: the controller has demonstrably not acted on the current spec.
	// An absent observedGeneration says nothing (some kinds never write it); a
	// different one does, including the -1 Flux writes before its first pass.
	drifted bool
}

func readFlux(root *unstructured.Unstructured) fluxFacts {
	var f fluxFacts
	for _, c := range readConditions(root) {
		on := c.Status == "True"
		switch c.Type {
		case "Ready":
			f.ready, f.readyReason = c.Status, c.Reason
		case "Healthy":
			f.healthy = c.Status
		case "Reconciling":
			f.reconciling = f.reconciling || on
			if on {
				f.retrying = strings.Contains(c.Reason, "Retry")
			}
		case "Stalled":
			f.stalled = f.stalled || on
		}
	}
	f.suspended, _, _ = unstructured.NestedBool(root.Object, "spec", "suspend")
	gen, hasGen, _ := unstructured.NestedInt64(root.Object, "metadata", "generation")
	seen, hasSeen, _ := unstructured.NestedInt64(root.Object, "status", "observedGeneration")
	f.drifted = hasGen && hasSeen && gen != seen
	return f
}

// FluxStatus derives sync and health for any Flux object. Sync is whether the
// declared state is applied: Ready, with the controller caught up to the
// spec. Reconciling is carried alongside and never decides either answer —
// Flux sets it without clearing Ready, and kubectl shows such an object
// Ready — so a wedged controller can be shown beside a correct Synced.
//
// First match wins:
//
//	suspended                                  Suspended; Synced if it was applied and the spec has not moved since
//	Stalled                                    OutOfSync / Degraded — the controller has given up
//	Ready, caught up                           Synced / Healthy, or Degraded when Healthy=False
//	Ready=False for a named cause, retrying    OutOfSync / Degraded — a failure that repeats
//	spec not yet acted on, or reconciling      Reconciling / Progressing
//	Ready=False                                OutOfSync / Degraded, or Progressing for a wait or retry
func FluxStatus(root *unstructured.Unstructured) FluxState {
	f := readFlux(root)
	state := func(sync, health string) FluxState {
		return FluxState{Sync: sync, Health: health, Reconciling: f.reconciling}
	}
	applied := f.ready == "True" && !f.drifted
	switch {
	case f.suspended:
		// Suspending does not undo the last apply; it does mean a later spec
		// change will never be picked up.
		if applied {
			return state("Synced", "Suspended")
		}
		return state("Unknown", "Suspended")
	case f.stalled:
		return state("OutOfSync", "Degraded")
	case applied:
		// Source kinds have no Healthy condition; for them applied is healthy.
		if f.healthy == "False" {
			return state("Synced", "Degraded")
		}
		return state("Synced", "Healthy")
	case f.ready == "False" && f.readyReason != "" && !isTransientFluxReason(f.readyReason) && f.retrying:
		// Flux retries most failures indefinitely instead of marking them
		// Stalled; Ready=False then names the cause (a missing path, a build
		// error), and that is no kind of progress.
		return state("OutOfSync", "Degraded")
	case f.drifted || f.reconciling:
		return state("Reconciling", "Progressing")
	case f.ready == "False" && isTransientFluxReason(f.readyReason):
		return state("OutOfSync", "Progressing")
	case f.ready == "False":
		return state("OutOfSync", "Degraded")
	}
	return state("Unknown", "Unknown")
}

// isTransientFluxReason matches on fragments because Flux composes its
// reasons (ProgressingWithRetry and the like) and the set changes between
// versions.
func isTransientFluxReason(reason string) bool {
	return strings.Contains(reason, "Progress") || strings.Contains(reason, "Retry") || strings.Contains(reason, "Wait")
}

// ParseFluxInventoryID splits Flux's "namespace_name_group_kind" inventory
// key. Kind and group are taken from the right and the namespace from the
// left, so a name with underscores in it survives whole; the core group,
// written "" or "core", comes back as "".
func ParseFluxInventoryID(id string) (group, kind, namespace, name string, ok bool) {
	rest, kind, found := cutLast(id)
	if !found || kind == "" {
		return "", "", "", "", false
	}
	rest, group, found = cutLast(rest)
	if !found {
		return "", "", "", "", false
	}
	namespace, name, found = strings.Cut(rest, "_")
	if !found || name == "" {
		return "", "", "", "", false
	}
	if group == "core" {
		group = ""
	}
	return group, kind, namespace, name, true
}

func cutLast(s string) (before, after string, found bool) {
	i := strings.LastIndexByte(s, '_')
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+1:], true
}
