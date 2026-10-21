package remediation

// executionwindow.go is the Go-side half of BACKLOG.md F14 (per-execution
// admission-policy scoping): the reviewed table that decides whether a
// plan's declared field paths (fieldpaths.go's PlannedFieldPaths) are already
// covered by the STANDING ValidatingAdmissionPolicy allowlist
// (deploy/helm/argus-agent/templates/validatingadmissionpolicy.yaml) or need
// a per-execution widening window opened first.
//
// # Why this table exists at all
//
// F11 lets a plan name a field path chosen from patchfield.go's own reviewed
// allowlist rather than one of the four original hand-built action types.
// Several of those paths (e.g. a Deployment's spec.progressDeadlineSeconds)
// are permitted by RBAC and by patchfield.go's own review, but are NOT among
// the four field groups the standing admission policy already lets
// argus-remediate touch — so a plan against one of them would pass every
// hub-side check, be approved by a human, and then be refused at the real API
// server the moment it reached admission. F14 closes that gap by letting the
// hub ask a separate, narrowly-scoped identity (argus-policy-controller) to
// open a short-lived, per-object, per-field window immediately before such a
// write and close it immediately after — see internal/execution/window.go
// for the orchestration and deploy/helm/argus-agent/templates/
// validatingadmissionpolicy.yaml for the CEL that actually consults it.
//
// # Two separate questions, two separate tables
//
// "Does this path need a window at all" (baseAllowedFieldPathPatterns) and
// "does a window for this path actually DO anything" (windowableFieldPaths)
// are deliberately not the same table. The first is a statement about what
// the standing policy already permits unconditionally — get it wrong in the
// "doesn't need one" direction and a real write is refused at admission
// (safe: F12's dry-run gate catches it before anything commits). The second
// is a statement about which fields someone has actually reviewed and wired
// a CEL clause for — CEL cannot walk an arbitrary, runtime-supplied JSONPointer
// through a schema-typed object (there is no generic "get by dotted path"
// builtin and no recursion, only bounded list comprehensions — confirmed
// against the CEL language definition and the Kubernetes CEL library, not
// assumed), so "open a window naming any field" cannot, by itself, make the
// admission policy honour a field nobody has enumerated a clause for. Get
// THIS one wrong in the "should be windowable" direction and the plan fails
// with a clear, honest "not supported yet" error before any tunnel round
// trip is spent opening a window that could never help.
//
// # Keeping this in lockstep with the chart
//
// Both tables below are a hand-maintained mirror of
// validatingadmissionpolicy.yaml's own comparisons, the same way
// patchFieldAllowlist mirrors the admission policy's PatchField coverage
// (patchfield.go's own doc comment: "the allowlist is enumerated so that the
// cluster-side admission policy can enumerate the same set"). There is no
// generator. TestBaseAllowedFieldPathsMatchTheStandingPolicy and
// TestWindowableFieldPathsMatchTheChart pin both against the exact strings
// the chart's own CEL and comments use, so a drift is a test failure rather
// than a silent gap discovered at a real API server.
import "strings"

// baseAllowedFieldPathPatterns is a Go-side mirror of the four field groups
// deploy/helm/argus-agent/templates/validatingadmissionpolicy.yaml's
// argus-remediate-field-restriction-{deployments,statefulsets} and
// argus-remediate-pod-template-restriction policies already permit
// UNCONDITIONALLY for the argus-remediate identity — no per-execution window
// required, ever, for a path matching one of these.
//
// Patterns use "*" for a single wildcard segment, matching
// patchfield.go's fieldPathMatches exactly (a container's name in
// fieldpaths.go's own "containers[name]" notation normalises to one
// segment, so "containers.*.image" is the right shape, not
// "containers[*].image").
var baseAllowedFieldPathPatterns = map[string][]string{
	"Deployment": {
		"spec.replicas",
		"spec.template.metadata.annotations",
		"spec.template.spec.containers.*.image",
		"spec.template.spec.containers.*.resources.limits.cpu",
		"spec.template.spec.containers.*.resources.limits.memory",
		"spec.template.spec.containers.*.resources.requests.cpu",
		"spec.template.spec.containers.*.resources.requests.memory",
	},
	"StatefulSet": {
		"spec.replicas",
		"spec.template.metadata.annotations",
		"spec.template.spec.containers.*.resources.limits.cpu",
		"spec.template.spec.containers.*.resources.limits.memory",
		"spec.template.spec.containers.*.resources.requests.cpu",
		"spec.template.spec.containers.*.resources.requests.memory",
	},
}

// windowableFieldPaths is the closed set of (Kind, fieldPath) pairs the
// admission policy actually knows how to widen today — the
// progressDeadlineSeconds/revisionHistoryLimit CEL clauses added to
// validatingadmissionpolicy.yaml's per-Kind policies alongside this feature.
// Both are plain, low-risk integers already compared as a bare equality
// there; widening them is this feature's first concrete, live-checkable use,
// deliberately chosen over a higher-risk field for a first cut of a brand
// new safety-critical mechanism. Extending coverage to another field is a
// row here plus a reviewed CEL clause in the chart — two edits in two files,
// same discipline patchfield.go's own header names for its own table.
var windowableFieldPaths = map[string]map[string]bool{
	"Deployment":  {"spec.progressDeadlineSeconds": true},
	"StatefulSet": {"spec.revisionHistoryLimit": true},
}

// FieldPathNeedsExecutionWindow reports whether writing fieldPath on a live
// object of Kind kind is already permitted by the standing
// ValidatingAdmissionPolicy allowlist (false — no window needed, ever) or
// requires BACKLOG.md F14's per-execution widening window to be open around
// the write (true).
//
// kind is the bare Kind ("Deployment", not a GVK string) — callers already
// have this from the plan's resolved target.
func FieldPathNeedsExecutionWindow(kind, fieldPath string) bool {
	normalised := normaliseFieldPath(fieldPath)
	for _, pattern := range baseAllowedFieldPathPatterns[kind] {
		if fieldPathMatches(pattern, normalised) {
			return false
		}
	}
	return true
}

// FieldPathIsWindowable reports whether a per-execution window opened for
// (kind, fieldPath) would actually change what the admission policy permits.
// Callers must check this before opening a window for a path
// FieldPathNeedsExecutionWindow already flagged: a window for a path that is
// not in this table is a wasted tunnel round trip the cluster will still
// refuse, not a safety hole (CEL enumerates permitted fields one at a time —
// see this file's own header), but it is also not a useful thing to attempt.
func FieldPathIsWindowable(kind, fieldPath string) bool {
	return windowableFieldPaths[kind][normaliseFieldPath(fieldPath)]
}

// FieldPathsNeedingExecutionWindow filters paths down to the ones that need a
// window at all, for a given Kind. Convenience wrapper for
// internal/execution/window.go's caller, which otherwise re-derives this
// loop identically at every call site.
func FieldPathsNeedingExecutionWindow(kind string, paths []string) []string {
	var out []string
	for _, p := range paths {
		if FieldPathNeedsExecutionWindow(kind, p) {
			out = append(out, p)
		}
	}
	return out
}

// GVKKind extracts the bare Kind from this codebase's "<apiVersion>/<Kind>"
// GVK wire convention, exported so internal/api's execution path (which
// already has its own private, identical gvkKind for the same reason —
// avoiding an internal/api -> internal/agent dependency for one helper) can
// use this package's copy instead of keeping a third one. Trivial and
// unlikely to drift, but one fewer copy is one fewer copy.
func GVKKind(gvk string) string {
	idx := strings.LastIndex(gvk, "/")
	if idx < 0 {
		return gvk
	}
	return gvk[idx+1:]
}
