package gitops

// This file is BACKLOG.md "still open" #4's fix — the `AF1`/`DEPL-003`
// finding: a manifest the API server rejects AT ADMISSION TIME never becomes
// a live object, so `Locate`/`LocateIn`'s normal caller (loadIncidentObject,
// internal/api/repository_change.go) has nothing to read an identity off —
// every source it consults (a plan's target, incidents.workload_key, a
// finding's own object_name) names something that was, at some point, a real
// object in the cluster. An admission-rejected manifest never gets that far.
//
// The fix is deliberately NOT a new search mechanism. `ObjectRef` was always
// a plain kind/name/namespace tuple — `Locate`/`LocateIn` never read a live
// object's own fields; they walk a directory and match parsed YAML documents
// against whatever `ObjectRef` they were handed, and always have. The actual
// gap was upstream of this package: nothing ever *populated* an `ObjectRef`
// from anywhere other than a live object's tracked identity. `IsControllerObject`
// and `ParseAdmissionRejectionObject` are that missing piece — they let a
// caller build an `ObjectRef` from an Argo CD Application's own sync-failure
// message instead, and hand it to the exact same `LocateIn` a live object
// would have used. See internal/api/repository_locate_identity.go for how the
// two compose with the existing `locateObjectFile`.

import "regexp"

// controllerSelfSourceKinds are the GitOps controller kinds whose OWN object
// is what an incident anchors on when the thing it actually manages never
// came to exist — mirrors internal/agent/tools.go's gitOpsSelfSourceKinds
// (BACKLOG.md "still open" #3, fixed 2026-08-29) exactly, including the same
// ApplicationSet exclusion (it generates many Applications from a template
// plus generators and has no single spec.source of its own to anchor
// anything on).
//
// Deliberately duplicated rather than imported: internal/agent is
// cluster-agent code and internal/gitops is hub-side, and this package must
// not import an agent-only package for a three-entry lookup table. Keyed on
// "<API group>/<Kind>" (not Kind alone) so a CRD elsewhere that happens to
// reuse one of these Kind names on its own, unrelated group is never
// mistaken for a GitOps controller object.
var controllerSelfSourceKinds = map[string]bool{
	"argoproj.io/Application":                   true,
	"kustomize.toolkit.fluxcd.io/Kustomization": true,
	"helm.toolkit.fluxcd.io/HelmRelease":        true,
}

// IsControllerObject reports whether ref identifies a GitOps controller's own
// object (an Argo CD Application, a Flux Kustomization or HelmRelease) rather
// than a workload it manages.
//
// This is the trigger for the identity-based fallback: an incident anchored
// on one of these three kinds is, in every case this codebase produces one
// today (checkArgoSyncFailed, internal/agent/syncfailure.go), an incident
// where the object the fix actually needs to reach was never created —
// there is nothing else for get_gitops_ownership to have walked up from
// (BACKLOG.md "still open" #3's fix comment says this explicitly: "an
// Application has no owner of its own to find"), and the manifest that
// declares the Application/Kustomization/HelmRelease itself almost never
// lives inside the directory it points AT, so the ordinary search
// legitimately finds nothing to match.
func IsControllerObject(ref ObjectRef) bool {
	return controllerSelfSourceKinds[apiGroupOf(ref.APIVersion)+"/"+ref.Kind]
}

// admissionRejectionPattern matches ONLY the shape k8s.io/apimachinery's
// errors.NewInvalid renders: `<Kind>[.<group>] "<name>" is invalid: <details>`
// — e.g. `Deployment.apps "web" is invalid: spec.strategy.rollingUpdate.
// maxSurge: ...` or, for a core-group kind with no group segment, `Pod "web"
// is invalid: ...`. Confirmed against the two real messages
// internal/agent/syncfailure.go's own header quotes verbatim (`CronJob.batch
// "s1-syncfail" is invalid: ...`, `Job.batch "immut-job" is invalid: ...`)
// and against DEPL-003's own scenario (an invalid maxSurge/maxUnavailable
// combination is exactly this same validation-rejection shape).
//
// Deliberately narrower than "every admission-time refusal": NewNotFound,
// NewAlreadyExists and NewForbidden all render the RESOURCE (the plural,
// lower-cased form — "deployments.apps", not "Deployment.apps"), which is a
// different string than the Kind this package's ObjectRef/documentMatches
// compares against. Matching those too would mean feeding a wrong-cased,
// wrong-pluralised Kind into a search that fails silently (no manifest's
// `kind:` field is ever literally "deployments") rather than loudly — worse
// than admitting the message could not be parsed. NewInvalid is also the
// only one of the four that is actually reachable through Argo's sync
// path for the fault this fix targets: a manifest with a value the schema or
// an admission policy refuses is rejected as Invalid, never NotFound/
// AlreadyExists/Forbidden.
var admissionRejectionPattern = regexp.MustCompile(`\b([A-Z][A-Za-z0-9]*)(?:\.[A-Za-z0-9][\w.\-]*)? "([^"]+)" is invalid:`)

// ParseAdmissionRejectionObject extracts the kind and name of the object an
// admission-time rejection message names, when the message carries the exact
// shape admissionRejectionPattern recognizes. ok is false for anything else
// — a permissions error, a stalled sync with no rejection at all, free text
// from a validating webhook that doesn't follow the apimachinery convention
// — because a wrong guess here is worse than admitting the message could not
// be parsed (DESIGN.md §8.1's evidence discipline: "could not determine,"
// never a guess presented as a fact).
//
// Namespace is deliberately not returned: NewInvalid's message never names
// one (the qualified kind and the object's own name are all it renders), and
// documentMatches already treats an empty ObjectRef.Namespace leniently — a
// manifest matches regardless of which namespace it declares, or none. An
// empty Namespace here is an honest "not named", not a stand-in for "any
// namespace" invented by this function; it happens to compose correctly with
// documentMatches's own leniency, which is a property of that function, not
// a promise this one is making.
func ParseAdmissionRejectionObject(message string) (kind, name string, ok bool) {
	m := admissionRejectionPattern.FindStringSubmatch(message)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}
