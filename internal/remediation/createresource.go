package remediation

// createResource — BACKLOG.md F9's last genuinely-buildable verb, and the
// one this task's own brief singles out as needing a real security decision
// rather than a mechanical addition: unlike annotateResource/labelResource/
// deleteResource (built 2026-08-29), createResource needs a `create` RBAC
// verb argus-remediate has never held at all, and its admission-policy shape
// cannot follow the "enumerate every field that must equal oldObject" idiom
// every other policy in this chart uses, because a CREATE request has no
// oldObject to diff against.
//
// # Scoped to ConfigMap only, and why
//
// BACKLOG.md's own text names the fault this closes: a missing ConfigMap is
// already a measured-live fault (GC-007/Z1's PVC-001 evidence row) — a
// Deployment references a ConfigMap that was never created, or was deleted
// out from under it, and until now ARGUS could diagnose that precisely and
// do nothing about it. ConfigMap is also the narrowest kind that closes the
// gap: its data is ordinary application configuration, not a security
// boundary, which is what makes a GENERIC "set these keys to these values"
// mechanism appropriate here in a way it structurally is not for annotate/
// label's much narrower per-(kind,key) review (annotatelabel.go's own header
// explains why that mechanism enumerates keys one at a time: a compromised
// or prompt-injected model choosing an arbitrary annotation VALUE on an
// existing Deployment is a different, and cheaper, blast radius than a
// compromised model choosing arbitrary NEW cluster state's shape).
//
// Every other kind considered and rejected, for a specific reason each:
//   - Secret is the one kind this mechanism must never reach. Non-negotiable
//     9 keeps Secret objects unfetchable and their values out of every
//     prompt/log/audit record; a model that was structurally never shown a
//     real Secret value has no business authoring a brand-new one either,
//     and a generic data-only create mechanism is exactly the shape that
//     would otherwise make "create a Secret with these values" look like an
//     ordinary remediation.
//   - Pod/Job (already createResource's near-mirror-image sibling,
//     deleteResource's own allowlist) need a controller to own them or they
//     orphan immediately — creating one directly is not what fixes "this
//     workload's ConfigMap disappeared," and a created Pod/Job carries a
//     security surface (arbitrary image, command, volumes) this action's
//     narrow key/value schema cannot bound the way patch_resource_limits'
//     four named quantities do.
//   - ServiceAccount, Role/RoleBinding, any admission-config or CRD: each is
//     itself a privilege boundary, and DESIGN.md §18.3's non-negotiable 1
//     already excludes RBAC objects and admission webhooks from what any
//     ARGUS-driven write may ever touch, remediation included.
//
// So: one kind, reviewed the same way patchfield.go's and deleteresource.go's
// tables are — a row per kind, each with its own justification — rather than
// "any kind ARGUS can already read."
//
// # Why there is no per-key allowlist the way annotateResource/labelResource has
//
// A ConfigMap's data keys are inherently open-ended and application-specific
// — unlike a metadata annotation/label key, which this codebase's own
// provenance convention (argus.io/...) can enumerate in advance, a
// ConfigMap's keys are named by whatever application will read them
// (RETRY_LIMIT, database.host, config.yaml, ...), and no fixed list could
// anticipate them. This mirrors OpenPRParams' own posture more than
// annotateResource's: a generic "whole content, human-approved every time"
// mechanism (this action type is in neverAutoApprove — see risk.go) rather
// than a small reviewed menu of values. What IS bounded, same discipline as
// every params type in this package: key syntax, value size, and the
// redact.Marker echo guard (BUGS.md 112) — shape and size limits, not a
// judgement about content, which is exactly what human approval exists to
// supply.
//
// # Why Reversible must always be false
//
// deleteResource's own allowlist (Pod, Job) does not include ConfigMap, so
// there is no representable "delete what we just created" compensating
// action through this codebase's reviewed delete mechanism — building one
// specifically for createResource's rollback would mean either widening
// deleteResource's allowlist for a reason that has nothing to do with
// deleteResource's own reviewed justification, or inventing a second,
// unreviewed ad hoc delete path outside it. Neither is acceptable, so this
// mirrors deleteResource's own honesty check (plan.go's RemediationPlan.
// Validate): a CreateResource plan that declares itself reversible is
// refused outright, Blocked rather than silently approved. An operator can
// always remove the created object by hand.
//
// # The RBAC verb and the admission-policy shape
//
// See deploy/helm/argus-agent/templates/clusterrole.yaml (a narrow `create`
// verb on `configmaps` only — never a blanket create grant) and
// templates/validatingadmissionpolicy.yaml's
// argus-remediate-create-protected-targets policy for the CREATE-shaped
// admission control this file's own header predicted would be needed: since
// there is no oldObject to diff against on a CREATE, that policy checks what
// IS expressible on a bare CREATE request — DESIGN.md §9.3's two absolute,
// deterministic modifiers (protected namespaces, tier=data) applied to the
// OBJECT BEING CREATED, plus refusing an object that arrives with
// ownerReferences/finalizers already set (this pack never legitimately sets
// either, and refusing them closes off a class of forged-ownership mischief
// a compromised agent could otherwise attempt). It does NOT and structurally
// cannot check "does this match an approved plan," "is this exactly the data
// the plan named," or "does an object with this name already exist" — none
// of those are expressible from a bare CREATE request's object alone, the
// same class of gap deleteResource's own policy names explicitly for DELETE.
// The primary control for those is Go-side: internal/execution's
// preparePlan re-derives the (kind) allowlist and confirms the target does
// NOT already exist immediately before signing, and internal/agent/
// createresource.go performs the identical Get-before-Create check again,
// independently, refusing rather than silently becoming a replace if the
// object is found to already exist by the time the agent acts.
import (
	"fmt"
	"regexp"
	"strings"

	"argus/internal/redact"
)

// ErrResourceNotFoundMessage is the exact text internal/agent's
// sanitizeK8sErr substitutes for a Kubernetes NotFound error, kept here — in
// the one package both the hub (internal/api, confirming a CreateResource
// target's ABSENCE before ever signing a plan to create it) and the agent
// (internal/agent's sanitizeK8sErr, and its own Get-before-Create check)
// already depend on — so the two sides of the tunnel cannot silently drift
// onto two different strings for the identical condition. A hub-side
// "resource not found" check against agent-reported error TEXT is a real,
// stated limitation (see confirmTargetAbsentForCreate's own doc comment in
// internal/execution): if a future change to sanitizeK8sErr's
// wording is made without updating this constant too, the hub's absence
// check fails CLOSED (it stops recognising "not found" and refuses to
// create, treating the ambiguous case as "cannot confirm absence") rather
// than failing open into creating blind — the safe direction for this
// particular brittleness.
const ErrResourceNotFoundMessage = "resource not found"

// CreateResourceParams is ActionCreateResource's typed parameter struct: the
// ConfigMap's data, keyed exactly as it will appear in the created object.
// Everything else the object needs — which kind, namespace, name — is
// already carried by RemediationPlan's own
// TargetGVK/TargetNamespace/TargetName, matching every other action type in
// this package.
type CreateResourceParams struct {
	Data map[string]string `json:"data"`
}

func (CreateResourceParams) actionType() ActionType { return ActionCreateResource }

// Bounds for CreateResourceParams.Data — gross-error backstops sized the
// same way this package's other absolute bounds are (PatchResourceLimits'
// quantity ceilings, OpenPRParams' file/byte bounds): far above anything a
// legitimate remediation sets, far below the ~1MiB a ConfigMap can actually
// hold in etcd, so a plan-authoring mistake fails here rather than as an
// opaque etcd/API-server rejection after the incident has already moved to
// Executing.
const (
	maxCreateResourceDataKeys   = 50
	maxCreateResourceValueBytes = 65536
	maxCreateResourceTotalBytes = 262144
)

// configMapDataKeyRE is Kubernetes' own ConfigMap data-key grammar: any
// non-empty string of alphanumerics, '-', '_', '.' — a real subset of what
// the API server itself validates as a valid file/env-var-source key.
var configMapDataKeyRE = regexp.MustCompile(`^[-._a-zA-Z0-9]+$`)

// Validate enforces every bound this params struct can carry on its own:
// at least one key, a well-formed key for every entry, each value within its
// size bound, no echo of redact.Marker, and a total-bytes ceiling across the
// whole map. What it deliberately does NOT and cannot check: whether an
// object with this name already exists (a live-cluster question, answered
// once at approval time and once, independently, at execution time — see
// this file's own header comment) and whether the VALUES are correct for
// whatever application will read them, which is exactly the judgement human
// approval exists to supply for a mechanism this generic (this action type
// is in risk.go's neverAutoApprove for precisely that reason).
func (p CreateResourceParams) Validate() error {
	if len(p.Data) == 0 {
		return fmt.Errorf("data is required — CreateResource creates a ConfigMap WITH content; an empty ConfigMap needs no remediation plan to create by hand")
	}
	if len(p.Data) > maxCreateResourceDataKeys {
		return fmt.Errorf("data has %d keys, over the %d-key bound for one CreateResource plan", len(p.Data), maxCreateResourceDataKeys)
	}
	total := 0
	for key, value := range p.Data {
		if !configMapDataKeyRE.MatchString(key) {
			return fmt.Errorf("data key %q is not a well-formed ConfigMap key (alphanumeric, '-', '_', '.' only)", key)
		}
		if len(value) > maxCreateResourceValueBytes {
			return fmt.Errorf("data key %q is %d bytes, over the %d-byte bound this action will set", key, len(value), maxCreateResourceValueBytes)
		}
		if strings.Contains(value, redact.Marker) {
			return fmt.Errorf("%w: data key %q contains %q — this value was withheld from the model at capture time (internal/redact), so the model has no basis to know or reproduce it; a human must supply the real value, not the marker that stood in for it", ErrNewValueEchoesRedactionMarker, key, redact.Marker)
		}
		total += len(key) + len(value)
	}
	if total > maxCreateResourceTotalBytes {
		return fmt.Errorf("this plan's data totals %d bytes, over the %d-byte bound for one CreateResource plan", total, maxCreateResourceTotalBytes)
	}
	return nil
}

// createableKind is one row of createResourceAllowlist.
type createableKind struct {
	// GVK is the exact target kind — not a prefix, not a wildcard, matching
	// patchableField.GVK's/deletableKind.GVK's own reasoning.
	GVK string
	// Why is the reviewed justification, required by this package's own
	// test — matching patchfield.go's/deleteresource.go's identical
	// requirement.
	Why string
}

// createResourceAllowlist is CreateResource's enumerated permission set —
// see this file's header comment for why it is exactly this one kind today.
var createResourceAllowlist = []createableKind{
	{
		GVK: "v1/ConfigMap",
		Why: "The fault type BACKLOG.md cites as already measured live: an application whose Deployment " +
			"references a ConfigMap that was never created, or was deleted out from under it (GC-007/Z1's " +
			"PVC-001 evidence row). ConfigMap data is ordinary application configuration, not a security " +
			"boundary — the property that makes a generic data-only create mechanism appropriate here, unlike " +
			"a Secret (never a candidate — non-negotiable 9 keeps Secret values out of every prompt a model " +
			"sees, so a model must never be trusted to author one either) or a workload kind (Pod/Job need a " +
			"controller to own them or they orphan immediately, and carry a security surface — image, command, " +
			"volumes — this action's narrow key/value schema does not bound).",
	},
}

// CreateResourcePermitted reports whether gvk may be targeted by a
// CreateResource plan.
//
// The refusal names the GVK, mirroring DeleteResourcePermitted's/
// PatchFieldPermitted's own reasoning: this is a permission decision, not a
// missing feature, and the message should read as one.
func CreateResourcePermitted(gvk string) (createableKind, error) {
	for _, entry := range createResourceAllowlist {
		if entry.GVK == gvk {
			return entry, nil
		}
	}
	return createableKind{}, fmt.Errorf("CreateResource may not target %s — that kind is not in the reviewed allowlist (internal/remediation/createresource.go). This is a permission decision, not a missing feature: creating cluster state needs a `create` RBAC verb argus-remediate did not previously hold at all, so this allowlist starts as narrow as possible and widens only when a specific fault names a specific kind", gvk)
}

// CreateResourceAllowlistEntries exposes the table for tests and for a
// future admission-policy generator, matching PatchFieldAllowlistEntries'/
// DeleteResourceAllowlistEntries' own reasoning: the permitted set should
// never be transcribed by hand into a second place.
func CreateResourceAllowlistEntries() []createableKind {
	out := make([]createableKind, len(createResourceAllowlist))
	copy(out, createResourceAllowlist)
	return out
}
