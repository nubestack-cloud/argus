package remediation

// PatchField is one action type that can set any field on an explicitly
// enumerated list of (kind, field path) pairs — as opposed to one bespoke action
// type per fault, which is how the first four were built.
//
// # Why this shape
//
// FAILURE_MODES.md's resolution columns put a number on the problem: 30 faults
// are reachable in-cluster and blocked only on there being no action type for
// them. Building thirty ScaleDeployment-shaped features is the wrong answer —
// each would need its own params struct, agent tool, field-path declaration,
// gate wiring, rollback capture and admission-policy clause, so the marginal
// cost of coverage never falls and in practice coverage stops at four.
//
// What those thirty actually need is not thirty mechanisms. It is one mechanism
// and thirty permissions.
//
// # Generic in mechanism, ENUMERATED in policy
//
// That distinction is the whole safety argument, and it is worth stating before
// the table rather than after it.
//
// The mechanism here is general: given a path and a value, patch it. If the
// permission were general too — "ARGUS may set any field the model names" — this
// file would be the largest single regression in the project's safety posture.
// deploy/helm/argus-agent's ValidatingAdmissionPolicy is the layer that holds
// when everything on the ARGUS side is compromised, up to and including a
// prompt-injected model and a hub with a leaked signing key, and it holds by
// ENUMERATING the fields a write may touch. An allowlist that accepted a pattern
// like `spec.**` would turn that policy into a formality.
//
// So: every path below is written out, reviewed, and justified in place. Adding
// coverage is a row here plus a line in the admission policy — deliberately two
// edits in two files, because the second is the one that survives the first
// being wrong.
//
// # What is deliberately NOT here, and why each absence is load-bearing
//
// Three field families are excluded even though they are obviously patchable,
// because a dedicated action type already owns them AND carries a guardrail that
// routing through here would bypass:
//
//   - `spec.replicas` belongs to ScaleDeployment, which refuses to scale a
//     workload up from zero without a per-request human confirmation
//     (checkScaleFromZero). PatchField has no such check, so allowing replicas
//     here would be a way to switch on a deliberately-stopped workload without
//     the confirmation the other path insists on.
//   - `containers[*].image` belongs to RevertContainerImage, whose central
//     design decision is that THE MODEL NEVER NAMES THE IMAGE — the value comes
//     from the workload's own rollout history and is re-verified agent-side,
//     because "an image reference is code, and a hallucinated or injected tag is
//     arbitrary code execution inside the customer's cluster". A generic patcher
//     accepting a model-supplied image string is precisely the thing that
//     schema was built to make unrepresentable.
//   - `containers[*].resources.limits.*` belongs to PatchResourceLimits. Less
//     dangerous than the other two, excluded anyway so that one fix has one
//     path: two ways to set the same field means two places to change when the
//     rule for setting it changes.
//
// Also absent: anything whose value expresses INTENT rather than correctness.
// `spec.suspend` on a CronJob and `spec.paused` on a Deployment are both single
// mutable booleans and both trivially patchable, and both are excluded, because
// "somebody paused this on purpose" and "this is stuck paused" are
// indistinguishable from outside and the cost of guessing wrong is resuming
// something a human stopped.
//
// # What is actually reachable today
//
// Sixteen paths are reviewed and permitted, and **all sixteen can now execute**:
// BACKLOG.md "still open" #9 (2026-08-29) closed the RBAC precondition this
// section used to describe — the shipped agent chart used to grant `patch` on
// only `apps/deployments` and `apps/statefulsets`, and the other thirteen rows
// (Service, Ingress, HorizontalPodAutoscaler, PodDisruptionBudget, CronJob)
// carried a NeedsGrant note refusing them up front rather than letting a human
// approve a plan the API server would then answer with a 403 (`Z1`'s `ING-004`,
// confirmed live). deploy/helm/argus-agent/templates/clusterrole.yaml's
// remediate.enabled section now grants `patch` on all five kinds (see that
// file's own comment for exactly what it added and why), so no entry below
// carries a NeedsGrant any more.
//
// This is a SEPARATE precondition from `F11`'s decision, which this change does
// not touch: `F11` keeps PatchField/StructuredPatch off the model's tool
// dispatch entirely, dormant by deliberate choice, so none of these sixteen
// paths is reachable by a model today regardless of RBAC. What changes here is
// that WHEN `F11` is eventually reversed, these fields will actually execute
// instead of failing a second, independently-discovered way.
//
// The empty-NeedsGrant state is not a promise that adding the next row here is
// free: the design work of reviewing whether writing a path is safe is still the
// expensive part, and a future row can absolutely reintroduce a NeedsGrant note
// if the chart hasn't caught up with it yet — see that field's own doc comment.
//
// # Approval
//
// PatchField is approval-only by construction, registered in risk.go's
// neverAutoApprove alongside PatchResourceLimits and RevertContainerImage. Every
// path here sets a value that cannot be derived from the API — that is why these
// faults were unreachable in the first place — so a human sees the preflight
// field diff before anything commits. The mechanism being general makes that
// non-negotiable rather than merely prudent.

import (
	"fmt"
	"strings"
)

// PatchFieldParams is what a PatchField plan carries.
//
// A path and a value and nothing else: no container name, no resource name, no
// per-fault fields. The path selects, the allowlist authorises, and the target
// GVK comes from the plan itself.
type PatchFieldParams struct {
	// FieldPath is dot/bracket notation, matching what the model already
	// produces elsewhere and what internal/gitops splits on:
	// "spec.ports[0].targetPort".
	FieldPath string `json:"fieldPath"`
	// NewValue is the literal string form of the value to set, as with every
	// other action's params. The agent converts it against the live object's own
	// type for that field.
	NewValue string `json:"newValue"`
	// ExpectCurrent, when non-empty, must equal the field's current value or the
	// execution refuses. Optional but strongly preferred: the resourceVersion
	// precondition already catches an object that CHANGED, while this catches the
	// subtler case where the object is untouched and the analysis' belief about
	// the field was wrong from the start.
	ExpectCurrent string `json:"expectCurrent,omitempty"`
}

func (PatchFieldParams) actionType() ActionType { return ActionPatchField }

// patchableField is one row of the permission table.
type patchableField struct {
	// GVK is the exact target kind. Not a prefix and not a wildcard: a path that
	// is safe on a Service is not automatically safe on anything else.
	GVK string
	// Path is the permitted field path, where "*" matches exactly ONE segment —
	// a list index, or a map key whose name cannot be known in advance. There is
	// deliberately no multi-segment wildcard: "spec.**" is how an allowlist
	// stops being one.
	Path string
	// Risk is this field's floor. Per-field rather than per-action, because the
	// blast radius of correcting a Service's targetPort and of rewriting a
	// PodDisruptionBudget's minAvailable are not the same thing.
	Risk RiskLevel
	// Type is the field's JSON type, so the string a plan carries can be
	// converted to what the API server expects.
	//
	// Declared here rather than inferred from the live object, and that is a
	// safety decision rather than a convenience one. Inferring means guessing
	// when the field is absent, and guessing wrong produces a manifest the API
	// server rejects on unmarshalling — the exact failure the PR route hit when a
	// numeric-looking string was written unquoted into a string field (WORKLOG
	// §185). A declared type is reviewed data, like the path and the risk.
	//
	// FieldIntOrString exists because Kubernetes genuinely has such fields:
	// a Service's targetPort accepts 8080 or "http", and both are correct.
	Type FieldType
	// Why is the reviewed justification. Required by the package's own test: an
	// entry nobody could explain is an entry nobody reviewed.
	Why string
	// NeedsGrant names the RBAC the shipped agent chart does NOT currently give,
	// or "" when the shipped role already covers this kind.
	//
	// This field exists because the first version of this table did not have it,
	// and that was a real defect rather than an omission: thirteen of sixteen
	// entries named kinds the remediate identity could not patch at all (the
	// chart granted `patch` on apps/deployments and apps/statefulsets and
	// nothing else). A plan for one of them would pass hub-side validation, be
	// approved by a human, cross the tunnel, and only then be refused by the API
	// server — so the operator sees a 403 that reads like a malfunction after
	// they have already authorised the change. That is precisely the failure
	// that got OpenPR removed from the model's prompt once before.
	//
	// So an entry that needs a grant the chart does not ship is refused UP FRONT,
	// with the missing permission named. The table keeps the entry, because the
	// design work of reviewing the path is done and should not be repeated when
	// the chart catches up; what changes is that proposing it is impossible until
	// then.
	//
	// BACKLOG.md "still open" #9 (2026-08-29) closed this for every row that
	// carried one — deploy/helm/argus-agent/templates/clusterrole.yaml's
	// remediate.enabled section now grants `patch` on all five kinds this table
	// names, so every entry below has NeedsGrant == "". The field itself stays:
	// the next row added here is reviewed and permitted first, and may still
	// need a chart change before it can execute.
	NeedsGrant string
}

// FieldType is the JSON type of an allowlisted field.
type FieldType string

const (
	// FieldString is a JSON string.
	FieldString FieldType = "string"
	// FieldInt is a JSON number that must be integral.
	FieldInt FieldType = "int"
	// FieldIntOrString is Kubernetes' IntOrString: a number if it parses as one,
	// otherwise a string. A Service's targetPort and a PDB's minAvailable (which
	// also accepts "25%") are both this.
	FieldIntOrString FieldType = "intOrString"
)

// patchFieldAllowlist is the enumerated permission set.
//
// Ordered by the value of the fault it unlocks, so the list reads as a work
// queue rather than an inventory.
var patchFieldAllowlist = []patchableField{
	// --- Service: the largest group of reachable-but-unfixable faults.
	{
		GVK: "v1/Service", Path: "spec.ports.*.targetPort", Risk: RiskMedium, Type: FieldIntOrString,
		Why: "A Service pointing at a port nothing serves silently drops every request, and the " +
			"cluster reports nothing wrong — endpoints exist and look ready. The corrected value is " +
			"not derivable (a container may listen on a port it never declares), which is exactly why " +
			"this is approval-only rather than automatic.",
	},
	{
		GVK: "v1/Service", Path: "spec.ports.*.port", Risk: RiskMedium, Type: FieldInt,
		Why: "The port clients connect to. Changing it is disruptive to callers, hence medium rather " +
			"than low, but it is the fix when a Service was published on the wrong port.",
	},
	{
		GVK: "v1/Service", Path: "spec.selector.*", Risk: RiskMedium, Type: FieldString,
		Why: "A selector typo is the classic cause of a Service with no endpoints. The map key cannot " +
			"be known in advance (it is whatever label the workload uses), which is what the " +
			"single-segment wildcard is for.",
	},

	// --- Ingress: detected since 2026-08-23, previously unfixable either way.
	{
		GVK: "networking.k8s.io/v1/Ingress", Path: "spec.rules.*.http.paths.*.backend.service.name", Risk: RiskMedium, Type: FieldString,
		Why: "An Ingress naming a Service that does not exist fails every request to that path with " +
			"nothing in the cluster complaining. Two wildcards because both the rule and the path are " +
			"positional.",
	},
	{
		GVK: "networking.k8s.io/v1/Ingress", Path: "spec.rules.*.http.paths.*.backend.service.port.number", Risk: RiskMedium, Type: FieldInt,
		Why: "The companion fault: the right Service, the wrong port. Unlike a container's declared " +
			"ports, a Service's port list IS binding, so a mismatch here is provable rather than " +
			"inferred — but the corrected number still needs a human to confirm intent.",
	},
	{
		GVK: "networking.k8s.io/v1/Ingress", Path: "spec.ingressClassName", Risk: RiskMedium, Type: FieldString,
		Why: "An ingressClassName naming a class no controller provides leaves the Ingress unclaimed " +
			"and routes nothing at all.",
	},

	// --- Autoscaling: bounds are pure numbers and entirely mutable.
	{
		GVK: "autoscaling/v2/HorizontalPodAutoscaler", Path: "spec.maxReplicas", Risk: RiskMedium, Type: FieldInt,
		Why: "An HPA pinned at its ceiling cannot respond to load, and the ceiling is usually a " +
			"stale guess. Medium, not low: raising it commits real capacity.",
	},
	{
		GVK: "autoscaling/v2/HorizontalPodAutoscaler", Path: "spec.minReplicas", Risk: RiskMedium, Type: FieldInt,
		Why: "A minReplicas above what the cluster can schedule keeps the HPA permanently unable to " +
			"scale, reported as a blocked autoscaler rather than as the misconfiguration it is.",
	},

	// --- Scheduling: requests are what actually block a Pod, and they are set
	//     on the controller's template rather than on the Pod.
	{
		GVK: "apps/v1/Deployment", Path: "spec.template.spec.containers.*.resources.requests.memory", Risk: RiskMedium, Type: FieldString,
		Why: "A memory request larger than any node can satisfy leaves every replica Pending " +
			"forever. Requests, not limits — limits belong to PatchResourceLimits.",
	},
	{
		GVK: "apps/v1/Deployment", Path: "spec.template.spec.containers.*.resources.requests.cpu", Risk: RiskMedium, Type: FieldString,
		Why: "The CPU counterpart of the same fault: a request above any node's allocatable CPU is " +
			"unschedulable forever, and the scheduler's message names the shortfall without saying " +
			"what the request should have been.",
	},

	// --- Rollout and disruption tuning: numbers whose wrong value stalls
	//     something quietly.
	{
		GVK: "apps/v1/Deployment", Path: "spec.progressDeadlineSeconds", Risk: RiskLow, Type: FieldInt,
		Why: "A progressDeadlineSeconds shorter than the workload's real startup time marks every " +
			"rollout failed while the rollout is in fact fine. Low: it changes only when Kubernetes " +
			"gives up reporting progress, never the workload itself.",
	},
	{
		GVK: "policy/v1/PodDisruptionBudget", Path: "spec.minAvailable", Risk: RiskHigh, Type: FieldIntOrString,
		Why: "A PDB that cannot be satisfied blocks every voluntary eviction, which blocks node " +
			"drains and therefore cluster maintenance. HIGH deliberately: relaxing a disruption " +
			"budget is exactly the change that turns a stuck drain into an outage, and the floor " +
			"means it can never auto-approve even if neverAutoApprove were ever relaxed.",
	},
	{
		GVK: "policy/v1/PodDisruptionBudget", Path: "spec.maxUnavailable", Risk: RiskHigh, Type: FieldIntOrString,
		Why: "The other half of the same budget, and high for the same reason: whether a drain is " +
			"blocked is decided by whichever of minAvailable and maxUnavailable is set, so the risk " +
			"of relaxing either is identical.",
	},

	// --- CronJob: schedule and concurrency, excluding `suspend` (intent).
	{
		GVK: "batch/v1/CronJob", Path: "spec.schedule", Risk: RiskMedium, Type: FieldString,
		Why: "An invalid or wrong cron expression means runs silently never happen. The corrected " +
			"expression is intent, so a human confirms it.",
	},
	{
		GVK: "batch/v1/CronJob", Path: "spec.startingDeadlineSeconds", Risk: RiskLow, Type: FieldInt,
		Why: "Too short a starting deadline makes the controller skip runs it could still have " +
			"started, reported as missed schedules.",
	},
	{
		GVK: "batch/v1/CronJob", Path: "spec.concurrencyPolicy", Risk: RiskMedium, Type: FieldString,
		Why: "`Forbid` silently skips a run whenever the previous one is still going, which reads as " +
			"a broken schedule rather than a policy choice.",
	},
}

// PatchFieldPermitted reports whether gvk may have fieldPath set by a PatchField
// plan, and at what risk floor.
//
// The refusal names the GVK and the path rather than saying "not permitted",
// because the actionable question for whoever hits it is which of the two was
// wrong — a path that is fine on a Deployment is refused on a StatefulSet, and
// that is a permission decision, not a typo.
func PatchFieldPermitted(gvk, fieldPath string) (patchableField, error) {
	normalised := normaliseFieldPath(fieldPath)
	if normalised == "" {
		return patchableField{}, fmt.Errorf("a field path is required")
	}
	for _, entry := range patchFieldAllowlist {
		if entry.GVK != gvk {
			continue
		}
		if fieldPathMatches(entry.Path, normalised) {
			if entry.NeedsGrant != "" {
				// Refused HERE rather than at the API server, which is the whole
				// point of the field: without this, a human approves a change and
				// then watches it fail with a 403 they cannot act on.
				return patchableField{}, fmt.Errorf("PatchField cannot set %q on %s yet: the agent's "+
					"RBAC does not permit it. Missing grant — %s. The path itself is reviewed and "+
					"permitted; what is missing is the cluster-side permission, which means a change to "+
					"deploy/helm/argus-agent and a redeploy of the agent, not a change here",
					fieldPath, gvk, entry.NeedsGrant)
			}
			return entry, nil
		}
	}
	return patchableField{}, fmt.Errorf("PatchField may not set %q on %s — that pair is not in the "+
		"reviewed allowlist (internal/remediation/patchfield.go). This is a permission decision, not a "+
		"missing feature: the allowlist is enumerated so that the cluster-side admission policy can "+
		"enumerate the same set", fieldPath, gvk)
}

// NormaliseFieldPath is normaliseFieldPath, exported for internal/api's
// execution path (internal/execution's readLiveFieldValue), which
// needs to walk a live object at the SAME concrete segments PatchFieldPermitted
// matched against in order to capture this plan's rollback from live state
// before executing it. Exported rather than duplicated a second time: unlike
// internal/agent's own copy (normalisePath, checked against this package only
// through the public PatchFieldPermitted — see
// TestPatchFieldPathNotationMatchesTheHub), internal/api is IN this module and
// has no dependency-direction reason to avoid importing it directly, so a
// second private copy here would just be a second place for the two hub-side
// readers to drift.
func NormaliseFieldPath(p string) string { return normaliseFieldPath(p) }

// normaliseFieldPath converts bracket and dot notation into dot-separated
// segments, matching internal/gitops/splitFieldPath so one notation carries from
// the model's proposal through the allowlist check to the patch itself.
func normaliseFieldPath(p string) string {
	p = strings.ReplaceAll(p, "[", ".")
	p = strings.ReplaceAll(p, "]", "")
	p = strings.ReplaceAll(p, "/", ".")
	parts := make([]string, 0, 8)
	for _, seg := range strings.Split(p, ".") {
		if strings.TrimSpace(seg) != "" {
			parts = append(parts, seg)
		}
	}
	return strings.Join(parts, ".")
}

// fieldPathMatches compares a permitted pattern against a concrete path, where
// "*" in the pattern matches exactly one segment.
//
// Segment count must be equal. That is what makes "*" single-segment in fact
// rather than by intention: a pattern can never match a path deeper or shallower
// than itself, so `spec.selector.*` cannot authorise `spec.selector.app.nested`
// and `spec.ports.*.targetPort` cannot authorise `spec.ports`.
func fieldPathMatches(pattern, path string) bool {
	pp := strings.Split(pattern, ".")
	cp := strings.Split(path, ".")
	if len(pp) != len(cp) {
		return false
	}
	for i := range pp {
		if pp[i] == "*" {
			// A wildcard segment must still be a real segment, and must not be a
			// traversal token: "spec.ports...targetPort" normalises away empty
			// segments, but a literal ".." would otherwise slip through here.
			if cp[i] == "" || cp[i] == ".." {
				return false
			}
			continue
		}
		if pp[i] != cp[i] {
			return false
		}
	}
	return true
}

// PatchFieldAllowlistSize is for tests and for the admission-policy generator,
// which must cover the same set this file permits.
func PatchFieldAllowlistSize() int { return len(patchFieldAllowlist) }

// PatchFieldAllowlistEntries exposes the table for the admission-policy
// generator and for documentation, so the permitted set is never transcribed by
// hand into a second place.
func PatchFieldAllowlistEntries() []patchableField {
	out := make([]patchableField, len(patchFieldAllowlist))
	copy(out, patchFieldAllowlist)
	return out
}
