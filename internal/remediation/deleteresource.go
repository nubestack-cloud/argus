package remediation

// deleteResource — BACKLOG.md F9's third genuinely-buildable verb, and the
// one this task's own brief singles out for extra caution: DESIGN.md §10.5
// is explicit that deletion is "effectively irreversible" (a pre-flight
// snapshot restores spec, never identity/uid, so every ownerReference into
// the deleted object dangles) and that it "is classified high, is never
// automatic, and requires requireApprovers >= 1 with the irreversibility
// stated in the approval UI". §9.3's own risk table lists "delete anything"
// under high, and reserves the harsher forbidden tier for
// namespace/CRD/PVC specifically.
//
// # Enumerated by KIND, following patchfield.go's own philosophy
//
// "Any kind ARGUS can already read" would make this mechanism as
// unboundedly generic as a bare create/delete verb on the API server —
// exactly what this task's own brief warns against. So, like PatchField's
// (kind, field) table, this is a reviewed list of (kind) rows, each with its
// own justification, rather than a blanket grant scoped only by RBAC.
//
// Three kinds today: Pod, Job, and (added 2026-09-01, `BUGS.md` 118 part
// (b) / `BACKLOG.md` AK1, an explicit owner decision — see DESIGN.md §9.3's
// amended forbidden-tier row for the corresponding spec change) a narrowly
// scoped PersistentVolumeClaim. Pod and Job are the ordinary "delete this
// stuck thing so its controller (or the next scheduled run) replaces it
// cleanly" shape — a Pod stuck Terminating or orphaned with no controller,
// or a completed/failed Job blocking a CronJob's next run under
// `concurrencyPolicy: Forbid` (already a reviewed PatchField row,
// patchfield.go's `spec.concurrencyPolicy`; deleting the stuck Job is
// usually the more direct fix than changing the policy).
//
// StatefulSet, Namespace and CustomResourceDefinition remain forbidden
// outright, never representable here at all: they carry an identity/state
// permanence deleting a PVC in the narrow case below does not — deleting a
// StatefulSet, for instance, orphans every PVC its still-live ordinals hold,
// which is a strictly worse version of the exact problem this action type
// exists to clean up. statefulTargetKinds in risk.go floors any OTHER action
// against a StatefulSet or PVC at high already, for the "the pods come back
// is a much weaker guarantee" reason; this table's refusal for
// StatefulSet/Namespace/CRD goes further than that floor by never permitting
// them to be named as a DELETE target at all, regardless of risk floor,
// because unlike a patch a delete on one of those has no controller left
// afterwards to reconcile anything back.
//
// # Why PersistentVolumeClaim is narrowly permitted, not forbidden like the other stateful kinds
//
// DESIGN.md §9.3's risk table used to list "Delete namespace/CRD/PVC" as a
// flat, unconditional forbidden-tier row — "never, at any confidence, [an
// absolute prohibition that applies] even to a super-admin" (§5.4's own
// framing of that tier). That table now carries a dated, narrow exception
// (2026-09-01): an orphaned, unmanaged PVC — one whose ownership resolves
// `managed_by: none` (no Argo CD/Flux/Helm governs it) AND that no live Pod
// currently references — floors at high instead, the same tier as every
// other DeleteResource target. This is a genuinely different case from the
// one the flat prohibition existed to rule out: a StatefulSet's
// `volumeClaimTemplate` PVC left behind after a scale-down (`BACKLOG.md`
// AK1/`checkOrphanedPVC`) has already lost every reason the forbidden tier
// worried about — nothing declares it, nothing mounts it, and its own
// StatefulSet's real fix (`persistentVolumeClaimRetentionPolicy`) is the
// thing that should have reclaimed it in the first place. A PVC that IS
// still owned or still mounted gets neither exception: this allowlist row
// only names the KIND, not the narrower condition, because a kind-level
// table has no field for "and only when X" — the condition is enforced
// structurally, in code, at two points that do not trust each other's
// answer any more than any other guardrail in this codebase does:
//
//   - internal/agent/deleteresource.go's own liveness precondition (a fresh
//     List of every Pod in the target's namespace, checked for a
//     PersistentVolumeClaim volume naming this claim) — matching
//     checkOrphanedPVC's own referencedClaims check in sweep_detector.go,
//     because "ask about the object you are about to act on" (this
//     package's own lesson, see argus-context) means the delete tool must
//     make its own fresh determination, not trust whatever made the
//     original incident.
//   - internal/execution's ownership re-check ahead of
//     signing, which — unlike checkGitOpsPrecedence's ordinary
//     confirmGitOpsManaged override, offered for every other action type —
//     has NO override for a PersistentVolumeClaim DeleteResource target:
//     a managed answer refuses outright, unconditionally, matching
//     errNamespaceProtectedRefused's "no confirmation ever waives it"
//     pattern rather than errGitOpsManagedRefused's confirmable one. Two
//     independent live re-checks, at two different layers, both required to
//     say "none"/"nothing" before this ever reaches the cluster — the
//     mechanism this repo already uses everywhere else for a mutating
//     action (defense in depth, not a single point of trust).
//
// D11's "deterministic risk floors cannot be argued down BY THE MODEL"
// still holds exactly as before: nothing here lets the model claim a lower
// risk, assert its own "this one is safe," or skip either re-check by being
// confident. The floor is still computed by rules, not by the model's
// self-report; what changed is which rule applies to which fact pattern,
// decided by a human, in the design doc, ahead of time — not argued down in
// the moment by anything the model said.
//
// # Never CreateResource's mirror image
//
// This is worth stating because it would be an easy, wrong assumption:
// deleteResource does not "undo" by creating a replacement. This task's own
// brief blocks createResource explicitly (a fundamentally different
// admission-policy shape with no oldObject on a CREATE, and a new `create`
// RBAC verb argus-remediate does not have) — building a create-based
// rollback for delete would be building createResource by another name. So
// DeleteResource's rollback is always nil (see preparePlan's own branch in
// internal/execution), exactly like RestartPod's "already
// happened, cannot be un-restarted" — the honest statement that this
// mechanism has no representable inverse, not a placeholder for one.
//
// # A DIFFERENT mechanism from the GitOps repository-file deletion
//
// Do not confuse this with BACKLOG.md item #2's ProposedFile.Delete
// (plan.go): that deletes a FILE inside a git repository as one edit in a
// pull request the OpenPR channel proposes — durable, reviewed via CI and
// human PR review, and reverted by reverting a commit. This action type
// deletes a LIVE CLUSTER OBJECT in place, with none of those properties.
// They share no code path: OpenPRParams/ProposedFile never appears here,
// and DeleteResourceParams never appears in internal/gitops.
//
// # Approval and risk
//
// Registered in risk.go's neverAutoApprove (belt-and-suspenders: the plan's
// own Reversible field is also refused if set true — see
// RemediationPlan.Validate below — so the existing hard high-risk+
// irreversible floor in gate.go's Evaluate already blocks this
// independently) and floored at RiskHigh in baseRiskFloors. See risk.go's
// own comments for the full reasoning on both.
import "fmt"

// DeleteResourceParams is ActionDeleteResource's typed parameter struct.
// Empty, like RestartPodParams: everything this action needs to know — which
// object — is already carried by RemediationPlan's own
// TargetGVK/TargetNamespace/TargetName, and there is nothing else to
// configure. Kept as its own named type for the same
// independently-checkable-ActionType/Params reason RestartPodParams is.
type DeleteResourceParams struct{}

func (DeleteResourceParams) actionType() ActionType { return ActionDeleteResource }

// deletableKind is one row of deleteResourceAllowlist.
type deletableKind struct {
	// GVK is the exact target kind — not a prefix, not a wildcard, matching
	// patchableField.GVK's own reasoning.
	GVK string
	// Why is the reviewed justification, required by this package's own
	// test — matching patchfield.go's identical requirement.
	Why string
}

// deleteResourceAllowlist is DeleteResource's enumerated permission set. See
// this file's header comment for the full reasoning — in particular, why
// StatefulSet/Namespace/CustomResourceDefinition are absent outright, and why
// PersistentVolumeClaim is present but named as a KIND only: the narrower
// "orphaned and unreferenced" condition its own Why below describes is
// enforced structurally in code (internal/agent/deleteresource.go's liveness
// precondition, internal/execution's non-overridable ownership
// re-check), not by anything expressible in this table.
var deleteResourceAllowlist = []deletableKind{
	{
		GVK: "v1/Pod",
		Why: "The single most common \"delete to fix\" shape in ordinary Kubernetes operations: a Pod " +
			"stuck Terminating, or orphaned with no controller to recreate it. A Pod owned by a " +
			"ReplicaSet/Deployment is trivially recovered (the controller creates a replacement " +
			"immediately) — RestartPod already covers the common rolling-restart case more safely via an " +
			"annotation bump; this covers the case a rolling restart does not: a Pod that will not go " +
			"away on its own.",
	},
	{
		GVK: "batch/v1/Job",
		Why: "Unblocks a CronJob whose concurrencyPolicy is Forbid and whose previous run's Job object " +
			"is still present (completed, failed, or stuck) — deleting the stale Job, rather than " +
			"changing the schedule or the policy (patchfield.go's spec.concurrencyPolicy row), is the " +
			"direct fix for \"the next scheduled run never starts because the last one is still " +
			"considered active\".",
	},
	{
		GVK: "v1/PersistentVolumeClaim",
		Why: "Added 2026-09-01 (BUGS.md 118 part (b), BACKLOG.md AK1), an explicit owner decision, " +
			"narrowly scoped: a StatefulSet volumeClaimTemplate PVC left Bound with no owning Pod after " +
			"a scale-down (this cluster's confirmed-live persistentVolumeClaimRetentionPolicy default is " +
			"Retain), where ownership resolves managed_by: none and no live Pod references the claim. " +
			"Both conditions are re-checked live at execution time, not trusted from the incident that " +
			"proposed this plan — see this file's header comment for exactly where. A PVC that is still " +
			"owned or still mounted gets neither check to pass, and is refused the same as any other " +
			"disallowed kind. Every OTHER PersistentVolumeClaim — one still bound to a live workload, " +
			"one a controller still declares — is not made reachable by this row; DESIGN.md §9.3's " +
			"forbidden tier still applies to those exactly as before.",
	},
}

// DeleteResourcePermitted reports whether gvk may be targeted by a
// DeleteResource plan.
//
// The refusal names the GVK, mirroring PatchFieldPermitted's own reasoning:
// this is a permission decision, not a missing feature, and the message
// should read as one.
func DeleteResourcePermitted(gvk string) (deletableKind, error) {
	for _, entry := range deleteResourceAllowlist {
		if entry.GVK == gvk {
			return entry, nil
		}
	}
	return deletableKind{}, fmt.Errorf("DeleteResource may not target %s — that kind is not in the reviewed allowlist (internal/remediation/deleteresource.go). This is a permission decision, not a missing feature: deletion is effectively irreversible, so the allowlist is deliberately narrow and StatefulSet/Namespace/CustomResourceDefinition are never permitted targets regardless of risk floor; PersistentVolumeClaim is permitted only for the narrow orphaned/unreferenced case this package's header comment describes, re-checked live at execution time — naming the kind here is not by itself a grant to delete any given PVC", gvk)
}

// DeleteResourceAllowlistEntries exposes the table for tests and for a
// future admission-policy generator, matching PatchFieldAllowlistEntries'
// own reasoning.
func DeleteResourceAllowlistEntries() []deletableKind {
	out := make([]deletableKind, len(deleteResourceAllowlist))
	copy(out, deleteResourceAllowlist)
	return out
}
