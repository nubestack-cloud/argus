package agent

// delete_resource executes remediation.ActionDeleteResource: removes the
// signed plan's target object from the cluster entirely, where the target
// KIND is in the reviewed allowlist internal/remediation/deleteresource.go
// declares (Pod, Job, PersistentVolumeClaim — see that file's header
// comment for why, and for why this is a genuinely different mechanism from
// the GitOps repository-file deletion internal/gitops/files.go implements).
//
// # The PersistentVolumeClaim liveness precondition
//
// Pod and Job carry no extra precondition beyond the allowlist check and the
// ordinary resourceVersion/UID compare-and-swap every kind here gets.
// PersistentVolumeClaim (added 2026-09-01, BUGS.md 118 part (b)) gets one
// more: a fresh List of every Pod in the target's namespace, checked for a
// volume naming this claim, refusing the delete if any Pod still references
// it. This is deliberately NOT a read of the incident's own stored facts —
// "ask about the object you are about to act on" (this codebase's own
// argus-context lesson) means the tool that is actually about to delete
// something makes its own live determination, the same discipline
// checkOrphanedPVC's referencedClaims map already applies at DETECTION time
// (internal/agent/sweep_detector.go) — this is that same check, run again,
// independently, immediately before the mutation, because the seconds
// between an incident opening and a human approving its plan are exactly
// when a claim could stop being orphaned (a StatefulSet scaled back up, a
// new Pod created directly against the same claim name). The ownership half
// of "genuinely orphaned" (no GitOps/Helm controller declares this object)
// is NOT re-checked here — that is internal/api/remediation_exec.go's job,
// ahead of signing, where the ownership tool call already lives for every
// other action type; duplicating it here would mean trusting two different
// answers to the same question rather than one.
//
// # Why there is no rollback check here
//
// Every other mutating tool in this package refuses to execute without a
// signed rollback (patch_resource_limits, patch_field) or accepts one
// optionally (annotate_resource/label_resource). This tool checks for
// neither, because DESIGN.md §10.5 is explicit that a delete has none:
// "deletion is therefore effectively irreversible" — there is no
// CompensatingAction shape this codebase's closed action-type set can
// express for "recreate what was deleted" (that would be createResource,
// which this task's own brief blocks explicitly), so
// remediation.RemediationPlan.Validate already refuses a DeleteResource plan
// that claims Reversible=true before this tool is ever reached. Nothing
// here needs to re-check that: a plan that failed validation was never
// signed in the first place.
//
// # Why Delete uses Preconditions rather than an embedded resourceVersion
//
// Every patch-based tool in this file embeds the expected resourceVersion
// directly in the strategic-merge patch body (applyPlanPatch's own doc
// comment: "the resourceVersion precondition ... embedded directly in the
// same patch body ... rather than a separate Get-then-Patch pair"). A DELETE
// call has no body to embed one in; client-go's dynamic client expresses
// the identical atomic compare-and-fail through
// metav1.DeleteOptions.Preconditions.ResourceVersion, which the API server
// enforces the same way — the request fails rather than deleting an object
// that changed since this plan was signed.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"argus/internal/remediation"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// deleteResourcePatchableResources is the resource set this tool will
// delete — the same three kinds internal/remediation/deleteresource.go's
// allowlist names, checked here too for the identical "fail closed on a row
// this tool has not been extended to cover" reason
// annotateLabelPatchableResources is.
var deleteResourcePatchableResources = map[string]bool{
	"pods":                   true,
	"jobs":                   true,
	"persistentvolumeclaims": true,
}

// errPVCStillReferenced is deleteResource's sentinel for the liveness
// precondition below — a Pod still mounts the claim, so this is not the
// orphaned case internal/remediation/deleteresource.go's allowlist entry
// names. Its own error type (matching every other named refusal in this
// package) so a caller can distinguish "still in use" from "not found" or
// "stale resourceVersion" rather than matching on message text.
var errPVCStillReferenced = errors.New("refusing to delete a PersistentVolumeClaim that a live Pod still references")

// errDeletionAlreadyInProgress is PROJECT.md B146's sentinel: the target
// already carries a deletionTimestamp when this tool is asked to delete it —
// a finalizer is blocking full removal, and a plain Kubernetes DELETE call
// against an object already marked for deletion is a genuine no-op: the API
// server accepts it and returns success without touching metadata.finalizers
// at all. Found live 2026-09-06 (breadth-campaign TERM-001 fixture): a
// DeleteResource execution against an already-Terminating Pod was recorded
// outcome='succeeded' while the finalizer, and the Pod itself, were both
// unchanged for 5+ minutes — a false positive this product's own "truthful
// change control" promise cannot tolerate. Returning this as an ERROR here
// (rather than the previous silent success) routes the execution to
// forwardOutcomeStates' Failed destination — a human is notified with the
// real reason immediately, rather than the incident cycling
// Validating<->Reopened until B144's own bounded reopen limit gives up on it
// with nothing ever having actually happened.
var errDeletionAlreadyInProgress = errors.New("this object already carries a deletionTimestamp — deletion is already in progress, blocked by a finalizer this call cannot clear")

// checkPVCNotReferenced is the liveness half of the PersistentVolumeClaim
// precondition (see this file's header comment for the ownership half,
// which lives in internal/api/remediation_exec.go instead). A fresh List of
// every Pod in namespace, checked via the SAME podMountsClaim helper
// checkOrphanedPVC's own referencedClaims map is built from
// (internal/agent/objectref.go) — reusing it rather than re-implementing an
// equivalent scan is deliberate: this tool's answer to "does anything mount
// this claim" must be the identical check the detector uses to decide
// "orphaned" in the first place, not a second opinion that could disagree
// with it.
func (e *ToolExecutor) checkPVCNotReferenced(ctx context.Context, namespace, claimName string) error {
	pods, err := e.typed.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		// FAIL CLOSED: an unreadable Pod list is not evidence that nothing
		// references this claim. Sanitized the same way every other live
		// cluster error surfaced by this tool is.
		return fmt.Errorf("could not verify no Pod references this claim before deleting it: %w", sanitizeK8sErr(err))
	}
	for i := range pods.Items {
		if podMountsClaim(&pods.Items[i], claimName) {
			return fmt.Errorf("%w: Pod %s/%s still has a volume naming this claim", errPVCStillReferenced, namespace, pods.Items[i].Name)
		}
	}
	return nil
}

// deleteResourceResult is this tool's successful result. Deliberately no
// Object/Patch fields the way planPatchResult's shared shape carries for a
// Patch-based tool: there is no "resulting object" after a delete, and no
// patch body to echo back — DryRun and the target identity are the whole of
// what a caller needs to confirm a rehearsal happened (interpretDryRunResult
// only ever requires the DryRun echo; see that function's own doc comment
// for why an old agent's silence, not this shape, is the thing it guards
// against).
//
// Outcome distinguishes the two ways this can succeed (PROJECT.md B146,
// second pass, 2026-09-07). DeleteResource's whole point is "this object must
// not exist" — both deleteResourceOutcomeDeleted (this call issued the DELETE)
// AND deleteResourceOutcomeAlreadyGone (the object was already absent before
// this call ever reached it — something else deleted it, or it never existed
// by the time this plan executed) leave the cluster in exactly the state the
// plan wanted. Collapsing "already gone" into an error — this tool's own
// original behavior, and BUGS.md's original TERM-001-shaped complaint was
// about the OTHER direction (false success) — was itself a smaller version
// of the same honesty problem in reverse: it told a human "this failed" when
// the desired end state already held, blocking the incident in a Failed
// state a human then had to manually discover was actually fine, rather than
// letting it reach Validating and be confirmed the ordinary way
// (verifyDeletionHeld/interpretDeletionVerificationResult, internal/api/
// rollback.go — that check already asks "is the object still absent",
// unconditionally on either of this tool's two success paths, so nothing
// downstream needed to change to validate this correctly once the outcome
// classification itself was fixed). "Deletion already in progress" (a
// deletionTimestamp already set, a finalizer blocking) is the one case that
// stays a hard error: the object still exists, nothing this call can do
// clears the finalizer, and a human genuinely needs to act.
type deleteResourceResult struct {
	DryRun          bool   `json:"dryRun"`
	GVK             string `json:"gvk"`
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	ResourceVersion string `json:"resourceVersion"`
	Outcome         string `json:"outcome"`
}

const (
	deleteResourceOutcomeDeleted     = "deleted"
	deleteResourceOutcomeAlreadyGone = "alreadyGone"
)

// deleteResource is the delete_resource tool entry point.
func (e *ToolExecutor) deleteResource(ctx context.Context, rawArgs json.RawMessage) (json.RawMessage, bool, error) {
	plan, gvr, err := e.verifySignedPlan(rawArgs, remediation.ActionDeleteResource)
	if err != nil {
		return nil, false, err
	}
	if !deleteResourcePatchableResources[gvr.Resource] {
		return nil, false, fmt.Errorf("delete_resource does not support target resource %q (Pod, Job, and PersistentVolumeClaim only)", gvr.Resource)
	}

	// The independent, agent-side re-check of the kind allowlist — same
	// reasoning as every other mutating tool's re-check: the signature
	// proves who signed the plan, not that the plan should have been
	// written.
	if _, err := remediation.DeleteResourcePermitted(plan.TargetGVK); err != nil {
		return nil, false, fmt.Errorf("agent-side allowlist refused this plan: %w", err)
	}

	// PersistentVolumeClaim's own extra precondition (see this file's header
	// comment): a fresh liveness check, ahead of the Get/resourceVersion
	// check below, because "does any Pod still reference this" is not
	// something a resourceVersion compare-and-swap on the CLAIM itself could
	// ever catch — a Pod referencing it is a different object, and could be
	// created, or deleted, at a resourceVersion the claim's own history says
	// nothing about.
	if gvr.Resource == "persistentvolumeclaims" {
		if err := e.checkPVCNotReferenced(ctx, plan.TargetNamespace, plan.TargetName); err != nil {
			return nil, false, err
		}
	}

	live, err := e.dynamic.Resource(gvr).Namespace(plan.TargetNamespace).Get(ctx, plan.TargetName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			// PROJECT.md B146 (second pass): SUCCESS, not an error — see
			// deleteResourceResult's own doc comment for why "already gone"
			// is one of this tool's two honest success outcomes, not a
			// failure. No ResourceVersion to report (there is no live
			// object left to have one).
			result := deleteResourceResult{
				DryRun: plan.DryRun, GVK: plan.TargetGVK, Namespace: plan.TargetNamespace, Name: plan.TargetName,
				Outcome: deleteResourceOutcomeAlreadyGone,
			}
			return mustMarshal(result), false, nil
		}
		return nil, false, sanitizeK8sErr(err)
	}
	if live.GetResourceVersion() != plan.ResourceVersion {
		return nil, false, fmt.Errorf("the target has changed since this plan was signed (resourceVersion %s, plan expected %s) — refusing to apply a plan whose preconditions no longer hold", live.GetResourceVersion(), plan.ResourceVersion)
	}
	// PROJECT.md B146: checked BEFORE issuing the DELETE call, and checked
	// even for a dry-run rehearsal (an approver reviewing a dry-run deserves
	// the same true answer a real execution would give, not a rehearsal that
	// looks clean because it never got this far). A deletionTimestamp already
	// set means a finalizer is blocking full removal, and issuing DELETE
	// again cannot clear that finalizer or make removal happen any faster —
	// it can only re-assert an intent the API server already recorded. Named
	// finalizers included in the message, since an operator's real recovery
	// action (locating and patching out the responsible finalizer) needs to
	// know which one.
	if ts := live.GetDeletionTimestamp(); ts != nil {
		return nil, false, fmt.Errorf("%w (marked for deletion at %s, blocked by finalizer(s) %v)", errDeletionAlreadyInProgress, ts.Format(time.RFC3339), live.GetFinalizers())
	}
	liveUID := live.GetUID()

	opts := metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{ResourceVersion: &plan.ResourceVersion, UID: &liveUID},
	}
	if plan.DryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}
	if err := e.dynamic.Resource(gvr).Namespace(plan.TargetNamespace).Delete(ctx, plan.TargetName, opts); err != nil {
		if rejection, isAdmission := admissionRejection(err); isAdmission {
			return nil, false, fmt.Errorf("the cluster refused this change: %s", rejection)
		}
		if apierrors.IsConflict(err) || apierrors.IsNotFound(err) {
			return nil, false, fmt.Errorf("%s %s/%s changed while this was being applied: %w", plan.TargetGVK, plan.TargetNamespace, plan.TargetName, err)
		}
		return nil, false, sanitizeK8sErr(err)
	}

	result := deleteResourceResult{
		DryRun: plan.DryRun, GVK: plan.TargetGVK, Namespace: plan.TargetNamespace, Name: plan.TargetName,
		ResourceVersion: plan.ResourceVersion, Outcome: deleteResourceOutcomeDeleted,
	}
	return mustMarshal(result), false, nil
}
