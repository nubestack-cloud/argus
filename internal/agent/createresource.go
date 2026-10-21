package agent

// create_resource executes remediation.ActionCreateResource: creates a
// brand-new object at the signed plan's target GVK/namespace/name, where the
// target KIND is in the reviewed allowlist internal/remediation/
// createresource.go declares (ConfigMap only today — see that file's header
// comment for why).
//
// # Why this tool re-checks existence itself, and refuses rather than replaces
//
// preparePlan (internal/api/remediation_exec.go) already confirms the target
// does not exist before ever signing the plan — but that confirmation is a
// moment in time, and the moment this tool actually runs is not the same
// moment. This task's own brief is explicit: "refuse if the object already
// exists, fail closed, not silently become a replace." So this tool performs
// its OWN Get immediately before the Create and refuses outright if the
// object is found — never falling back to an Update, which would be a
// completely different, unreviewed action (BACKLOG.md's own text keeps
// replaceResource deliberately unbuilt, precisely because a whole-object
// write has no admission-policy allowlist shape this codebase can express;
// silently taking that path here would reintroduce the exact thing that
// stayed out of scope). The residual TOCTOU window between this Get and the
// Create call itself is closed by the API server's own guarantee: Create on
// an object that has since come to exist returns AlreadyExists, which this
// tool treats identically to the Get finding it — a refusal, never a
// fallback.
//
// # Why there is no resourceVersion precondition
//
// Every other mutating tool in this package embeds the target's live
// resourceVersion as its precondition (applyPlanPatch's patch-body embedding
// for Patch-based tools, metav1.Preconditions for delete_resource). A CREATE
// has no live object to have a resourceVersion in the first place — this
// tool's precondition is the Get-then-Create sequence above, and
// verifySignedPlan is told to accept this action type's plans with no
// ResourceVersion set at all (see that function's own comment).
//
// # Why there is no rollback check here
//
// Same reasoning as delete_resource's own doc comment, in the opposite
// direction: deleteResource's allowlist (Pod, Job) does not include any kind
// createResource can target, so there is no CompensatingAction shape this
// codebase's closed action-type set can express for "undo a create" through
// its reviewed delete mechanism. remediation.RemediationPlan.Validate
// already refuses a CreateResource plan that claims Reversible=true before
// this tool is ever reached, so nothing here needs to re-check that either.
//
// # No redaction step
//
// Every Patch-based tool in this package that touches an EXISTING value
// (patch_field, annotate_resource/label_resource with a live current value)
// captures that value for a potential rollback before mutating. This tool
// creates content the plan itself specifies, in full, from nothing — there
// is no prior value to read, compare against, or redact; the
// redact.Marker echo guard already runs on the params themselves
// (CreateResourceParams.Validate, re-run below), which is the correct and
// sufficient place for it.
import (
	"context"
	"encoding/json"
	"fmt"

	"argus/internal/remediation"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// createResourcePatchableResources is the resource set this tool will
// create — the same single kind internal/remediation/createresource.go's
// allowlist names, checked here too for the identical "fail closed on a row
// this tool has not been extended to cover" reason
// deleteResourcePatchableResources/annotateLabelPatchableResources are.
var createResourcePatchableResources = map[string]bool{
	"configmaps": true,
}

// createResourceResult is this tool's successful result. Mirrors
// deleteResourceResult's own shape and reasoning: no live "before" object to
// echo back (there was none), so DryRun plus the target identity is the
// whole of what a caller needs to confirm a rehearsal happened.
type createResourceResult struct {
	DryRun          bool   `json:"dryRun"`
	GVK             string `json:"gvk"`
	Namespace       string `json:"namespace"`
	Name            string `json:"name"`
	ResourceVersion string `json:"resourceVersion,omitempty"`
}

// createResource is the create_resource tool entry point.
func (e *ToolExecutor) createResource(ctx context.Context, rawArgs json.RawMessage) (json.RawMessage, bool, error) {
	plan, gvr, err := e.verifySignedPlan(rawArgs, remediation.ActionCreateResource)
	if err != nil {
		return nil, false, err
	}
	if !createResourcePatchableResources[gvr.Resource] {
		return nil, false, fmt.Errorf("create_resource does not support target resource %q (ConfigMap only)", gvr.Resource)
	}

	// The independent, agent-side re-check of the kind allowlist — same
	// reasoning as every other mutating tool's re-check: the signature
	// proves who signed the plan, not that the plan should have been
	// written.
	if _, err := remediation.CreateResourcePermitted(plan.TargetGVK); err != nil {
		return nil, false, fmt.Errorf("agent-side allowlist refused this plan: %w", err)
	}

	var params remediation.CreateResourceParams
	if err := json.Unmarshal(plan.Params, &params); err != nil {
		return nil, false, fmt.Errorf("invalid create resource params: %w", err)
	}
	if err := params.Validate(); err != nil {
		return nil, false, fmt.Errorf("agent-side re-validation rejected this plan: %w", err)
	}

	gvk, err := parseGVKString(plan.TargetGVK)
	if err != nil {
		return nil, false, err
	}

	// Fail closed, not a silent replace: refuse outright if the object
	// already exists, rather than falling back to an Update — see this
	// file's own doc comment for why that fallback is exactly what this
	// task must not build.
	if _, getErr := e.dynamic.Resource(gvr).Namespace(plan.TargetNamespace).Get(ctx, plan.TargetName, metav1.GetOptions{}); getErr == nil {
		return nil, false, fmt.Errorf("%s %s/%s already exists — create_resource refuses to target an existing object rather than silently becoming a replace (a mechanism this codebase deliberately does not build; see internal/remediation/plan.go's ActionCreateResource comment on why replaceResource stays deferred)", plan.TargetGVK, plan.TargetNamespace, plan.TargetName)
	} else if !apierrors.IsNotFound(getErr) {
		return nil, false, sanitizeK8sErr(getErr)
	}

	data := make(map[string]any, len(params.Data))
	for k, v := range params.Data {
		data[k] = v
	}
	obj := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": gvk.GroupVersion().String(),
		"kind":       gvk.Kind,
		"metadata": map[string]any{
			"name":      plan.TargetName,
			"namespace": plan.TargetNamespace,
		},
		"data": data,
	}}

	opts := metav1.CreateOptions{}
	if plan.DryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}
	created, err := e.dynamic.Resource(gvr).Namespace(plan.TargetNamespace).Create(ctx, obj, opts)
	if err != nil {
		if rejection, isAdmission := admissionRejection(err); isAdmission {
			return nil, false, fmt.Errorf("the cluster refused this change: %s", rejection)
		}
		if apierrors.IsAlreadyExists(err) {
			// The TOCTOU case this file's own doc comment names: the object
			// came to exist in the window between the Get above and this
			// Create. Refused, exactly like the Get finding it — never a
			// fallback to Update.
			return nil, false, fmt.Errorf("%s %s/%s was created by something else while this plan was being applied — refusing to overwrite it", plan.TargetGVK, plan.TargetNamespace, plan.TargetName)
		}
		return nil, false, sanitizeK8sErr(err)
	}

	result := createResourceResult{
		DryRun: plan.DryRun, GVK: plan.TargetGVK, Namespace: plan.TargetNamespace, Name: plan.TargetName,
	}
	if created != nil {
		result.ResourceVersion = created.GetResourceVersion()
	}
	return mustMarshal(result), false, nil
}
