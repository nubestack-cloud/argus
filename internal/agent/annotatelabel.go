package agent

// annotate_resource / label_resource execute
// remediation.ActionAnnotateResource / remediation.ActionLabelResource: set
// one key to one value in metadata.annotations (or metadata.labels) on a
// live object, where the (kind, key) -> allowed-value pair is in the
// reviewed allowlist internal/remediation/annotatelabel.go declares.
//
// # Why the allowlist is re-checked HERE too
//
// Same reasoning as patch_field's own re-check (see patchfield.go's header
// comment): the signature proves this plan came from something holding the
// hub's key, not that the plan SHOULD have been written. So this agent
// re-derives the (kind, key, value) authorisation from its own copy of the
// table before ever calling Patch — DESIGN.md §10.3's "even a fully
// compromised hub cannot make an agent" exceed local guardrails.
//
// # Why a strategic-merge patch, not a JSON patch
//
// A map key is exactly what a strategic-merge patch is good at: naming one
// key inside metadata.annotations/metadata.labels merges that one entry and
// leaves every sibling alone, with no positional addressing at all — unlike
// patch_field's use of JSON Patch, there is no list index here to make a
// strategic merge the wrong tool.
//
// # Why the rollback check here is looser than patch_field's
//
// patch_resource_limits/patch_field/revert_container_image all REFUSE to
// execute without a signed rollback. This tool does not, because a nil
// rollback is a real and EXPECTED state here, not a hub bug: preparePlan
// (internal/api/remediation_exec.go) leaves it nil precisely when the key
// was not previously set — the common case for these two action types,
// which exist mostly to ADD new provenance metadata, not to correct
// existing values. When a rollback IS present, it is checked exactly like
// patch_field's: same action type, same key.
import (
	"context"
	"encoding/json"
	"fmt"

	"argus/internal/remediation"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// annotateLabelPatchableResources is the resource set this tool will touch —
// deliberately the same two kinds internal/remediation/annotatelabel.go's
// allowlist names today (Deployment, StatefulSet), checked here as well so a
// future allowlist row naming a kind this tool has not been extended to
// cover fails closed with a clear message rather than attempting an
// unreviewed patch shape.
var annotateLabelPatchableResources = map[string]bool{
	"deployments":  true,
	"statefulsets": true,
}

// annotateOrLabelResource is the shared implementation behind both tool
// entry points below — one function so the two cannot silently diverge in
// how they build the patch, only in which map (annotations/labels) and which
// allowlist (AnnotationPermitted/LabelPermitted) they use.
func (e *ToolExecutor) annotateOrLabelResource(ctx context.Context, rawArgs json.RawMessage, actionType remediation.ActionType, mapName string) (json.RawMessage, bool, error) {
	plan, gvr, err := e.verifySignedPlan(rawArgs, actionType)
	if err != nil {
		return nil, false, err
	}
	if !annotateLabelPatchableResources[gvr.Resource] {
		return nil, false, fmt.Errorf("%s does not support target resource %q (Deployment and StatefulSet only)", mapName, gvr.Resource)
	}

	key, value, err := decodeAnnotateOrLabelParams(plan.Params, actionType)
	if err != nil {
		return nil, false, err
	}

	var permErr error
	if actionType == remediation.ActionAnnotateResource {
		_, permErr = remediation.AnnotationPermitted(plan.TargetGVK, key, value)
	} else {
		_, permErr = remediation.LabelPermitted(plan.TargetGVK, key, value)
	}
	if permErr != nil {
		return nil, false, fmt.Errorf("agent-side allowlist refused this plan: %w", permErr)
	}

	// The rollback, when present, must address the SAME key — a rollback
	// pointing elsewhere would be a second, unreviewed write dressed as a
	// reversal. Absent entirely is fine (see this file's header comment).
	if plan.Rollback != nil {
		if plan.Rollback.ActionType != actionType {
			return nil, false, fmt.Errorf("signed plan's rollback is a %q, which cannot undo a %s", plan.Rollback.ActionType, actionType)
		}
		rollbackKey, _, err := decodeAnnotateOrLabelParams(plan.Rollback.Params, actionType)
		if err != nil {
			return nil, false, fmt.Errorf("invalid rollback params: %w", err)
		}
		if rollbackKey != key {
			return nil, false, fmt.Errorf("the plan's rollback targets %q but the plan changes %q — an undo must address the same key", rollbackKey, key)
		}
	}

	live, err := e.dynamic.Resource(gvr).Namespace(plan.TargetNamespace).Get(ctx, plan.TargetName, metav1.GetOptions{})
	if err != nil {
		return nil, false, sanitizeK8sErr(err)
	}
	if live.GetResourceVersion() != plan.ResourceVersion {
		return nil, false, fmt.Errorf("the target has changed since this plan was signed (resourceVersion %s, plan expected %s) — refusing to apply a plan whose preconditions no longer hold", live.GetResourceVersion(), plan.ResourceVersion)
	}
	var current map[string]any
	switch mapName {
	case "annotations":
		current, _, _ = unstructuredNestedMap(live.Object, "metadata", "annotations")
	default:
		current, _, _ = unstructuredNestedMap(live.Object, "metadata", "labels")
	}
	if existing, ok := current[key]; ok {
		if existingStr, ok := existing.(string); ok && existingStr == value {
			return nil, false, fmt.Errorf("%s %q is already %q — refusing to execute a change with nothing in it", mapName, key, value)
		}
	}

	patch, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"resourceVersion": plan.ResourceVersion,
			mapName:           map[string]any{key: value},
		},
	})
	if err != nil {
		return nil, false, fmt.Errorf("build patch: %w", err)
	}

	patched, err := e.applyPlanPatch(ctx, gvr, plan, patch)
	if err != nil {
		return nil, false, sanitizeK8sErr(err)
	}
	return planPatchResult(plan, patched, patch), false, nil
}

// annotateResource is the annotate_resource tool entry point.
func (e *ToolExecutor) annotateResource(ctx context.Context, rawArgs json.RawMessage) (json.RawMessage, bool, error) {
	return e.annotateOrLabelResource(ctx, rawArgs, remediation.ActionAnnotateResource, "annotations")
}

// labelResource is the label_resource tool entry point.
func (e *ToolExecutor) labelResource(ctx context.Context, rawArgs json.RawMessage) (json.RawMessage, bool, error) {
	return e.annotateOrLabelResource(ctx, rawArgs, remediation.ActionLabelResource, "labels")
}

// decodeAnnotateOrLabelParams decodes plan/rollback params for whichever of
// the two action types this call concerns and re-runs the params' own
// shape-only Validate — the same "agent-side re-validation" every other
// mutating tool in this package performs.
func decodeAnnotateOrLabelParams(raw json.RawMessage, actionType remediation.ActionType) (key, value string, err error) {
	switch actionType {
	case remediation.ActionAnnotateResource:
		var p remediation.AnnotateResourceParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return "", "", fmt.Errorf("invalid annotate resource params: %w", err)
		}
		if err := p.Validate(); err != nil {
			return "", "", fmt.Errorf("agent-side re-validation rejected this plan: %w", err)
		}
		return p.Key, p.Value, nil
	case remediation.ActionLabelResource:
		var p remediation.LabelResourceParams
		if err := json.Unmarshal(raw, &p); err != nil {
			return "", "", fmt.Errorf("invalid label resource params: %w", err)
		}
		if err := p.Validate(); err != nil {
			return "", "", fmt.Errorf("agent-side re-validation rejected this plan: %w", err)
		}
		return p.Key, p.Value, nil
	default:
		return "", "", fmt.Errorf("decodeAnnotateOrLabelParams called for action type %q", actionType)
	}
}

// unstructuredNestedMap is a tiny, local NestedStringMap-shaped reader over
// an unstructured object's map[string]any tree — client-go's own
// unstructured.NestedStringMap refuses a value that is not already
// map[string]string, which a freshly-decoded map[string]any tree never is
// (JSON numbers/maps all decode as any). Returns (nil, false, nil) for an
// absent path, matching this package's existing nestedFieldAt's own
// not-found convention (patchfield.go).
func unstructuredNestedMap(obj map[string]any, fields ...string) (map[string]any, bool, error) {
	var cur any = obj
	for _, f := range fields {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false, nil
		}
		v, ok := m[f]
		if !ok {
			return nil, false, nil
		}
		cur = v
	}
	m, ok := cur.(map[string]any)
	return m, ok, nil
}
