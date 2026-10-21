package agent

// patch_field executes a remediation.ActionPatchField plan: it sets one field on
// one live object, where the (kind, field path) pair is in the reviewed allowlist
// in internal/remediation/patchfield.go.
//
// # Why the allowlist is checked HERE as well as hub-side
//
// The hub already refuses a path that is not permitted, at plan validation. This
// checks it again, and that is not belt-and-braces for its own sake — it is
// DESIGN.md §10.3's agent-side re-validation, and for a generic patcher it is the
// difference between a bounded action and an arbitrary one.
//
// The threat is not a buggy hub. It is a compromised one: a prompt-injected
// model, a leaked signing key, or an operator-facing bug that lets an
// unauthorised path through validation. The signature proves a plan came from
// something holding the hub's key; it proves nothing about whether the plan
// should have been written. So the agent re-derives the authorisation from its
// own copy of the table, and the cluster's ValidatingAdmissionPolicy enumerates
// the same set again beneath that. Three enumerations of one permission, each
// surviving the one above it being wrong.
//
// # Why a JSON Patch rather than a strategic merge
//
// Every other action here uses a strategic merge patch, which is the right tool
// when the path is fixed and known. It is the wrong tool for a path containing a
// list index: a strategic merge patch addresses list elements by their MERGE KEY
// (`port` for a Service's ports, `name` for containers), not by position, so
// expressing "element 0" means knowing each list's merge key and rewriting the
// path accordingly — a second table, and a source of silent mis-targeting.
//
// A JSON Patch (RFC 6902) addresses by position directly, and brings something
// the merge patch cannot: a `test` operation, which makes the write an ATOMIC
// compare-and-swap on the field itself. The resourceVersion precondition already
// catches an object that changed; `test` additionally catches the case where the
// object is untouched and the plan's belief about this one field was wrong from
// the start. That is checked by the API server, not by this code reading and then
// writing, so nothing can interleave between the two.
//
// JSON Patch's known weakness — every intermediate path segment must already
// exist — is handled by choosing the operation from what is actually there:
// `replace` (with a `test`) when the field exists, `add` when it does not and its
// parent does. A missing parent is refused rather than created, because creating
// intermediate structure on a live object is how a patch invents a shape nobody
// reviewed.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"argus/internal/logging"
	"strconv"
	"strings"

	"argus/internal/remediation"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

// patchField is the tool entry point.
func (e *ToolExecutor) patchField(ctx context.Context, rawArgs json.RawMessage) (json.RawMessage, bool, error) {
	plan, gvr, err := e.verifySignedPlan(rawArgs, remediation.ActionPatchField)
	if err != nil {
		return nil, false, err
	}

	var params remediation.PatchFieldParams
	if err := json.Unmarshal(plan.Params, &params); err != nil {
		return nil, false, fmt.Errorf("invalid patch field params: %w", err)
	}
	if err := params.Validate(); err != nil {
		return nil, false, fmt.Errorf("agent-side re-validation rejected this plan: %w", err)
	}

	// The independent authorisation check. Uses the plan's own signed GVK, not
	// the resource the request happened to be routed to, so a plan cannot be
	// aimed at one kind and executed against another.
	entry, err := remediation.PatchFieldPermitted(plan.TargetGVK, params.FieldPath)
	if err != nil {
		return nil, false, fmt.Errorf("agent-side allowlist refused this plan: %w", err)
	}

	// Same mandatory-rollback rule the other mutating tools carry, and for the
	// same reason: DESIGN.md §10.3 requires the compensating action to be
	// captured from live state before execution, the hub is the side that reads
	// it, so refusing to run without one is the only way this side can enforce
	// that it happened. Rollback is inside the signature, so this also
	// distinguishes "the hub captured nothing" from "something stripped it".
	if plan.Rollback == nil {
		return nil, false, fmt.Errorf("signed plan carries no rollback: this action requires a pre-computed compensating action captured from live state before execution")
	}
	if plan.Rollback.ActionType != remediation.ActionPatchField {
		return nil, false, fmt.Errorf("signed plan's rollback is a %q, which cannot undo a PatchField", plan.Rollback.ActionType)
	}
	var rollbackParams remediation.PatchFieldParams
	if err := json.Unmarshal(plan.Rollback.Params, &rollbackParams); err != nil {
		return nil, false, fmt.Errorf("invalid rollback params: %w", err)
	}
	// The undo must address the SAME field. A rollback pointing elsewhere would
	// be a second unreviewed write dressed as a reversal.
	if normalisePath(rollbackParams.FieldPath) != normalisePath(params.FieldPath) {
		return nil, false, fmt.Errorf("the plan's rollback targets %q but the plan changes %q — an undo must address the same field",
			rollbackParams.FieldPath, params.FieldPath)
	}

	live, err := e.dynamic.Resource(gvr).Namespace(plan.TargetNamespace).
		Get(ctx, plan.TargetName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, false, fmt.Errorf("%s %s/%s does not exist", plan.TargetGVK, plan.TargetNamespace, plan.TargetName)
		}
		return nil, false, fmt.Errorf("read %s %s/%s before patching: %w", plan.TargetGVK, plan.TargetNamespace, plan.TargetName, err)
	}
	// Same check every other mutating tool in this package makes (see
	// annotateOrLabelResource, deleteResource, scaleDeployment et al.) — this
	// file's own doc comment above already describes it as a precondition
	// that "already catches an object that changed," which was true of the
	// design but not, until this line, of the code. Without it, a PatchField
	// plan signed against resourceVersion V1 would still apply after an
	// unrelated field bumped the object to V2, so long as the ONE field this
	// plan addresses happened to still hold the value the plan expects —
	// exactly the approval-integrity gap "any change to the plan or target
	// invalidates the approval" exists to close.
	if live.GetResourceVersion() != plan.ResourceVersion {
		return nil, false, fmt.Errorf("the target has changed since this plan was signed (resourceVersion %s, plan expected %s) — refusing to apply a plan whose preconditions no longer hold", live.GetResourceVersion(), plan.ResourceVersion)
	}

	segments := strings.Split(normalisePath(params.FieldPath), ".")
	current, found, err := nestedFieldAt(live.Object, segments)
	if err != nil {
		return nil, false, fmt.Errorf("cannot address %s on the live object: %w", params.FieldPath, err)
	}

	newValue, err := coerceFieldValue(params.NewValue, entry.Type)
	if err != nil {
		return nil, false, fmt.Errorf("%s expects %s: %w", params.FieldPath, entry.Type, err)
	}

	// ExpectCurrent, when the plan carries one, is checked against what is
	// actually there before anything is built — so the refusal names the real
	// value rather than reporting a failed `test` operation the operator cannot
	// interpret.
	if params.ExpectCurrent != "" {
		if !found {
			return nil, false, fmt.Errorf("this plan expected %s to be %q, but the field is not set on the live object — it was built against a different version of it",
				params.FieldPath, params.ExpectCurrent)
		}
		if fmt.Sprintf("%v", current) != params.ExpectCurrent {
			return nil, false, fmt.Errorf("this plan expected %s to be %q; it is %v — it was built against a different version of this object",
				params.FieldPath, params.ExpectCurrent, current)
		}
	}
	if found && fmt.Sprintf("%v", current) == fmt.Sprintf("%v", newValue) {
		return nil, false, fmt.Errorf("%s is already %v — refusing to execute a change with nothing in it", params.FieldPath, newValue)
	}
	if !found {
		// The field is absent, so its parent must exist for an `add` to land.
		if _, parentFound, perr := nestedFieldAt(live.Object, segments[:len(segments)-1]); perr != nil || !parentFound {
			return nil, false, fmt.Errorf("neither %s nor its parent exists on the live object; this action sets a field, it does not create the structure around one",
				params.FieldPath)
		}
	}

	patch, err := buildJSONPatch(segments, current, newValue, found)
	if err != nil {
		return nil, false, err
	}

	// BACKLOG.md F12's dry-run gate, honored here exactly the way
	// applyPlanPatch (tools.go) centralizes it for every strategic-merge
	// action — found MISSING entirely on a real cluster (BACKLOG.md E4/F14
	// live verification, 2026-08-31): this call used to submit with a bare
	// metav1.PatchOptions{}, ignoring plan.DryRun completely, which is
	// precisely the bug applyPlanPatch's own doc comment warns a fifth,
	// independently-written action type would introduce — "a bug whose
	// symptom is a 'dry run' that changes the cluster." It did exactly that:
	// the REHEARSAL step (called before a human's approval is even final)
	// silently applied for real. interpretDryRunResult
	// (internal/api/remediation_exec.go) then failed closed on the missing
	// `dryRun` echo (this tool's `out` map never set one either) and reported
	// the whole operation as FAILED — so the hub's own bookkeeping was never
	// fooled into a wrong precondition or a double-apply, but the operator
	// still saw "failed" while the field had already changed on the live
	// cluster, before any approval had actually taken effect. Confirmed live,
	// not theorized: CAPABILITIES.md §6bx measured the object's real field
	// value immediately after a "failed" (502) approve call and found it
	// already at the proposed value. Fixed here; see that entry for the full
	// account. Not separately covered by a fast unit test: client-go's fake
	// dynamic client cannot execute a JSON Patch at all (this file's own
	// TestPatchField_BuildsTheRightPatch header comment explains why), so a
	// dry-run-vs-real regression test for this specific action would need the
	// shared fake reactor (remediation_exec_test.go's
	// installRealisticPatchReactor) extended to parse JSON Patch bodies
	// rather than just merge-patch ones — real, worthwhile follow-up work,
	// not attempted here. The live-cluster proof above is the load-bearing
	// verification for this fix in the meantime.
	opts := metav1.PatchOptions{}
	if plan.DryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}
	patched, err := e.dynamic.Resource(gvr).Namespace(plan.TargetNamespace).Patch(
		ctx, plan.TargetName, types.JSONPatchType, patch, opts)
	if err != nil {
		if rejection, isAdmission := admissionRejection(err); isAdmission {
			// The cluster's own admission policy refused it. Surfaced verbatim
			// because it is the layer that holds when everything on this side is
			// compromised, and its message is the only honest account of why.
			return nil, false, fmt.Errorf("the cluster refused this change: %s", rejection)
		}
		if apierrors.IsInvalid(err) {
			return nil, false, fmt.Errorf("the API server rejected %s = %v as invalid for this object: %w", params.FieldPath, newValue, err)
		}
		if apierrors.IsConflict(err) {
			return nil, false, fmt.Errorf("%s %s/%s changed while this was being applied: %w", plan.TargetGVK, plan.TargetNamespace, plan.TargetName, err)
		}
		return nil, false, fmt.Errorf("patch %s on %s %s/%s: %w", params.FieldPath, plan.TargetGVK, plan.TargetNamespace, plan.TargetName, err)
	}

	// Read the result back from the response rather than trusting the request:
	// the value that matters is the one the API server stored, after whatever
	// defaulting or coercion it applied.
	applied, appliedFound, _ := nestedFieldAt(patched.Object, segments)
	if !appliedFound {
		return nil, false, fmt.Errorf("the patch was accepted but %s is not set on the returned object", params.FieldPath)
	}

	result := map[string]any{
		"gvk":             plan.TargetGVK,
		"namespace":       plan.TargetNamespace,
		"name":            plan.TargetName,
		"fieldPath":       normalisePath(params.FieldPath),
		"previousValue":   fmt.Sprintf("%v", current),
		"appliedValue":    fmt.Sprintf("%v", applied),
		"fieldExisted":    found,
		"resourceVersion": patched.GetResourceVersion(),
		// dryRun MUST be set on every response, real or rehearsed — see this
		// function's own comment above the Patch call. interpretDryRunResult
		// (internal/api/remediation_exec.go) treats a missing/false value on
		// a dry-run request as a failed attestation, by design: the whole
		// point of the echo is telling an agent that actually rehearsed the
		// change apart from one that ignored plan.DryRun and mutated for
		// real.
		"dryRun": plan.DryRun,
	}
	if plan.DryRun {
		// Best-effort diff payload, exactly like planPatchResult's for the
		// strategic-merge actions: the object as the API server would really
		// produce it (after defaulting/admission), and the patch exactly as
		// submitted. Neither failure here should ever fail the attestation
		// itself — the API server has already accepted the patch, which is
		// the fact the gate needs.
		if b, err := patched.MarshalJSON(); err != nil {
			logger.Warn("dry-run patch_field: could not marshal the resulting object for the diff",
				slog.String("target_gvk", plan.TargetGVK), slog.String("target_namespace", plan.TargetNamespace),
				slog.String("target_name", plan.TargetName), logging.Err(err))
		} else if len(b) > maxDryRunObjectBytes {
			logger.Warn("dry-run patch_field: resulting object past the diff-payload size cap — attesting without the diff payload",
				slog.String("target_gvk", plan.TargetGVK), slog.String("target_namespace", plan.TargetNamespace),
				slog.String("target_name", plan.TargetName), slog.Int("bytes", len(b)), slog.Int("cap_bytes", maxDryRunObjectBytes))
		} else {
			result["object"] = json.RawMessage(b)
		}
		result["patch"] = json.RawMessage(patch)
	}

	out, err := json.Marshal(result)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// normalisePath mirrors remediation.normaliseFieldPath so the agent splits a path
// exactly as the allowlist matched it. Deliberately duplicated rather than
// exported across the package boundary: the two are checked against each other by
// TestPatchFieldPathNotationMatchesTheHub.
func normalisePath(p string) string {
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

// nestedFieldAt walks an unstructured object, handling both map keys and list
// indices. client-go's NestedFieldNoCopy cannot do the latter, which is the whole
// reason this exists.
func nestedFieldAt(obj map[string]any, segments []string) (any, bool, error) {
	var cur any = obj
	for i, seg := range segments {
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[seg]
			if !ok {
				return nil, false, nil
			}
			cur = v
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil {
				return nil, false, fmt.Errorf("%q is a list, so %q must be an index", strings.Join(segments[:i], "."), seg)
			}
			if idx < 0 || idx >= len(node) {
				return nil, false, nil
			}
			cur = node[idx]
		default:
			return nil, false, fmt.Errorf("%q is a single value, so %q cannot be read from it", strings.Join(segments[:i], "."), seg)
		}
	}
	return cur, true, nil
}

// coerceFieldValue converts the plan's string into the type the allowlist
// declares for that field.
func coerceFieldValue(raw string, t remediation.FieldType) (any, error) {
	switch t {
	case remediation.FieldString:
		return raw, nil
	case remediation.FieldInt:
		n, err := strconv.Atoi(raw)
		if err != nil {
			return nil, fmt.Errorf("%q is not an integer", raw)
		}
		return n, nil
	case remediation.FieldIntOrString:
		// A number if it parses as one, a string otherwise — which is exactly how
		// Kubernetes' own IntOrString behaves, so a targetPort of 8080 lands as a
		// number and one of "http" lands as a name.
		if n, err := strconv.Atoi(raw); err == nil {
			return n, nil
		}
		return raw, nil
	default:
		return nil, fmt.Errorf("unrecognised field type %q", t)
	}
}

// buildJSONPatch renders the operations for one field.
//
// When the field exists, a `test` precedes the `replace`, making the write an
// atomic compare-and-swap the API SERVER evaluates — not this process reading and
// then writing, between which anything could interleave. When it does not, a bare
// `add`, because there is nothing to test against.
func buildJSONPatch(segments []string, current, newValue any, exists bool) ([]byte, error) {
	pointer := "/" + strings.Join(escapeJSONPointer(segments), "/")
	ops := make([]map[string]any, 0, 2)
	if exists {
		ops = append(ops, map[string]any{"op": "test", "path": pointer, "value": current})
		ops = append(ops, map[string]any{"op": "replace", "path": pointer, "value": newValue})
	} else {
		ops = append(ops, map[string]any{"op": "add", "path": pointer, "value": newValue})
	}
	return json.Marshal(ops)
}

// escapeJSONPointer applies RFC 6901's escaping. A Kubernetes label key can
// contain "/" — `app.kubernetes.io/name` is the canonical example and is exactly
// the sort of key a Service selector fix would target — and an unescaped one
// would silently address a different, deeper path.
func escapeJSONPointer(segments []string) []string {
	out := make([]string, len(segments))
	for i, s := range segments {
		s = strings.ReplaceAll(s, "~", "~0")
		s = strings.ReplaceAll(s, "/", "~1")
		out[i] = s
	}
	return out
}
