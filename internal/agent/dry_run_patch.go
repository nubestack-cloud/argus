package agent

// dry_run_patch is BACKLOG.md C4's dry_run_patch half: an INVESTIGATION-time
// tool the model calls mid-investigation to test a hypothesis ("would
// setting this field to X actually fix it?"), before any plan is authored
// and before any human has approved anything.
//
// This is deliberately NOT F12's dry-run gate (internal/api/remediation_exec.go's
// attestByDryRun). That mechanism rehearses a plan that is already fully
// authored and narrowed through the signed-plan path, using argus-remediate's
// existing patch grant — it needed no new RBAC (see that gate's own
// "it was NOT blocked on C4" note). This tool proposes an ARBITRARY
// exploratory patch, against resources/fields argus-remediate may hold no
// grant on at all, which is why it needs its own ServiceAccount
// (argus-dryrun) with its own admission-policy-restricted write verbs — see
// dryrun_client.go's package doc comment for the full reasoning, and
// deploy/helm/argus-agent/templates/dryrun.yaml for the RBAC/admission-policy
// shape itself.
//
// Consequently this tool does NOT go through verifySignedPlan the way
// scale_deployment/restart_pod/patch_resource_limits/revert_container_image/
// patch_field do: there is no signed plan at this point in an investigation,
// by construction — nothing has been proposed yet. Its args are a bare
// target and a patch body, unmarshalled directly, exactly like the six
// read-only tools this file's sibling implements. What makes this safe
// despite that is NOT a signature check — it's that:
//
//  1. e.dryRunDynamic is a genuinely different, narrower-than-remediate but
//     still bounded credential (deploy/helm/argus-agent/templates/dryrun.yaml's
//     enumerated resource list), never the same client scale_deployment etc.
//     use.
//  2. metav1.PatchOptions.DryRun is hardcoded to
//     []string{metav1.DryRunAll} on every call this function makes — never
//     read from the caller's args, never omittable. dry_run_patch_test.go's
//     TestDryRunPatch_AlwaysSubmitsDryRunAll is the proof that stays true.
//  3. The cluster's own ValidatingAdmissionPolicy (argus-dryrun-enforce-dryrun)
//     independently refuses anything that ISN'T dryRun=All from this
//     identity, regardless of what this Go code does or gets wrong — the
//     same "the layer that holds even if everything on this side is
//     compromised" property templates/validatingadmissionpolicy.yaml's own
//     header comment claims for argus-remediate's field restriction.
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

// dryRunPatchAllowedResources is the exact resource set
// deploy/helm/argus-agent/templates/dryrun.yaml's argus-dryrun ClusterRole
// grants (lld/04-rbac-profiles.md §5), transcribed here so this tool fails
// with a clean, specific error BEFORE ever calling the API server for a
// resource the identity could never have been granted on — the same
// defence-in-depth reasoning revert_container_image's ReplicaSet check and
// patch_field's agent-side allowlist re-check already apply: a compromised
// or buggy caller (hub, model, or this code) is still bounded by an
// independent, reviewed enumeration on this side, not only by whatever RBAC
// happens to be deployed.
//
// Deliberately keyed on the bare resource plural, not a full GVK map:
// dry_run_patch only ever targets built-in core/apps kinds this agent's
// existing supportedGVKs already knows the GVR for, so reusing that lookup
// (rather than a second GVK table) is what keeps this list and
// supportedGVKs from being able to drift apart on the group/version part.
var dryRunPatchAllowedResources = map[string]bool{
	"deployments":            true,
	"statefulsets":           true,
	"configmaps":             true,
	"persistentvolumeclaims": true,
}

type dryRunPatchArgs struct {
	// GVK in this file's usual "[group/]version/Kind" convention, e.g.
	// "apps/v1/Deployment". Resolved against the SAME supportedGVKs map
	// every other tool uses, then narrowed further to
	// dryRunPatchAllowedResources — a gvk this agent cannot even
	// describe_resource is never worth asking the API server about either.
	GVK       string `json:"gvk"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	// Patch is a strategic-merge-patch body — the same patch type
	// applyPlanPatch already uses for every real remediation action, so an
	// operator reading a dry-run result and a real execution result is
	// reading the same shape. A bare JSON object, e.g.
	// {"spec":{"replicas":3}} or
	// {"spec":{"template":{"spec":{"containers":[{"name":"app","image":"..."}]}}}}.
	Patch json.RawMessage `json:"patch"`
}

// dryRunPatchResult is this tool's successful result — deliberately a
// smaller, standalone shape rather than a reuse of executeResult: that type
// carries plan-specific fields (an ActionType-keyed log line, a Rollback
// notion) this tool has no plan to speak of, and Dry is always true here, so
// echoing it back the way executeResult.DryRun does for a signed plan that
// COULD have been a real execution would be reporting a fact that was never
// in doubt.
type dryRunPatchResult struct {
	Accepted        bool   `json:"accepted"`
	ResourceVersion string `json:"resourceVersion,omitempty"`
	// Object is the API server's own resulting object — after defaulting,
	// mutating admission webhooks, and this identity's OWN
	// ValidatingAdmissionPolicy — capped the same way applyPlanPatch's own
	// dry-run diff already is (maxDryRunObjectBytes), for the same reason:
	// a single tool result is one message on the wire, and this is
	// evidence for the model to reason about, not a transcript it must
	// receive in full.
	Object json.RawMessage `json:"object,omitempty"`
}

// dryRunPatch is the tool entry point.
func (e *ToolExecutor) dryRunPatch(ctx context.Context, rawArgs json.RawMessage) (json.RawMessage, bool, error) {
	if e.dryRunDynamic == nil {
		return nil, false, errDryRunNotConfigured
	}

	var args dryRunPatchArgs
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return nil, false, fmt.Errorf("invalid args: %w", err)
	}
	if args.Namespace == "" || args.Name == "" {
		return nil, false, errors.New("namespace and name are required")
	}
	// Checked by decoding into a map, not merely json.Valid: an absent
	// Patch field marshals as the 4 literal bytes "null" on the wire
	// (json.RawMessage has no omitempty behaviour worth relying on for a
	// missing field vs. an explicit null), and "null" is both non-empty and
	// valid JSON — exactly the gap a bare length/validity check would miss.
	var patchObj map[string]any
	if err := json.Unmarshal(args.Patch, &patchObj); err != nil || len(patchObj) == 0 {
		return nil, false, errors.New("patch must be a non-empty JSON object (a strategic-merge patch body)")
	}

	gvk, err := parseGVKString(args.GVK)
	if err != nil {
		return nil, false, err
	}
	res, ok := supportedGVKs[gvk]
	if !ok {
		return nil, false, fmt.Errorf("unsupported gvk %q", args.GVK)
	}
	if !res.namespaced {
		// Every entry in dryRunPatchAllowedResources today is namespaced;
		// stated as a real check rather than assumed so a future addition
		// to that map cannot silently skip this.
		return nil, false, fmt.Errorf("dry_run_patch does not support cluster-scoped resource %q", res.gvr.Resource)
	}
	if !dryRunPatchAllowedResources[res.gvr.Resource] {
		return nil, false, fmt.Errorf("dry_run_patch does not support %q — the argus-dryrun pack grants only deployments, statefulsets, configmaps, and persistentvolumeclaims", res.gvr.Resource)
	}

	// PatchOptions.DryRun is the ONLY option ever set here, and it is set
	// unconditionally — nothing in dryRunPatchArgs can influence it, by
	// construction (there is no such field to decode into). The cluster's
	// own argus-dryrun-enforce-dryrun ValidatingAdmissionPolicy is the
	// control that holds even if this line is ever wrong; this is the first
	// of the two.
	patched, err := e.dryRunDynamic.Resource(res.gvr).Namespace(args.Namespace).Patch(
		ctx, args.Name, types.StrategicMergePatchType, args.Patch,
		metav1.PatchOptions{DryRun: []string{metav1.DryRunAll}},
	)
	if err != nil {
		if rejection, isAdmission := admissionRejection(err); isAdmission {
			// The cluster evaluated the hypothesis and said no — exactly as
			// informative to the model as an acceptance, and the whole
			// reason this tool exists rather than the model guessing. Passed
			// through verbatim (bounded, per admissionRejection's own
			// discipline) rather than generalised away.
			return nil, false, fmt.Errorf("the cluster would reject this change: %s", rejection)
		}
		return nil, false, sanitizeK8sErr(err)
	}

	result := dryRunPatchResult{Accepted: true, ResourceVersion: patched.GetResourceVersion()}
	if obj, marshalErr := boundedDryRunObject(patched); marshalErr == "" {
		result.Object = obj
	}
	// true (truncated) is deliberately NOT returned here: Object being
	// capped/omitted past maxDryRunObjectBytes is a size decision about the
	// EVIDENCE payload, not a statement that this result is an incomplete
	// view of a larger set the way list_resources' Truncated means — there
	// is exactly one object, seen in full by the API server, and Accepted
	// already reports the fact that matters.
	return mustMarshal(result), false, nil
}

// boundedDryRunObject mirrors planPatchResult's own size discipline for the
// dry-run diff object (maxDryRunObjectBytes, tools.go) — reused rather than
// re-derived so the two dry-run paths (this tool, and F12's gate) cannot
// silently diverge on how big a "reasonable" dry-run object is. Returns an
// empty errMsg on success; a non-empty one names why Object was omitted,
// logged by the caller-equivalent pattern the sibling function already
// established (degrading the diff, never the Accepted fact).
func boundedDryRunObject(obj *unstructured.Unstructured) (json.RawMessage, string) {
	b, err := obj.MarshalJSON()
	if err != nil {
		return nil, err.Error()
	}
	if len(b) > maxDryRunObjectBytes {
		return nil, fmt.Sprintf("resulting object is %d bytes, past the %d cap", len(b), maxDryRunObjectBytes)
	}
	return b, ""
}
