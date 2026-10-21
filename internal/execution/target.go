package execution

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"argus/internal/remediation"
)

// signedPlanTTL bounds how long a signed plan stays valid — generous
// relative to how long this whole synchronous approve-and-execute flow
// actually takes (well under a second in the ordinary case), but short
// enough that a signed envelope logged or cached anywhere is useless again
// quickly. This entire flow runs inside one HTTP request; there is no
// legitimate reason for a signature to still be fresh minutes later.
const signedPlanTTL = 2 * time.Minute

// restartablePodTemplateKinds mirrors internal/agent/tools.go's own
// constant of the same name — the Kinds that HAVE a pod template at all
// (/spec/template, which a strategic-merge patch can add an annotation or a
// container's resources under; a bare Pod does not). Named for RestartPod
// because that was its first caller; resolvePodTemplateTarget below now uses
// it for PatchResourceLimits too, which needs the same "walk up to the object
// that owns the template" resolution. Note that the two actions then diverge:
// this set is where the owner walk STOPS, while what may actually be patched
// once resolved is narrower for resources (patchResourceLimitsKinds, no
// DaemonSet). Kept as its own small copy here
// rather than an import: internal/api has no other reason to depend on
// internal/agent (a hub-side package pulling in agent-side k8s client
// dependencies for one map would be the wrong direction), and this table
// is small and unlikely to change silently out of step — see
// TestRestartablePodTemplateKindsMatchesAgent for the guard that keeps it
// that way.
var restartablePodTemplateKinds = map[string]bool{
	"Deployment":  true,
	"StatefulSet": true,
	"DaemonSet":   true,
}

// gvkKind extracts the Kind from this codebase's "<apiVersion>/<Kind>" gvk
// wire convention (internal/agent/tools.go's parseGVKString, duplicated
// here only to the extent of "the part after the last slash" — this file
// never needs the full schema.GroupVersionKind, only the Kind).
func gvkKind(gvk string) string {
	idx := strings.LastIndex(gvk, "/")
	if idx < 0 {
		return gvk
	}
	return gvk[idx+1:]
}

// resolvePodTemplateTarget returns the real object a plan whose action acts
// on a pod template should patch: the plan's own target unchanged if it
// already names a workload Kind (a plan authored directly against a
// Deployment/StatefulSet/DaemonSet), or — the common case, since such a plan
// is usually proposed against the specific Pod that's crashing — the nearest
// resolved ancestor of one of those Kinds, walked via the existing read-only
// get_owner_chain tool. Returns a clear error if no such ancestor is found,
// rather than guessing or falling back to patching the Pod itself.
//
// Named for the property it needs (a pod template to patch) rather than for
// one caller, since it now has three: RestartPod, PatchResourceLimits, and
// RevertContainerImage.
// All are proposed against whatever object the finding named — for an
// OOMKilled or CrashLooping container that is nearly always the Pod — and all
// can only be
// applied to the workload that owns it, or the controller would immediately
// recreate the pod from the unchanged template. Reusing this walk rather
// than writing a second one is the point: the three actions must agree about
// what "the real target" is, and a divergence between them would be a plan
// signed against one object and validated against another.
func (s *Executor) resolvePodTemplateTarget(ctx context.Context, clusterID, targetGVK, targetNamespace, targetName string) (gvk, namespace, name string, err error) {
	if restartablePodTemplateKinds[gvkKind(targetGVK)] {
		return targetGVK, targetNamespace, targetName, nil
	}

	argsJSON, err := json.Marshal(map[string]any{
		"gvk": targetGVK, "namespace": targetNamespace, "name": targetName, "direction": "up",
	})
	if err != nil {
		return "", "", "", fmt.Errorf("build get_owner_chain args: %w", err)
	}
	raw, err := s.gw.CallTool(ctx, clusterID, "get_owner_chain", argsJSON)
	if err != nil {
		return "", "", "", fmt.Errorf("walk owner chain for %s %s/%s: %w", targetGVK, targetNamespace, targetName, err)
	}
	var nodes []struct {
		GVK       string `json:"gvk"`
		Namespace string `json:"namespace,omitempty"`
		Name      string `json:"name"`
		Resolved  bool   `json:"resolved"`
	}
	if err := json.Unmarshal(raw, &nodes); err != nil {
		return "", "", "", fmt.Errorf("decode owner chain: %w", err)
	}
	for _, n := range nodes {
		if n.Resolved && restartablePodTemplateKinds[gvkKind(n.GVK)] {
			return n.GVK, n.Namespace, n.Name, nil
		}
	}
	return "", "", "", fmt.Errorf("no owning Deployment/StatefulSet/DaemonSet found for %s %s/%s — an unmanaged pod has no pod template to patch, so neither a rollout restart nor a resource change can be applied to it", targetGVK, targetNamespace, targetName)
}

// fetchPrecondition fetches the live object via the existing read-only
// describe_resource tool and returns its current resourceVersion (the
// precondition embedded in the signed plan, per lld/08 §5) and its spec, as
// a plain map for the sanity-bound check below — never the value from
// whenever the plan was originally proposed, which may since be stale.
func (s *Executor) fetchPrecondition(ctx context.Context, clusterID, gvk, namespace, name string) (resourceVersion string, spec map[string]any, err error) {
	resourceVersion, spec, _, err = s.FetchPreconditionWithObject(ctx, clusterID, gvk, namespace, name)
	return resourceVersion, spec, err
}

// FetchPreconditionWithObject is fetchPrecondition, additionally returning the
// whole live object it already read.
//
// The extra return value is free: describe_resource returns the complete object
// and fetchPrecondition was decoding two fields out of it and discarding the
// rest. Keeping it is what lets BACKLOG.md F13 compute its diff with **no
// additional cluster round-trip at all** — the "before" is this object, and the
// "after" is what the dry-run gate already brings back. Split into two
// functions rather than widening every caller, because exactly one caller wants
// the object and five want the two fields.
func (s *Executor) FetchPreconditionWithObject(ctx context.Context, clusterID, gvk, namespace, name string) (resourceVersion string, spec map[string]any, live json.RawMessage, err error) {
	argsJSON, err := json.Marshal(map[string]any{"gvk": gvk, "namespace": namespace, "name": name})
	if err != nil {
		return "", nil, nil, fmt.Errorf("build describe_resource args: %w", err)
	}
	raw, err := s.gw.CallTool(ctx, clusterID, "describe_resource", argsJSON)
	if err != nil {
		return "", nil, nil, fmt.Errorf("describe %s %s/%s: %w", gvk, namespace, name, err)
	}
	var result struct {
		Object json.RawMessage `json:"object"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return "", nil, nil, fmt.Errorf("decode describe_resource result: %w", err)
	}
	var obj struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Spec map[string]any `json:"spec"`
	}
	if err := json.Unmarshal(result.Object, &obj); err != nil {
		return "", nil, nil, fmt.Errorf("decode object: %w", err)
	}
	if obj.Metadata.ResourceVersion == "" {
		return "", nil, nil, fmt.Errorf("%s %s/%s has no resourceVersion", gvk, namespace, name)
	}
	return obj.Metadata.ResourceVersion, obj.Spec, result.Object, nil
}

// confirmTargetAbsentForCreate is CreateResource's own precondition: not "the
// live resourceVersion matches", because there is no live object, but "no
// live object exists at all." Calls the same read-only describe_resource tool
// every other precondition fetch uses, and interprets its outcome three ways:
//
//  1. describe_resource SUCCEEDS -> the object already exists. Refused
//     outright: creating a new object at a name that is already taken is a
//     replace, and this codebase deliberately does not build replaceResource
//     (see internal/remediation/plan.go's ActionCreateResource comment) —
//     silently treating "already exists" as "proceed anyway" would build
//     exactly that, unreviewed, as a side effect of this function.
//  2. describe_resource FAILS with the agent's own "resource not found" text
//     (sanitizeK8sErr's fixed string for apierrors.IsNotFound,
//     remediation.ErrResourceNotFoundMessage) -> confirmed absent, the happy
//     path this action exists for.
//  3. describe_resource FAILS for any OTHER reason (RBAC denied, a
//     disconnected agent, a timeout) -> ambiguous. This function fails
//     CLOSED here: it cannot rule out that the object exists, so it refuses
//     to create blind rather than treating "I don't know" as "probably
//     absent."
//
// The known, stated brittleness in case 2: this recognises absence by
// matching TEXT that crossed the tunnel as a plain error string, not a typed
// error code — the tunnel protocol carries no such thing today. If
// sanitizeK8sErr's wording (internal/agent/tools.go) ever changes without
// remediation.ErrResourceNotFoundMessage changing to match, this function
// stops recognising a genuine "not found" and falls into case 3 — refusing to
// create rather than proceeding, which is the safe direction for this
// particular brittleness to fail in. TestConfirmTargetAbsentForCreate exists
// to catch that drift immediately rather than silently.
func (s *Executor) confirmTargetAbsentForCreate(ctx context.Context, clusterID, gvk, namespace, name string) error {
	argsJSON, err := json.Marshal(map[string]any{"gvk": gvk, "namespace": namespace, "name": name})
	if err != nil {
		return fmt.Errorf("build describe_resource args: %w", err)
	}
	_, callErr := s.gw.CallTool(ctx, clusterID, "describe_resource", argsJSON)
	return interpretAbsenceCheckResult(gvk, namespace, name, callErr)
}

// interpretAbsenceCheckResult is confirmTargetAbsentForCreate's decision
// logic, split out as a pure function purely so it is directly testable
// without a live gateway/cluster — the same testability reason
// interpretDryRunResult is split from attestByDryRun (that function's own
// doc comment gives the identical argument: a control this important should
// not be reachable only through a live tunnel). See
// confirmTargetAbsentForCreate's own doc comment for the three cases this
// interprets and the stated brittleness of case two.
func interpretAbsenceCheckResult(gvk, namespace, name string, callErr error) error {
	if callErr == nil {
		return fmt.Errorf("%s %s/%s already exists — CreateResource refuses to target an existing object rather than silently becoming a replace (a mechanism this codebase deliberately does not build; see internal/remediation/plan.go's ActionCreateResource comment). If this object needs to change, use an in-place patch action against it instead of CreateResource", gvk, namespace, name)
	}
	if strings.Contains(callErr.Error(), remediation.ErrResourceNotFoundMessage) {
		return nil
	}
	return fmt.Errorf("could not confirm %s %s/%s does not already exist before creating it (%v) — refusing to create blind", gvk, namespace, name, callErr)
}
