package execution

// This file implements the hub-side half of BACKLOG.md F14 — per-execution
// admission-policy scoping. See internal/remediation/executionwindow.go's own
// header for the field-path tables this builds on, and
// deploy/helm/argus-agent/templates/validatingadmissionpolicy.yaml's
// argus.io/v1 ExecutionWindow paramKind for the CEL that consults what this
// file opens.
//
// # The problem this closes
//
// deploy/helm/argus-agent/templates/validatingadmissionpolicy.yaml's standing
// policies enumerate exactly four field groups argus-remediate may ever
// change, and that allowlist is the layer that holds even if the hub itself
// is fully compromised. F11 needs that allowlist to widen — a plan can name a
// field (patchfield.go's own reviewed table) the standing policy has never
// heard of — and BACKLOG.md's own record of the 2026-08-22 decision is
// explicit that the answer is NOT to widen the standing policy permanently
// (that is a real, permanent reduction of the compromised-hub bound), but to
// open the exact field, on the exact object, for a short window immediately
// around the one approved execution that needs it, then close it again.
//
// # Who actually does the widening
//
// Neither argus-investigate (read-only by design) nor argus-remediate (whose
// own RBAC is the field-write grant this mechanism scopes, and which has no
// grant to touch ValidatingAdmissionPolicy/ValidatingAdmissionPolicyBinding
// objects at all) can be the identity that unlocks this. A brand new,
// narrowly-scoped agent identity — argus-policy-controller
// (deploy/helm/argus-agent/templates/policycontroller.yaml) — holds RBAC on
// exactly one thing: get/list/watch/create/update/patch/delete on
// argus.io/v1 ExecutionWindow objects, a cluster-scoped CRD instance this
// package's openExecutionWindow/closeExecutionWindow calls create and mutate
// over the tunnel, using the exact same ToolRequest/ToolResult channel and
// dispatch mechanism as every other tool (see
// deploy/helm/argus-agent/templates/dryrun.yaml's own precedent for "a
// second admission-scoped identity mounted into the same agent Pod as a
// second Secret volume" — this reuses that shape rather than inventing a
// new one). Never RBAC on the workloads themselves: a compromised
// argus-policy-controller identity, on its own, can create or edit
// ExecutionWindow objects but cannot patch a single Deployment field with
// that alone — it can only widen what argus-remediate's OWN, separately
// authorized write may subsequently do, and only for the fixed, reviewed set
// of fields validatingadmissionpolicy.yaml's CEL actually recognises
// (internal/remediation.FieldPathIsWindowable).
//
// # Crash safety — the property this feature is least allowed to get wrong
//
// A window must not survive its execution. Two independent layers enforce
// that, deliberately not just one:
//
//  1. planNeedsExecutionWindow/openExecutionWindow/closeExecutionWindow are
//     wired into ExecuteApprovedPlan (this package) so that the close
//     call is registered via `defer` immediately after the open call
//     SUCCEEDS, before preparePlanWithCorrection (which performs the dry-run
//     attestation the window exists to permit) or the real tunnel patch call
//     ever run. That defer fires on every return path out of
//     ExecuteApprovedPlan from that point on — a PreparePlan failure, a
//     rejected dry-run, a tunnel error on the real patch, or the ordinary
//     success path all close the window before the HTTP handler returns.
//     TestExecuteApprovedPlanAlwaysClosesTheExecutionWindow exercises this
//     directly, forcing failures at each stage.
//  2. That guarantee is only as good as the hub process being alive to run
//     the deferred call. A hub crash or a dropped tunnel between open and
//     close leaves the window's `defer` never firing at all — nothing at the
//     orchestration layer can close what it isn't running to close. The
//     independent backstop is agent-side and does not depend on the hub in
//     any way: the agent's own background sweep (internal/agent's
//     policyWindowTTL) re-reads the ExecutionWindow object on its own timer,
//     using its own clock and its own credential, and removes any entry
//     older than the TTL regardless of whether the hub that opened it is
//     still there to ask. See internal/agent/policywindow.go's header for the
//     TTL bound and why it is generous relative to this feature's own
//     signedPlanTTL-bounded happy path.
//
// # Composition with G6 (per-target lock) and R3 (batch execution)
//
// ExecuteApprovedPlan already takes G6's per-target pg_advisory_xact_lock,
// keyed on (clusterID, gvk, namespace, name), before this file's window is
// ever opened — see concurrency.go's own header for why that
// lock is held on scope.Tx for this whole request. Two DIFFERENT targets on the
// SAME cluster take DIFFERENT advisory locks (hashtext of different key
// strings) and so proceed concurrently, including opening/closing their own
// windows concurrently — this file adds no cluster-wide serialization of its
// own. The ExecutionWindow object itself is a single shared per-cluster
// object, so two concurrent opens for different targets DO race on updating
// it; the agent's own handler (internal/agent/policywindow.go) resolves that
// with an ordinary get-modify-update retry-on-conflict loop, entirely inside
// the agent process — it never blocks or serializes the HUB's two concurrent
// requests against each other, only retries its own small K8s API call a
// bounded number of times. R3's batching (internal/orchestrator/batch.go)
// operates a layer above this entirely (which incidents are even allowed to
// reach execution this tick) and neither knows nor needs to know this
// mechanism exists.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"argus/internal/logging"
	"argus/internal/remediation"
)

// executionWindowEntry is the wire shape this file sends to the agent's
// open_execution_window tool, and the shape the agent stores (one per list
// element) on the argus.io/v1 ExecutionWindow singleton's spec.windows.
// Field names and JSON tags here MUST match
// internal/agent/policywindow.go's decoding exactly, and MUST match the
// property names the ExecutionWindow CRD's OpenAPI schema
// (deploy/helm/argus-agent/templates/executionwindow-crd.yaml) declares,
// since those are what validatingadmissionpolicy.yaml's CEL indexes by name
// off `params.spec.windows[*]`.
type executionWindowEntry struct {
	PlanID          string `json:"planId"`
	TargetAPIGroup  string `json:"targetApiGroup"`
	TargetKind      string `json:"targetKind"`
	TargetNamespace string `json:"targetNamespace,omitempty"`
	TargetName      string `json:"targetName"`
	TargetUID       string `json:"targetUid"`
	FieldPath       string `json:"fieldPath"`
}

// gvkGroup extracts the API group from this codebase's "<group>/<version>/<Kind>"
// (or, for core/v1, "<version>/<Kind>") GVK wire convention. Only used for
// this file's own observability payload (TargetAPIGroup) — the CEL widening
// clauses match on targetUID+fieldPath alone, never on the group, because
// matchConstraints.resourceRules on each policy already fixes which
// group/resource it evaluates against.
func gvkGroup(gvk string) string {
	parts := strings.Split(gvk, "/")
	if len(parts) == 3 {
		return parts[0]
	}
	return "" // core group, or a malformed gvk — never load-bearing either way
}

// planWindowRequirements resolves which (if any) per-execution windows plan
// needs before it can execute against the live object at gvk/namespace/name,
// given that object's own live spec-derived UID.
//
// Returns (nil, nil) — no error, no entries — for the ordinary case: every
// field this plan writes is already covered by the standing policy
// unconditionally (true for every ScaleDeployment/RestartPod/
// PatchResourceLimits/RevertContainerImage plan, by construction of their
// own fixed field paths, and true for a PatchField/StructuredPatch plan that
// happens to target one of the four already-open field groups). Callers must
// not pay for a window, or the extra live-object read below, on that
// (overwhelmingly common) path — see ExecuteApprovedPlan's own call site.
//
// Returns an error, still entirely read-only and safe to retry, when a needed
// path is not one validatingadmissionpolicy.yaml has actually been taught to
// widen (internal/remediation.FieldPathIsWindowable) — a clear "not supported
// yet" refusal before any tunnel round trip, rather than a window that would
// open and then not help.
func (s *Executor) planWindowRequirements(ctx context.Context, clusterID, planID string, plan remediation.RemediationPlan, gvk, namespace, name string) ([]executionWindowEntry, error) {
	paths, err := remediation.PlannedFieldPaths(plan)
	if err != nil {
		return nil, fmt.Errorf("determine planned field paths: %w", err)
	}
	kind := remediation.GVKKind(gvk)
	needed := remediation.FieldPathsNeedingExecutionWindow(kind, paths)
	if len(needed) == 0 {
		return nil, nil
	}
	for _, p := range needed {
		if !remediation.FieldPathIsWindowable(kind, p) {
			return nil, fmt.Errorf("this plan writes %q on a %s, which the standing admission policy does not permit and no per-execution widening clause exists for yet — this field cannot be executed until deploy/helm/argus-agent/templates/validatingadmissionpolicy.yaml is extended to cover it", p, kind)
		}
	}

	// Only reached on the rare path (today: a PatchField/StructuredPatch plan
	// against spec.progressDeadlineSeconds or spec.revisionHistoryLimit) —
	// the extra live-object read is deliberately paid for here rather than
	// threaded through from PreparePlan's own later fetch, mirroring
	// executionTargetForLock's own "redundant, cheap, and deliberately not
	// shared" reasoning in concurrency.go: this function needs
	// the object's UID before preparePlanWithCorrection ever runs (the
	// window must be open before ITS internal dry-run attestation, not just
	// before the final real patch), so it cannot wait for PreparePlan's own
	// read.
	_, _, live, err := s.FetchPreconditionWithObject(ctx, clusterID, gvk, namespace, name)
	if err != nil {
		return nil, fmt.Errorf("fetch live object to resolve its UID for the execution window: %w", err)
	}
	var obj struct {
		Metadata struct {
			UID string `json:"uid"`
		} `json:"metadata"`
	}
	if err := json.Unmarshal(live, &obj); err != nil {
		return nil, fmt.Errorf("decode live object to resolve its UID for the execution window: %w", err)
	}
	if obj.Metadata.UID == "" {
		return nil, fmt.Errorf("live object %s %s/%s has no readable metadata.uid — refusing to open an execution window that could not be scoped to a specific object", gvk, namespace, name)
	}

	group := gvkGroup(gvk)
	entries := make([]executionWindowEntry, 0, len(needed))
	for _, p := range needed {
		entries = append(entries, executionWindowEntry{
			PlanID:          planID,
			TargetAPIGroup:  group,
			TargetKind:      kind,
			TargetNamespace: namespace,
			TargetName:      name,
			TargetUID:       obj.Metadata.UID,
			FieldPath:       remediation.NormaliseFieldPath(p),
		})
	}
	return entries, nil
}

// openExecutionWindow asks clusterID's argus-policy-controller identity
// (over the same tunnel every other tool uses) to add entries to the live
// argus.io/v1 ExecutionWindow singleton. Not advertised to the model's tool
// loop anywhere — like scale_deployment and its siblings, this is dispatched
// directly by hub Go code (ExecuteApprovedPlan below), never something a
// model's tool call could reach; internal/agent's executeTool switch is the
// server-side allowlist that makes that true regardless of what any caller
// claims (argus-context non-negotiable 3).
func (s *Executor) openExecutionWindow(ctx context.Context, clusterID string, entries []executionWindowEntry) error {
	if len(entries) == 0 {
		return nil
	}
	argsJSON, err := json.Marshal(map[string]any{"windows": entries})
	if err != nil {
		return fmt.Errorf("build open_execution_window args: %w", err)
	}
	if _, err := s.gw.CallTool(ctx, clusterID, "open_execution_window", argsJSON); err != nil {
		return fmt.Errorf("open per-execution admission-policy window: %w", err)
	}
	return nil
}

// closeExecutionWindow asks clusterID's argus-policy-controller identity to
// remove every window entry tagged with planID. Idempotent and safe to call
// even when no window was ever opened for this plan (the agent reports zero
// closed, not an error) — callers rely on that so the unconditional `defer`
// in ExecuteApprovedPlan below never needs to remember whether opening
// actually happened.
func (s *Executor) closeExecutionWindow(ctx context.Context, clusterID, planID string) error {
	argsJSON, err := json.Marshal(map[string]any{"planId": planID})
	if err != nil {
		return fmt.Errorf("build close_execution_window args: %w", err)
	}
	if _, err := s.gw.CallTool(ctx, clusterID, "close_execution_window", argsJSON); err != nil {
		return fmt.Errorf("close per-execution admission-policy window: %w", err)
	}
	return nil
}

// withExecutionWindow resolves whether plan needs a per-execution widening
// window against the live object at gvk/namespace/name, opens it if so, and
// returns a closer that MUST be called (via `defer`, unconditionally) by the
// caller — see this file's header for why the guarantee lives at this layer
// as a `defer` and what backstops it when the process holding that defer
// never gets to run it.
//
// The returned closer is always non-nil and always safe to call exactly
// once, whether or not a window was actually opened (closeExecutionWindow's
// own idempotence covers the "never opened" case) — callers never need an
// `if opened` branch of their own.
func (s *Executor) withExecutionWindow(ctx context.Context, clusterID, planID string, plan remediation.RemediationPlan, gvk, namespace, name string) (closer func(), err error) {
	entries, err := s.planWindowRequirements(ctx, clusterID, planID, plan, gvk, namespace, name)
	if err != nil {
		return func() {}, err
	}
	return openExecutionWindowCore(
		entries,
		func() error { return s.openExecutionWindow(ctx, clusterID, entries) },
		func() {
			// Deliberately a background context, not ctx: this always runs
			// from a `defer`, which in ExecuteApprovedPlan fires on every
			// return path including a caller-cancelled request — the window
			// must still be asked to close even then, or a client disconnect
			// would leave it open for the full agent-side TTL instead of
			// closing immediately.
			if err := s.closeExecutionWindow(context.Background(), clusterID, planID); err != nil {
				logger.WarnContext(ctx, "closing the execution window failed; the agent's own independent TTL sweep will remove it regardless, within its own bound",
					logging.ClusterID(clusterID), slog.String("plan_id", planID), logging.Err(err))
			}
		},
	)
}

// openExecutionWindowCore is withExecutionWindow's mechanism, pulled out as
// a pure function of (entries, open, close) so
// TestOpenExecutionWindowCoreAlwaysReturnsAWorkingCloser can exercise the
// exact crash-safety-relevant contract — a closer that is always non-nil,
// safe to call multiple times, and calls the underlying close function
// exactly once — without a live cluster or database. Everything network- or
// database-shaped (resolving entries, actually calling the tunnel) stays in
// the two closures the caller supplies.
//
// Contract, matching ExecuteApprovedPlan's own reliance on it exactly:
//   - zero entries: no-op closer, open is never called at all (the ordinary
//     case for every ScaleDeployment/RestartPod/PatchResourceLimits/
//     RevertContainerImage plan).
//   - open fails: a no-op closer and the error — nothing was opened, so
//     there is nothing to close, and the caller (still pre-commit at this
//     point in ExecuteApprovedPlan) turns this into a plain HTTP error.
//   - open succeeds: a REAL closer that calls close(), and only ever calls
//     it once even if invoked more than once (ExecuteApprovedPlan's own
//     `defer` calls it exactly once, but a closer safe against a second call
//     is what makes it safe to also call defensively from any future second
//     caller without auditing this one first).
func openExecutionWindowCore(entries []executionWindowEntry, open func() error, closeFn func()) (closer func(), err error) {
	noop := func() {}
	if len(entries) == 0 {
		return noop, nil
	}
	if err := open(); err != nil {
		return noop, err
	}
	closed := false
	return func() {
		if closed {
			return
		}
		closed = true
		closeFn()
	}, nil
}
