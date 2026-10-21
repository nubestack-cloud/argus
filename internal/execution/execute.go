package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/jackc/pgx/v5"

	"argus/internal/domain"
	"argus/internal/events"
	"argus/internal/gateway"
	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
)

// ToolForAction maps an action type to the agent tool name that
// executes it — five entries now that PatchField (BUGS.md 78) is wired
// end to end alongside the original four; still no OpenPR execution, which
// takes the pull-request path in handleApproveIncident instead of this one.
func ToolForAction(actionType remediation.ActionType) (tool string, ok bool) {
	switch actionType {
	case remediation.ActionScaleDeployment:
		return "scale_deployment", true
	case remediation.ActionRestartPod:
		return "restart_pod", true
	case remediation.ActionPatchResourceLimits:
		return "patch_resource_limits", true
	case remediation.ActionRevertContainerImage:
		return "revert_container_image", true
	case remediation.ActionPatchField:
		return "patch_field", true
	case remediation.ActionStructuredPatch:
		// "patch_structured" names no tool the agent actually implements —
		// see ActionStructuredPatch's own doc comment
		// (internal/remediation/plan.go) for why that is deliberate. This
		// entry exists so PreparePlan's dry-run/diff/rollback pipeline is
		// genuinely exercisable (attestByDryRun needs a tool name to put in
		// the signed envelope, even one that will not resolve against any
		// real agent) and so this action type has an entry at all —
		// TestPlanApprovalGatesCoverEveryActionType and
		// TestPlannedFieldPathsCoversEveryExecutableAction both key off
		// exactly this table.
		return "patch_structured", true
	case remediation.ActionAnnotateResource:
		return "annotate_resource", true
	case remediation.ActionLabelResource:
		return "label_resource", true
	case remediation.ActionDeleteResource:
		return "delete_resource", true
	case remediation.ActionCordonNode:
		return "cordon_node", true
	case remediation.ActionDrainNode:
		return "drain_node", true
	case remediation.ActionCreateResource:
		return "create_resource", true
	default:
		return "", false
	}
}

// ExecuteApprovedPlan runs the full resolve -> precondition -> sign ->
// Executing -> call -> record-outcome flow for a ScaleDeployment/RestartPod/
// PatchResourceLimits/RevertContainerImage plan already known to be
// well-formed and approvable.
// incidentState/
// alreadyApproved/latestRecommendationForIncident have already been
// checked by the caller (handleApproveIncident) using its own scope.Tx before
// this is ever called — this function does its own, separate, row-locked
// re-check immediately before committing to Executing (see
// recordExecutingTransition), since real time (potentially real cluster
// round trips) elapses between that first check and this one.
//
// The returned error is meaningful ONLY for everything before the
// Executing commit (resolving the target, fetching the precondition,
// signing) — nothing has been recorded or changed yet at that point, so the
// caller (handleApproveIncident) turns it into a real HTTP error response,
// exactly like any other request that failed to do anything. Once
// recordExecutingTransition succeeds, this function is committed: every
// path after that point returns (response, nil) — a tunnel-call failure
// from here on is an honest "approved, but execution failed" outcome
// (Verdict "approved", IncidentState Failed), never an HTTP error, because
// something real and durable did happen.
//
// confirmScaleFromZero carries the approver's explicit intent for the one
// guardrail that needs it (checkScaleFromZero). It is a plain parameter
// threaded from the request body rather than anything derived, cached or
// defaulted, because the entire value of the guardrail is that its default is
// refusal: any path that reaches here without an operator having said the
// word must get the refusal, including a replayed approve call or a queue
// click that never touched the confirmation.
func (s *Executor) ExecuteApprovedPlan(
	ctx context.Context, scope Scope,
	incidentID, planID, clusterID string,
	plan remediation.RemediationPlan,
	overrides Overrides,
	actor Actor,
) (Result, error) {
	// BACKLOG.md G6: the per-target lock — held on scope.Tx for the rest of
	// this request (see concurrency.go's header comment for why
	// that is the right transaction to hold it on), so a second, different
	// plan against the SAME live object cannot also start executing while
	// this one is being dry-run or applied. Taken before PreparePlan does
	// anything at all, including its own read-only target resolution.
	if err := s.acquireTargetLock(ctx, scope.Tx, clusterID, plan); err != nil {
		return Result{}, err
	}

	// BACKLOG.md F14: open, if needed, the per-execution admission-policy
	// widening window for whatever field(s) this plan writes that the
	// standing ValidatingAdmissionPolicy does not unconditionally permit —
	// see internal/execution/window.go's header for the full mechanism.
	// Resolved from the plan's own target the same way the per-target lock
	// just above just did (executionTargetForLock): redundant, cheap, and
	// deliberately not threaded through from acquireTargetLock, matching
	// that function's own reasoning for why a second resolution here is
	// fine. Every ScaleDeployment/RestartPod/PatchResourceLimits/
	// RevertContainerImage plan resolves zero entries here (their field
	// paths are always within the standing allowlist by construction) and
	// pays for nothing beyond this one cheap call.
	//
	// The returned closer is deferred UNCONDITIONALLY, before
	// preparePlanWithCorrection (whose own dry-run attestation is exactly
	// what a widened field needs the window open FOR) ever runs — so a
	// failure at any later stage of this function still closes the window
	// before returning. See window.go's header for what backstops
	// this guarantee if the process itself does not survive to run it.
	lockGVK, lockNamespace, lockName, err := s.executionTargetForLock(ctx, clusterID, plan)
	if err != nil {
		return Result{}, fmt.Errorf("resolve execution target for the admission-policy window: %w", err)
	}
	closeWindow, err := s.withExecutionWindow(ctx, clusterID, planID, plan, lockGVK, lockNamespace, lockName)
	if err != nil {
		return Result{}, err
	}
	defer closeWindow()

	// preparePlanWithCorrection (correction.go, BACKLOG.md F12b) is
	// PreparePlan plus the bounded dry-run correction retry loop: on a
	// rejection specifically about this plan's params, it asks the model for
	// a correction, re-validates it exactly like a fresh proposal, and runs
	// the corrected plan back through PreparePlan's full pipeline before ever
	// dry-run-attempting it again. Every other PreparePlan failure (target
	// resolution, a guardrail, a stale risk floor) passes through unchanged.
	prep, corrections, err := s.preparePlanWithCorrection(ctx, scope, incidentID, planID, clusterID, plan, overrides)
	if err != nil {
		return Result{}, err
	}
	tool, signed, resourceVersion := prep.Tool, prep.Signed, prep.ResourceVersion
	rollback, attestation, digestWarning := prep.Rollback, prep.Attestation, prep.DigestWarning
	confirmedScaleFromZero, confirmedGitOpsManaged := prep.ConfirmedScaleFromZero, prep.ConfirmedGitOpsManaged

	// This is the irreversible commit point: AwaitingApproval -> Executing,
	// its own transaction, before the tunnel call — see this file's own
	// header comment. A failure here (lost the double-approve race, or the
	// incident moved on for some other reason) means nothing was executed
	// and nothing new was recorded, so this is still a plain error response.
	// The rollback rides along so that it is committed in the SAME
	// transaction as "we are doing this", and therefore strictly before the
	// mutation — the whole point of a pre-computed compensating action is
	// that it survives the hub crashing mid-execution. There is no
	// remediation_executions column for it (this feature adds no migration),
	// so its durable home is this transaction's audit event, which is
	// append-only and already the record of what was authorized.
	//
	// One honest limit of that home, worth knowing before anyone relies on
	// it: audit_events.details is deliberately excluded from the audit chain's
	// hash input (internal/audit's Event doc comment, lld/05-data-model.md
	// §7), so the rollback is durable and attributable but NOT tamper-evident
	// the way the hashed columns are. The tamper-evident copy is the one
	// inside the signed plan envelope the agent verified. A future undo path
	// that wants both properties should re-sign what it reads back rather than
	// trusting the details blob on its own.
	//
	// The rollback now ALSO rides along in a queryable column, on the attempt
	// row below, for the reason migration 000050 already gave about
	// audit_events.details being the wrong place to read an undo back from.
	//
	// dispatchCtx bounds everything from here to the outcome write. It is what
	// the attempt row's expires_at is derived from, and therefore what decides
	// how long a crashed hub leaves this incident unresolved — see
	// executionDispatchLimit. Derived from ctx, so a caller that has already
	// bounded the whole execution (handleApproveIncident's detached workCtx)
	// still caps this.
	dispatchCtx, cancelDispatch := context.WithTimeout(ctx, executionDispatchLimit)
	defer cancelDispatch()

	attempt := executionAttempt{
		ID: domain.NewID(domain.PrefixExecutionAttempt), TenantID: scope.TenantID, ClusterID: clusterID,
		IncidentID: incidentID, PlanID: planID,
		Kind: executionAttemptForward, ActionType: string(plan.ActionType),
		TargetGVK: prep.TargetGVK, TargetNamespace: prep.TargetNamespace, TargetName: prep.TargetName,
		ForwardApplied: prep.ForwardApplied, ResourceVersion: resourceVersion, Rollback: rollback,
		Actor: actor, SuccessState: orchestrator.StateValidating, ExpiresAt: attemptExpiry(dispatchCtx),
	}
	if err := s.recordExecutingTransition(dispatchCtx, scope, incidentID, planID, clusterID, actor, confirmedScaleFromZero, confirmedGitOpsManaged, digestWarning, rollback, attestation, corrections, attempt); err != nil {
		return Result{}, fmt.Errorf("commit to Executing: %w", err)
	}

	if s.events != nil {
		s.events.Publish(events.IncidentUpdated(incidentID, clusterID))
	}

	// From here on, every path returns (response, nil): the approval and
	// the Executing transition are already durably committed above.
	argsJSON, err := json.Marshal(map[string]any{"plan": signed})
	var outcome, execError string
	if err != nil {
		outcome, execError = "failed", fmt.Sprintf("build tool args: %v", err)
	} else if _, callErr := s.gw.CallToolWithGrace(dispatchCtx, clusterID, tool, argsJSON); callErr != nil {
		if errors.Is(callErr, gateway.ErrIndeterminate) {
			// BACKLOG.md C8 / BUGS.md 104: this call's own error is the
			// disconnect/timeout shape, not an explicit ToolResult.Error —
			// the mutation may have reached the agent and been fully
			// applied, only the ACK back was lost. Never conclude "failed"
			// from this shape alone; verify against the live cluster first.
			outcome, execError = s.resolveIndeterminateOutcome(dispatchCtx, clusterID, plan, prep, callErr)
		} else {
			outcome, execError = "failed", callErr.Error()
		}
	} else {
		outcome = "succeeded"
	}

	finalState, err := s.recordExecutionOutcome(dispatchCtx, scope, incidentID, planID, clusterID, actor, outcome, execError, resourceVersion,
		rollback, prep.ForwardApplied, forwardOutcomeStates(), attempt.ID, string(plan.ActionType), "forward")
	if err != nil {
		// The cluster mutation (if outcome == succeeded) already happened
		// or didn't; only the bookkeeping write failed. Logged loudly —
		// this is exactly the kind of drift-between-reality-and-database
		// this table exists to prevent — but the caller still needs an
		// honest answer about what was attempted.
		//
		// The incident is NOT abandoned here any more: the attempt row
		// committed above is still open, so RunExecutionReconciler picks this
		// up once its expiry passes and settles it against the live cluster.
		// Reporting Executing is therefore honest rather than terminal — it is
		// what the incident is, and something is now going to finish the job.
		logger.ErrorContext(ctx, "recording the execution outcome failed; the attempt stays open for the execution reconciler to settle",
			logging.IncidentID(incidentID), logging.ClusterID(clusterID),
			slog.String("attempt_id", attempt.ID), logging.Err(err))
		finalState = orchestrator.StateExecuting
	}

	if s.events != nil {
		s.events.Publish(events.IncidentUpdated(incidentID, clusterID))
	}

	if outcome == "succeeded" {
		message := "Approved and executed. The cluster accepted the change; this incident is now Validating — it auto-resolves if the symptom doesn't recur, or reopens if it does."
		// Appended, not a separate field: this is exactly the kind of extra
		// context an operator reads once and moves on from, and it must never
		// be missed by a client that only renders `message` (every ApprovalsPage
		// success path today does exactly that).
		if digestWarning != "" {
			message += " Note: " + digestWarning + "."
		}
		return Result{IncidentState: finalState, Message: message}, nil
	}
	if outcome == "unknown" {
		return Result{
			IncidentState: finalState,
			Message:       "Approved and sent, but the outcome could not be confirmed: " + execError + " Check the cluster directly before assuming this needs redoing — the change may already have applied.",
		}, nil
	}
	return Result{IncidentState: finalState, Message: "Approved, but execution failed: " + execError}, nil
}

// resolveIndeterminateOutcome is BACKLOG.md C8's verify-before-concluding
// step (BUGS.md 104): called only when ExecuteApprovedPlan's mutating tunnel
// call failed with the disconnect/timeout shape (gateway.ErrIndeterminate),
// never for an explicit ToolResult.Error. Re-reads the live target object
// via FetchPreconditionWithObject — the same read-only describe_resource
// path PreparePlan's own precondition already uses — and compares it against
// what this plan intended to set (verifyMutationApplied), so a live
// reproduction of exactly this bug (a tunnel drop mid-patch that the patch
// itself survived) resolves to the truth instead of a false "failed".
//
// Returns ("succeeded", "") on a confident match: this incident should read
// exactly like any other successful execution, not like a false failure an
// operator has to discover by hand. Returns ("unknown", <reason>) for every
// other case — an inconclusive comparison, an action type this verify step
// does not know how to compare (see verifyMutationApplied), or the re-read
// itself failing (still disconnected, object gone). Deliberately never
// returns "failed" here: a mismatch on this path proves "not confirmed," not
// "confirmed not to have happened" — eventual-consistency lag on a mutation
// that DID apply moments before the read looks identical to a genuinely
// failed one from a single follow-up read, and asserting a second guess
// would repeat this bug's own mistake in the opposite direction.
func (s *Executor) resolveIndeterminateOutcome(ctx context.Context, clusterID string, plan remediation.RemediationPlan, prep PlanPrep, callErr error) (outcome, execError string) {
	_, liveSpec, _, err := s.FetchPreconditionWithObject(ctx, clusterID, prep.TargetGVK, prep.TargetNamespace, prep.TargetName)
	if err != nil {
		logger.ErrorContext(ctx, "the tunnel call was indeterminate and the follow-up verify read also failed; recording unknown",
			logging.ClusterID(clusterID), slog.String("target_gvk", prep.TargetGVK),
			slog.String("target_namespace", prep.TargetNamespace), slog.String("target_name", prep.TargetName),
			slog.String("call_error", callErr.Error()), logging.Err(err))
		return "unknown", fmt.Sprintf("gateway: %v; a follow-up read to check whether the change actually applied also failed: %v", callErr, err)
	}

	matched, matchErr := verifyMutationApplied(plan, prep, liveSpec)
	if matchErr != nil {
		logger.WarnContext(ctx, "verification comparison errored; treated as inconclusive, never as failure",
			logging.ClusterID(clusterID), slog.String("target_gvk", prep.TargetGVK),
			slog.String("target_namespace", prep.TargetNamespace), slog.String("target_name", prep.TargetName),
			logging.Err(matchErr))
	}
	if matched {
		logger.InfoContext(ctx, "the tunnel call was indeterminate but a follow-up read confirms the change applied; recording succeeded",
			logging.ClusterID(clusterID), slog.String("target_gvk", prep.TargetGVK),
			slog.String("target_namespace", prep.TargetNamespace), slog.String("target_name", prep.TargetName),
			slog.String("call_error", callErr.Error()))
		return "succeeded", ""
	}
	logger.WarnContext(ctx, "the tunnel call was indeterminate and a follow-up read could not confirm the change applied; recording unknown, never failed",
		logging.ClusterID(clusterID), slog.String("target_gvk", prep.TargetGVK),
		slog.String("target_namespace", prep.TargetNamespace), slog.String("target_name", prep.TargetName),
		slog.String("call_error", callErr.Error()))
	return "unknown", fmt.Sprintf("gateway: %v; a follow-up read could not confirm whether the change applied — check the cluster directly", callErr)
}

// verifyMutationApplied compares the live spec (re-read after an
// indeterminate tunnel-call result) against what this plan intended to set,
// for the four action types ExecuteApprovedPlan's own mutating tunnel call
// covers per BACKLOG.md C8's own scope (ScaleDeployment, RestartPod,
// PatchResourceLimits, RevertContainerImage — the same four BUGS.md 104
// names). Returns (false, nil) — "not confirmed," never "confirmed false" —
// for any action type this function does not know how to compare, or any
// case where what was set is not knowable (a multi-field PatchResourceLimits
// plan has no single forwardApplied value); a caller must only ever read
// that as "still unknown," never as evidence the mutation failed.
func verifyMutationApplied(plan remediation.RemediationPlan, prep PlanPrep, liveSpec map[string]any) (matched bool, err error) {
	switch plan.ActionType {
	case remediation.ActionScaleDeployment:
		if prep.ForwardApplied == "" {
			return false, nil
		}
		want, convErr := strconv.Atoi(prep.ForwardApplied)
		if convErr != nil {
			return false, fmt.Errorf("forward applied value %q is not a replica count: %w", prep.ForwardApplied, convErr)
		}
		live, ok := liveReplicaCount(liveSpec)
		return ok && live == want, nil

	case remediation.ActionRevertContainerImage:
		params, ok := plan.Params.(remediation.RevertContainerImageParams)
		if !ok || prep.ForwardApplied == "" {
			return false, nil
		}
		live, liveErr := liveContainerImage(liveSpec, params.Container)
		if liveErr != nil {
			// The container itself could not be read post-mutation — not
			// confirmable, and not a hard error worth surfacing beyond the
			// honest "unknown" the caller already returns.
			return false, nil
		}
		return live == prep.ForwardApplied, nil

	case remediation.ActionPatchResourceLimits:
		params, ok := plan.Params.(remediation.PatchResourceLimitsParams)
		if !ok {
			return false, nil
		}
		live, liveErr := liveContainerResources(liveSpec, params.Container)
		if liveErr != nil {
			return false, nil
		}
		if params.MemoryLimit != "" && live.MemoryLimit != params.MemoryLimit {
			return false, nil
		}
		if params.MemoryRequest != "" && live.MemoryRequest != params.MemoryRequest {
			return false, nil
		}
		if params.CPULimit != "" && live.CPULimit != params.CPULimit {
			return false, nil
		}
		if params.CPURequest != "" && live.CPURequest != params.CPURequest {
			return false, nil
		}
		return true, nil

	case remediation.ActionCordonNode:
		params, ok := plan.Params.(remediation.CordonNodeParams)
		if !ok {
			return false, nil
		}
		live, _ := liveSpec["unschedulable"].(bool)
		return live == params.Unschedulable, nil

	case remediation.ActionDrainNode:
		// A drain always cordons first; the evictions are checked by
		// validation (the node's pods gone), not here.
		live, _ := liveSpec["unschedulable"].(bool)
		return live, nil

	case remediation.ActionRestartPod:
		// RestartPod sets no forwardApplied at all (the agent picks the
		// annotation's timestamp value at apply time — see
		// internal/agent/tools.go — so the hub never knows it in advance),
		// and the annotation key itself ("argus.io/restartedAt") contains
		// dots that this codebase's dot-path field reader
		// (readLiveFieldValue) would mis-split, the same reason
		// fieldpaths.go declines to make a dot-path claim about an
		// annotation key. The only available signal is: did this specific
		// annotation's value change from what it was immediately before the
		// call (prep.LiveObject, captured by PreparePlan's own precondition
		// read)?
		beforeSpec, specErr := specFromLiveObject(prep.LiveObject)
		if specErr != nil {
			return false, nil
		}
		beforeVal, _ := liveRestartedAtAnnotation(beforeSpec)
		afterVal, afterFound := liveRestartedAtAnnotation(liveSpec)
		if !afterFound {
			return false, nil
		}
		return afterVal != beforeVal, nil

	default:
		// Not one of the four action types this verify step covers —
		// ExecuteApprovedPlan's mutating tunnel call is reached by other
		// action types too (AnnotateResource, LabelResource, PatchField,
		// StructuredPatch, DeleteResource, CreateResource), but BACKLOG.md
		// C8's own reproduction and this fix were scoped to the four named
		// in BUGS.md 104. "Not confirmed" is the honest answer for the
		// rest, not a guess.
		return false, nil
	}
}

// specFromLiveObject decodes a live object's .spec, the same shape
// FetchPreconditionWithObject's own internal decode already uses — pulled
// out as its own small function because verifyMutationApplied's RestartPod
// branch needs to do the identical decode against prep.LiveObject (the
// BEFORE object, captured by PreparePlan) rather than against a freshly
// read AFTER object.
func specFromLiveObject(live json.RawMessage) (map[string]any, error) {
	var obj struct {
		Spec map[string]any `json:"spec"`
	}
	if err := json.Unmarshal(live, &obj); err != nil {
		return nil, fmt.Errorf("decode object: %w", err)
	}
	return obj.Spec, nil
}

// liveRestartedAtAnnotation reads ActionRestartPod's own rollout-restart
// annotation ("argus.io/restartedAt", set by internal/agent/tools.go)
// straight out of a decoded spec map via direct map indexing, rather than
// through readLiveFieldValue's dot-path notation — that reader splits every
// "." as a path separator, which would mis-split this key's own dots (the
// same reason fieldpaths.go's ActionAnnotateResource/ActionLabelResource
// entries decline to make a dot-path claim about an annotation key at all).
// Returns ("", false) for any missing or malformed level rather than
// erroring: an absent annotation is exactly what "never restarted" or "the
// live object's shape isn't what was expected" looks like, and this
// function's only caller already treats "not found" as "not confirmed"
// rather than a hard failure.
func liveRestartedAtAnnotation(spec map[string]any) (string, bool) {
	template, _ := spec["template"].(map[string]any)
	metadata, _ := template["metadata"].(map[string]any)
	annotations, _ := metadata["annotations"].(map[string]any)
	v, ok := annotations["argus.io/restartedAt"].(string)
	return v, ok
}

// LoadRecommendationPlan reads one remediation_recommendations row's full
// column set and reconstructs a typed remediation.RemediationPlan from it
// (orchestrator.ReconstructPlan) — needed by the execution path, unlike
// scanApprovalQueueItem's buildPlanView, which only ever renders a plan for
// display and never needs it back as a live, typed value.
func LoadRecommendationPlan(ctx context.Context, tx pgx.Tx, planID string) (remediation.RemediationPlan, error) {
	var incidentID, analysisID, actionType, targetGVK, targetName, riskLevel string
	var targetNamespace *string
	var paramsJSON []byte
	var reversible bool
	err := tx.QueryRow(ctx,
		`SELECT incident_id, analysis_id, action_type, target_gvk, target_namespace, target_name, params, reversible, risk_level
		   FROM remediation_recommendations WHERE id = $1`, planID,
	).Scan(&incidentID, &analysisID, &actionType, &targetGVK, &targetNamespace, &targetName, &paramsJSON, &reversible, &riskLevel)
	if err != nil {
		return remediation.RemediationPlan{}, err
	}
	return orchestrator.ReconstructPlan(incidentID, analysisID, actionType, targetGVK, deref(targetNamespace), targetName, paramsJSON, reversible, riskLevel)
}
