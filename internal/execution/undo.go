package execution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"k8s.io/apimachinery/pkg/api/resource"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/data"
	"argus/internal/domain"
	"argus/internal/logging"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
)

// Undo one execution.
//
// The HTTP endpoint is internal/api's handleRollbackExecution; everything below
// is what it delegates to once it has decided the request is well formed and
// the operator holds the capability for this cluster.
//
// # Why this is a separate path rather than "just approve the inverse"
//
// Every PatchResourceLimits and RevertContainerImage plan has carried a signed
// compensating action since WORKLOG §93 — and now ScaleDeployment does too
// (WORKLOG §146). The values are captured from the live object BEFORE the
// mutation, because that is the only moment they are knowable: afterwards the
// pre-change memory limit, or the image the container was running, is simply
// gone from the cluster.
//
// Nothing could replay any of it. `CapRemediationRollback` had been in the
// capability catalogue since the first authz pass, granted to three roles, and
// enforced by no handler. `BACKLOG.md`'s R1 called it "the one item on the
// automatic-mode prerequisite list that also pays off immediately for human
// operators", and unattended execution then shipped without it, which turned it
// from a prerequisite into a live gap: an unattended change that turns out wrong
// is undone by hand.
//
// # It goes through the ordinary execution path, and that is the point
//
// An undo is a mutation of a production cluster, so it gets everything a forward
// execution gets: the target re-resolved, a fresh `resourceVersion` precondition,
// the per-action bounds re-checked, the GitOps-ownership refusal, a **server-side
// dry run** before anything is committed, a freshly signed plan the agent
// re-verifies, and an audit record. Building a shortcut for it — "we already
// decided this was safe once" — would make the undo the least-checked write in
// the product, which is exactly backwards for the operation you reach for when
// something has already gone wrong.
//
// Concretely: the compensating action is turned into an ordinary
// remediation.RemediationPlan and handed to ExecuteApprovedPlan. There is no
// second executor.
//
// # What it refuses, and why each refusal is load-bearing
//
//   - **A failed execution.** Its outcome is unknown by definition — the patch may
//     have applied, partly applied, or not at all — so "put it back to what it
//     was" is not a statement anyone can make truthfully. Re-analyse instead.
//   - **An execution already undone.** Recorded on the row itself
//     (`rolled_back_by_execution_id`), so this is a fact rather than an inference.
//   - **An incident with a change in flight.** A signed plan is being applied to
//     this incident right now, so the value this undo restores predates a change
//     that has not resolved, and the in-flight execution owns the incident's next
//     state. Refused on the way in, before anything reads or writes a cluster —
//     see CheckUndoable.
//   - **A field somebody else has moved.** The sharpest one. The compensating
//     action was derived from state before the forward change, so replaying it is
//     only honest while the forward change is still what is running. If the live
//     value no longer matches what we applied, someone or something else changed
//     it, and restoring "our" old value would silently discard theirs. This is the
//     same reasoning as the pull-request path's `expectedCurrentValue`, and the
//     `resourceVersion` precondition alone does NOT cover it: that catches a
//     concurrent write between read and patch, not a deliberate change made an
//     hour ago. This is also what covers a SUPERSEDED execution — a later
//     execution against the same field moved it, so the live value no longer
//     matches what this one applied and the undo refuses. There is deliberately
//     no separate "is there a newer execution on this incident" check: a newer
//     execution against a DIFFERENT field is not something this undo would
//     discard, and refusing on it would block a legitimate undo on the strength
//     of an unrelated change.

// UndoableExecution is one execution and everything needed to decide whether its
// undo can honestly be applied.
type UndoableExecution struct {
	ID          string
	IncidentID  string
	PlanID      string
	ClusterID   string
	Outcome     string
	ActionType  string
	Params      []byte
	Description string
	// RecommendationActionType is the FORWARD action's own type
	// (remediation_recommendations.action_type) — deliberately a separate
	// field from ActionType above, which is the COMPENSATING action's type
	// (remediation_executions.rollback_action_type) and stays empty for any
	// irreversible action type, DeleteResource included. B143: a caller
	// asking "what action type actually ran" (VerifyAppliedValue's
	// DeleteResource branch) must read this field, never ActionType — for
	// every reversible action type the two happen to coincide (a
	// ScaleDeployment's own rollback is itself a ScaleDeployment, and
	// likewise for every other rollbackFor* builder), which is exactly what
	// let this go unnoticed until a live DeleteResource execution exposed it:
	// rollback_action_type is unconditionally NULL for an irreversible
	// action, so a check keyed on ActionType alone can never distinguish "no
	// rollback was recorded" from "the forward action itself was
	// DeleteResource."
	RecommendationActionType string
	// RecommendationParams is the FORWARD plan's own params
	// (remediation_recommendations.params) — what ARGUS asked the cluster to
	// set, as opposed to Params above, which is what it would set to UNDO
	// that. Carried for the same reason RecommendationActionType is: a
	// multi-field change has no single scalar in ForwardApplied, so the only
	// statement of what it applied is the plan itself. See
	// VerifyAppliedValue's PatchResourceLimits branch.
	RecommendationParams []byte
	ForwardApplied       string
	AlreadyUndone        *string
	ExecutedAt           time.Time
	// IncidentState is the incident's state at the moment the undo was asked
	// for. Filled by the handler (LoadUndoableExecution deliberately does not
	// read it — VerifyAppliedValue shares that loader and has no use for it),
	// and load-bearing twice: CheckUndoable refuses outright where an undo has
	// no sensible answer, and undoOutcomeStates decides what the undo does to
	// the incident from each state it is legal to start from.
	IncidentState string
	// The target, from the recommendation being undone. A compensating action
	// records WHAT to restore, never WHERE — the where has not changed, and
	// duplicating it would be a second place for it to be wrong.
	TargetGVK       string
	TargetNamespace string
	TargetName      string
}

// undoParams decodes the stored compensating params, or nil. Errors are the
// caller's to report through UndoPlan, which decodes the same bytes and is the
// one place a decode failure becomes a user-visible refusal.
func (e UndoableExecution) undoParams() remediation.ActionParams {
	p, err := orchestrator.UnmarshalPlanParams(e.ActionType, e.Params)
	if err != nil {
		return nil
	}
	return p
}

// ExecuteUndo is PreparePlan, a durable "we are doing this" record, the tunnel
// call, and the outcome — the forward path's shape with the approval-specific
// parts removed.
//
// The durability property the approval path gets from committing
// AwaitingApproval -> Executing before the call is kept here WITHOUT adding
// Executing edges from Validating/Failed/Reopened. Those edges would make
// Executing mean two different things ("a plan is being applied" and "a plan is
// being un-applied") and would need an Executing -> Reopened edge to get back
// out, for no gain.
//
// It used to be kept as an audit event alone, and that was not enough. An audit
// event is durable and attributable, but nothing queries audit_events for
// unfinished work — so a hub that died between the undo's dispatch and its
// outcome left a changed cluster and no row anything would ever come back to.
// The record is now the same attempt row the forward path writes
// (internal/execution/attempt.go, migration 000093), committed in the same
// transaction as that audit event and settled by whichever of this request or
// RunExecutionReconciler gets there first.
func (s *Executor) ExecuteUndo(ctx context.Context, scope Scope, actor Actor,
	exec UndoableExecution, plan remediation.RemediationPlan, overrides Overrides,
) (Result, error) {
	// BACKLOG.md G6: the same per-target lock ExecuteApprovedPlan takes,
	// for the same reason — an undo is a real mutation of the target
	// object (this file's own header comment: "it goes through the
	// ordinary execution path, and that is the point"), so a concurrent
	// forward execution or a concurrent second undo against the SAME
	// object must not also proceed while this one is in flight. See
	// concurrency.go's header comment for why scope.Tx is the
	// right transaction to hold this on.
	if err := s.acquireTargetLock(ctx, scope.Tx, exec.ClusterID, plan); err != nil {
		return Result{}, err
	}

	prep, err := s.PreparePlan(ctx, scope, exec.IncidentID, exec.PlanID, exec.ClusterID, plan, overrides, PrepForExecution)
	if err != nil {
		return Result{}, err
	}

	// dispatchCtx bounds everything from the durable record to the outcome
	// write, and is what the attempt's expiry is derived from — the same shape
	// and the same reasoning as ExecuteApprovedPlan's.
	dispatchCtx, cancelDispatch := context.WithTimeout(ctx, executionDispatchLimit)
	defer cancelDispatch()

	attempt := executionAttempt{
		ID: domain.NewID(domain.PrefixExecutionAttempt), TenantID: scope.TenantID, ClusterID: exec.ClusterID,
		IncidentID: exec.IncidentID, PlanID: exec.PlanID,
		Kind: executionAttemptUndo, ActionType: exec.ActionType,
		TargetGVK: prep.TargetGVK, TargetNamespace: prep.TargetNamespace, TargetName: prep.TargetName,
		ForwardApplied: prep.ForwardApplied, ResourceVersion: prep.ResourceVersion, Rollback: prep.Rollback,
		UndoOfExecutionID: exec.ID, Actor: actor,
		ExpiresAt: attemptExpiry(dispatchCtx),
	}
	// Where this undo puts the incident if it works is decided inside
	// recordUndoIntent, under the incident's row lock, and stamped onto the
	// attempt in the same transaction. Real time — two live cluster round trips
	// for the precondition and the dry run — has passed since the handler read
	// the state on the way in, so deciding from that reading would risk
	// carrying a destination derived from a state the incident has since left.
	states, err := s.recordUndoIntent(dispatchCtx, scope, exec, actor, prep, &attempt)
	if err != nil {
		return Result{}, fmt.Errorf("record the undo before applying it: %w", err)
	}

	argsJSON, marshalErr := json.Marshal(map[string]any{"plan": prep.Signed})
	var outcome, execError string
	switch {
	case marshalErr != nil:
		outcome, execError = "failed", fmt.Sprintf("build tool args: %v", marshalErr)
	default:
		// CallToolWithGrace, not plain CallTool: BACKLOG.md C8's cheap half
		// (internal/gateway/tools.go) — an undo is a mutating call exactly
		// like a forward execution, so it gets the same free, no-resend
		// late-result grace window. Its residual gap is NOT closed here: a
		// genuinely indeterminate undo result (gateway.ErrIndeterminate)
		// still falls straight to "failed" below rather than through
		// ExecuteApprovedPlan's resolveIndeterminateOutcome verify step —
		// BACKLOG.md C8's own text scopes the verify-and-correct half to the
		// forward path (BUGS.md 104's own reproduction), and an undo's
		// "intended result" is a second, not-yet-built comparison (the
		// rollback's own params, not a proposed plan's). Left as a stated,
		// not silent, gap.
		if _, callErr := s.gw.CallToolWithGrace(dispatchCtx, exec.ClusterID, prep.Tool, argsJSON); callErr != nil {
			outcome, execError = "failed", callErr.Error()
		} else {
			outcome = "succeeded"
		}
	}

	// The destinations decided above, not a hardcoded pair. Success moves the
	// incident only out of Validating, and only to Reopened; a failed or
	// indeterminate undo moves it nowhere at all. See undoOutcomeStates for
	// why, and recordExecutionOutcome for why an unreachable destination can
	// no longer cost this undo its own record.
	// exec.RecommendationActionType (the FORWARD action's own type), not
	// exec.ActionType (the compensating action's type) — see that field's
	// own doc comment, "recorded here" reused for the identical reason
	// B143's own check needed it: an undo of a ScaleDeployment is worth
	// distinguishing from an undo of a PatchResourceLimits, and ActionType
	// alone can never say which forward action this undo is undoing.
	finalState, err := s.recordExecutionOutcome(dispatchCtx, scope, exec.IncidentID, exec.PlanID, exec.ClusterID, actor,
		outcome, execError, prep.ResourceVersion, prep.Rollback, prep.ForwardApplied, states, attempt.ID, exec.RecommendationActionType, "undo")
	if err != nil {
		// The attempt row stays open, so the reconciler will settle it — the
		// cluster has already been changed and something must still say so.
		logger.ErrorContext(ctx, "recording an undo outcome failed; the attempt stays open for the execution reconciler",
			logging.IncidentID(exec.IncidentID), slog.String("attempt_id", attempt.ID), logging.Err(err))
		finalState = ""
	}
	if outcome != "succeeded" {
		return Result{}, fmt.Errorf("the cluster or its ARGUS agent refused the undo: %s", execError)
	}
	return Result{IncidentState: finalState}, nil
}

// recordUndoIntent commits, in its own transaction and before the tunnel call,
// the fact that this undo was authorised and is about to be applied: the
// attempt row something will come back to if this process does not, and the
// audit event recording who authorised it and what was checked first.
//
// Its own transaction for the same reason the forward path's Executing commit
// has one: a hub that dies between here and the patch must leave a durable record
// that it had committed to the change, rather than silently rolling back an
// intent whose effect may already have reached the cluster.
//
// The incident's state is re-read here under its row lock, and the same refusal
// CheckUndoable already made on the way in is made again. Real time — including
// live cluster round trips for the precondition and the dry run — passes
// between that first check and this commit, which is exactly the window in
// which an approval could have started executing a different plan against the
// same incident. This is the last point at which refusing is still free.
func (s *Executor) recordUndoIntent(ctx context.Context, scope Scope, exec UndoableExecution, actor Actor, prep PlanPrep, attempt *executionAttempt) (incidentOutcomeStates, error) {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return incidentOutcomeStates{}, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if err := data.SetRequestScope(ctx, tx, scope.TenantID, nil); err != nil {
		return incidentOutcomeStates{}, fmt.Errorf("set request scope: %w", err)
	}
	var state string
	if err := tx.QueryRow(ctx, `SELECT state FROM incidents WHERE id = $1 FOR UPDATE`, exec.IncidentID).Scan(&state); err != nil {
		return incidentOutcomeStates{}, fmt.Errorf("lock incident %s: %w", exec.IncidentID, err)
	}
	recheck := exec
	recheck.IncidentState = state
	if problem := CheckUndoable(recheck); problem != nil {
		return incidentOutcomeStates{}, fmt.Errorf("%w: %s", ErrUndoStateConflict, problem.Detail)
	}
	states := undoOutcomeStates(state)
	attempt.SuccessState = states.Succeeded
	if err := insertExecutionAttempt(ctx, tx, *attempt); err != nil {
		return incidentOutcomeStates{}, err
	}
	capability := authz.CapRemediationRollback
	if err := audit.RecordEvent(ctx, tx, audit.Event{
		TenantID: scope.TenantID, ActorID: actor.ActorIDOrNil(), ActorAuthMethod: actor.AuthMethod,
		SourceIP: actor.SourceIP, Capability: &capability, ClusterID: &exec.ClusterID,
		Outcome: audit.OutcomeSuccess,
		Details: map[string]any{
			"action":      "rollback_committed",
			"incidentId":  exec.IncidentID,
			"executionId": exec.ID,
			"undoing":     exec.Description,
			// The precondition and the attestation, so "we checked before we wrote"
			// is provable for an undo exactly as it is for a forward execution.
			"resourceVersion":  prep.ResourceVersion,
			"dryRunAttestedAt": prep.Attestation.At.Format(time.RFC3339),
			// The attempt this audit event now shares a transaction with, so
			// an auditor reading the log can find the row that says whether
			// the undo ever resolved — and who resolved it.
			"attemptId":     attempt.ID,
			"incidentState": state,
		},
	}); err != nil {
		return incidentOutcomeStates{}, fmt.Errorf("record audit event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return incidentOutcomeStates{}, fmt.Errorf("commit: %w", err)
	}
	return states, nil
}

// ErrUndoStateConflict is the sentinel for "the incident stopped being a
// sensible place to apply an undo between the request arriving and this
// commit". It exists so the handler answers 409 — an ordinary, expected
// concurrency outcome the operator can act on by waiting — rather than the
// generic 502 every other ExecuteUndo failure maps to, which would describe a
// clean, nothing-was-changed refusal as a cluster or agent fault.
var ErrUndoStateConflict = errors.New("this incident is no longer in a state where an undo can be applied")

// LoadUndoableExecution reads one execution plus its recorded undo.
func LoadUndoableExecution(ctx context.Context, tx pgx.Tx, executionID string) (UndoableExecution, error) {
	var e UndoableExecution
	var actionType, description, forwardApplied *string
	err := tx.QueryRow(ctx,
		`SELECT x.id, x.incident_id, x.recommendation_id, x.cluster_id, x.outcome,
		        x.rollback_action_type, x.rollback_params, x.rollback_description,
		        x.forward_applied_value, x.rolled_back_by_execution_id, x.executed_at,
		        r.target_gvk, COALESCE(r.target_namespace, ''), r.target_name, r.action_type, r.params
		   FROM remediation_executions x
		   JOIN remediation_recommendations r ON r.id = x.recommendation_id
		  WHERE x.id = $1`, executionID).
		Scan(&e.ID, &e.IncidentID, &e.PlanID, &e.ClusterID, &e.Outcome,
			&actionType, &e.Params, &description, &forwardApplied, &e.AlreadyUndone, &e.ExecutedAt,
			&e.TargetGVK, &e.TargetNamespace, &e.TargetName, &e.RecommendationActionType, &e.RecommendationParams)
	if err != nil {
		return UndoableExecution{}, err
	}
	e.ActionType = deref(actionType)
	e.Description = deref(description)
	e.ForwardApplied = deref(forwardApplied)
	return e, nil
}

// UndoPlan turns a stored compensating action into an ordinary plan.
//
// The target comes from the recommendation being undone, not from the stored
// params: a compensating action records WHAT to restore, never WHERE, because the
// where has not changed and duplicating it would be a second place for it to be
// wrong.
//
// Built through remediation.NewVerifiedRestorePlan rather than a literal
// RemediationPlan{...} (PROJECT.md B171): that constructor is the only way a
// plan's RestoreVerified() can ever report true, and it can only be reached
// from params this function has JUST decoded out of e.Params — the stored
// remediation_executions.rollback_params bytes, never anything from an HTTP
// request body. That is the provenance chain: rollback_params is written only
// by captureRollback at the ORIGINAL forward execution's PreparePlan, from a
// value read off the live container before that mutation
// (rollbackForResourceLimits and friends) — so a plan built here is, by
// construction, "restore a value that was itself live moments ago," never a
// fresh proposal, and RestoreVerified() lets a live-state check make
// that distinction without trusting a bare boolean asserted by whoever calls
// PreparePlan.
//
// # What this alone does NOT yet fix
//
// checkResourceLimitsBound's rule 2 ("a memory limit may only be RAISED",
// internal/execution) still runs unconditionally for every
// PatchResourceLimits plan PreparePlan sees, forward or undo, and does not
// yet consult RestoreVerified() — so undoing a memory-limit RAISE (which
// necessarily lowers the limit back) is still refused today exactly as
// before this change. Completing B171 needs one more edit, outside this
// file's scope: in PreparePlan's PatchResourceLimits branch
// (this package, the `checkResourceLimitsBound(live, params)` call),
// pass `plan.RestoreVerified()` through to relax ONLY rule 2's `mayDecline`
// for the memoryLimit field — every other bound (fields 1, 3, 4) must keep
// applying to a verified restore exactly as to a forward plan. This function
// now carries everything that check needs to consume; it does not yet consume
// it.
func UndoPlan(e UndoableExecution) (remediation.RemediationPlan, error) {
	params, err := orchestrator.UnmarshalPlanParams(e.ActionType, e.Params)
	if err != nil {
		return remediation.RemediationPlan{}, err
	}
	return remediation.NewVerifiedRestorePlan(remediation.ActionType(e.ActionType), params, e.TargetGVK, e.TargetNamespace, e.TargetName)
}

// LiveValueForUndo reads the one field this undo would restore, so it can be
// compared against what the forward change applied.
//
// Reuses the read-only describe_resource path every other check uses rather than
// adding a tool: the value is in the object the precondition fetch already knows
// how to get, and a second way of reading it would be a second way of reading it
// wrong.
func (s *Executor) LiveValueForUndo(ctx context.Context, e UndoableExecution) (string, error) {
	// The same resolution the forward path did: a pod-template action was applied
	// to the owning workload, so that is where the value lives.
	gvk, namespace, name, err := s.resolvePodTemplateTarget(ctx, e.ClusterID, e.TargetGVK, e.TargetNamespace, e.TargetName)
	if err != nil {
		return "", fmt.Errorf("resolve target: %w", err)
	}
	_, spec, err := s.fetchPrecondition(ctx, e.ClusterID, gvk, namespace, name)
	if err != nil {
		return "", fmt.Errorf("read %s %s/%s: %w", gvk, namespace, name, err)
	}

	switch remediation.ActionType(e.ActionType) {
	case remediation.ActionScaleDeployment:
		// The undo is a ScaleDeployment, so the forward change was one too, and the
		// value is spec.replicas.
		if n, ok := liveReplicaCount(spec); ok {
			return strconv.Itoa(n), nil
		}
		return "", errors.New("the workload does not report a replica count")
	case remediation.ActionPatchResourceLimits:
		params, ok := e.undoParams().(remediation.PatchResourceLimitsParams)
		if !ok {
			return "", fmt.Errorf("recorded undo params are %T, not PatchResourceLimitsParams", e.undoParams())
		}
		live, err := liveContainerResources(spec, params.Container)
		if err != nil {
			return "", err
		}
		// Whichever single field the undo restores is the field the forward change
		// set — singleAppliedValue guaranteed there is exactly one, or
		// ForwardApplied is empty and this function is never called.
		return singleAppliedValue(remediation.PatchResourceLimitsParams{
			Container:     params.Container,
			MemoryLimit:   pick(params.MemoryLimit, live.MemoryLimit),
			MemoryRequest: pick(params.MemoryRequest, live.MemoryRequest),
			CPULimit:      pick(params.CPULimit, live.CPULimit),
			CPURequest:    pick(params.CPURequest, live.CPURequest),
		}), nil
	case remediation.ActionRevertContainerImage:
		params, ok := e.undoParams().(remediation.RevertContainerImageParams)
		if !ok {
			return "", fmt.Errorf("recorded undo params are %T, not RevertContainerImageParams", e.undoParams())
		}
		return liveContainerImage(spec, params.Container)
	case remediation.ActionCordonNode:
		live, _ := spec["unschedulable"].(bool)
		return strconv.FormatBool(live), nil
	}
	return "", fmt.Errorf("action type %q has no live-value comparison", e.ActionType)
}

// UndoTargetValue is the value the undo would set, so "already there" can be told
// apart from "somebody else changed it". Empty when the action type has no single
// scalar, in which case the comparison is skipped rather than guessed at.
func UndoTargetValue(e UndoableExecution) string {
	switch remediation.ActionType(e.ActionType) {
	case remediation.ActionScaleDeployment:
		if p, ok := e.undoParams().(remediation.ScaleDeploymentParams); ok {
			return strconv.Itoa(p.Replicas)
		}
	case remediation.ActionPatchResourceLimits:
		if p, ok := e.undoParams().(remediation.PatchResourceLimitsParams); ok {
			return singleAppliedValue(p)
		}
	case remediation.ActionCordonNode:
		if p, ok := e.undoParams().(remediation.CordonNodeParams); ok {
			return strconv.FormatBool(p.Unschedulable)
		}
	case remediation.ActionRevertContainerImage:
		// Read from the raw JSON, not the typed params: RevertContainerImageParams
		// deliberately has no Image field — a plan never names an image, the hub
		// resolves it from the workload's own rollout history and refuses to accept
		// one from a model. The compensating action stores the *exec* params shape
		// (rollbackForContainerImage), which does carry it, because the undo's whole
		// content is "the image it was running before".
		var exec remediation.RevertContainerImageExecParams
		if err := json.Unmarshal(e.Params, &exec); err == nil {
			return exec.Image
		}
	}
	return ""
}

// pick returns live only where the undo names that field, so the comparison is
// made on the one field the forward change actually set and not on whatever else
// the container happens to have configured.
func pick(undoNames, live string) string {
	if undoNames == "" {
		return ""
	}
	return live
}

// verifiedFieldName is the field an execution changed, for a human-readable
// assertion.
//
// Derived from the recorded compensating action rather than stored separately:
// for every invertible action type the undo targets the same field the forward
// change did, so the path is already implied and a second stored copy would be a
// second thing to keep in step. Falls back to the target object when the path
// cannot be derived, which is honest — "something on this Deployment" rather than
// a guessed field name.
func verifiedFieldName(e UndoableExecution) string {
	if plan, err := UndoPlan(e); err == nil {
		// The error is deliberately ignored here, unlike at the execution call site:
		// this function's whole contract is "a field name if one can be derived, an
		// honest description of the object otherwise", and the fallback below IS the
		// handling. A log line per rendered incident would be noise.
		if paths, err := remediation.PlannedFieldPaths(plan); err == nil && len(paths) > 0 {
			return paths[0]
		}
	}
	return fmt.Sprintf("the field changed on %s %s/%s", e.TargetGVK, e.TargetNamespace, e.TargetName)
}

// VerifyAppliedValue implements orchestrator.AppliedValueVerifier — BACKLOG V1's
// positive post-fix check.
//
// It answers one question: does the field this execution changed still hold the
// value it applied? That turns `Validating -> Resolved` from "nothing came back"
// into an assertion, and it is what stops ARGUS reporting a successful remediation
// for a change the cluster has already discarded (WORKLOG §145 watched exactly
// that happen).
//
// # It lives here, not in the sweeper
//
// The answer needs a live read over the tunnel, and internal/gateway already
// imports internal/orchestrator — so the sweeper cannot call it. It also needs
// the action-to-field-path table (plannedFieldPaths) and the precondition reader,
// both of which are here. So the sweeper declares the interface and this supplies
// it; see orchestrator.AppliedValueVerifier.
//
// # What an error means, and why that is not "the change is gone"
//
// Every "cannot tell" path returns an error rather than held=false, and the
// distinction is load-bearing: false makes the sweeper REOPEN the incident, so
// returning it for an unreachable cluster or an unmodelled action type would
// manufacture recurrences out of ignorance. The sweeper falls back to the old
// grace-period behaviour on an error and says in its log that the assertion was
// not made.
func (s *Executor) VerifyAppliedValue(ctx context.Context, executionID string) (bool, string, error) {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return false, "", fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tenantID, err := data.SingleOrganisationID(ctx, tx)
	if err != nil {
		return false, "", fmt.Errorf("resolve organisation: %w", err)
	}
	if err := data.SetRequestScope(ctx, tx, tenantID, nil); err != nil {
		return false, "", fmt.Errorf("set request scope: %w", err)
	}

	// Reuses LoadUndoableExecution: the undo path already needed exactly this —
	// the execution, its applied value, and the recommendation's target — so the
	// two features share one loader rather than two queries that could disagree
	// about which object an execution touched.
	exec, err := LoadUndoableExecution(ctx, tx, executionID)
	if err != nil {
		return false, "", fmt.Errorf("load execution %s: %w", executionID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return false, "", fmt.Errorf("commit: %w", err)
	}

	if exec.ForwardApplied == "" {
		// PROJECT.md B140: a DeleteResource execution records no scalar
		// applied value by design — there is nothing left to re-read once
		// the object is gone — but that is not the same as nothing being
		// assertable. The deletion analogue of "does the field still hold
		// what we set it to" is "is the object still gone", and this
		// codebase already has, and trusts, exactly that check:
		// confirmTargetAbsentForCreate/interpretAbsenceCheckResult, built
		// for CreateResource's OWN precondition (confirming absence BEFORE
		// creating) — reused here in the opposite direction, confirming
		// absence AFTER deleting. Live-reproduced 2026-09-05
		// (docs/VERIFICATION.md, PVC-002 fixture): a genuinely successful
		// deletion — object confirmed gone from the live cluster — sat in
		// Validating for the full grace-period-plus-deadline window and
		// landed in ValidationUnknown instead of Resolved, because this
		// branch used to return unconditionally below regardless of
		// action type.
		//
		// B143: this check must read RecommendationActionType (the FORWARD
		// action's own type), not ActionType (the compensating action's
		// type, sourced from rollback_action_type). DeleteResource is
		// unconditionally irreversible, so rollback_action_type — and
		// therefore ActionType — is always empty for it; a check keyed on
		// ActionType alone could never be true here, which is exactly why
		// this branch was live-confirmed unreachable (docs/VERIFICATION.md,
		// b140verify fixture, 2026-09-06) despite being correct in isolation.
		if remediation.ActionType(exec.RecommendationActionType) == remediation.ActionDeleteResource {
			if !s.gw.IsConnected(exec.ClusterID) {
				return false, "", fmt.Errorf("cluster %s is not connected", exec.ClusterID)
			}
			return s.verifyDeletionHeld(ctx, exec)
		}
		// T5, found live 2026-09-17: the same shape as B140 above, for the
		// case this branch's own comment used to name and then decline —
		// "a multi-field limits patch". It is not a rare shape. A model
		// fixing an OOMKilled container sets a request AND a limit in one
		// plan, which is the correct fix and the one the gate encourages;
		// singleAppliedValue then records nothing, because there is no
		// single scalar to record. The consequence was that a demonstrably
		// successful in-place remediation could never be positively
		// verified: inc_01m2rbs6e9zycjnh9e0xcemxh2 executed cleanly (memory
		// 4Mi -> 128Mi limit, 4Mi -> 64Mi request, pod back to 1/1 Running)
		// and the sweeper logged "the change itself could not be re-checked"
		// every 60s, bound for ValidationUnknown an hour later.
		//
		// "Cannot assert" was the honest answer only while nothing could
		// assert it. Something can: the forward PLAN states every value it
		// set, and liveContainerResources reads every one of them back off
		// the live container. That is the identical question the single-field
		// path asks, asked once per field instead of once — not a guess, and
		// not a weaker claim. Held means every field the plan set still
		// holds the value it set; a single field that moved is held=false,
		// exactly as it would be for a single-field patch, so the sweeper's
		// reopen-on-negative behaviour is unchanged.
		if remediation.ActionType(exec.RecommendationActionType) == remediation.ActionPatchResourceLimits {
			if !s.gw.IsConnected(exec.ClusterID) {
				return false, "", fmt.Errorf("cluster %s is not connected", exec.ClusterID)
			}
			return s.verifyResourceLimitsHeld(ctx, exec)
		}
		// Still honest "cannot assert" for an action type with no modelled
		// field, rather than a guess.
		return false, "", fmt.Errorf("execution %s recorded no single applied value to re-check", executionID)
	}
	if !s.gw.IsConnected(exec.ClusterID) {
		return false, "", fmt.Errorf("cluster %s is not connected", exec.ClusterID)
	}

	live, err := s.LiveValueForUndo(ctx, exec)
	if err != nil {
		return false, "", err
	}
	// Named by the FIELD, not by exec.Description — that field describes the
	// undo ("scale back to 1 replica(s)"), so using it here produced the nonsense
	// "scale back to 1 replica(s) is still 3". The field path is what the
	// assertion is actually about.
	field := verifiedFieldName(exec)
	if live == exec.ForwardApplied {
		return true, fmt.Sprintf("%s is still %q", field, live), nil
	}
	return false, fmt.Sprintf("%s: ARGUS set it to %q and it is now %q", field, exec.ForwardApplied, live), nil
}

// verifyResourceLimitsHeld is VerifyAppliedValue's multi-field
// PatchResourceLimits branch (T5): does every resource value this execution's
// plan set still hold on the live container?
//
// Split out and given the forward plan's own params as its input the same way
// verifyDeletionHeld is split out, so the comparison is a small function over
// two values rather than another case inside an already long one.
//
// Every "cannot tell" path returns an error, never held=false, for the reason
// VerifyAppliedValue's own doc comment gives: false makes the sweeper REOPEN
// the incident, and an unreadable container or undecodable params is ignorance,
// not a reverted change.
//
// Compared through resource.Quantity.Cmp, never as strings: the API server
// serializes what it stores, so a plan that said "64Mi" can legitimately read
// back as "64Mi", "65536Ki" or "67108864" — all the same value, and a string
// comparison would report two of the three as a reverted change and reopen a
// correctly fixed incident.
func (s *Executor) verifyResourceLimitsHeld(ctx context.Context, exec UndoableExecution) (bool, string, error) {
	var planned remediation.PatchResourceLimitsParams
	if err := json.Unmarshal(exec.RecommendationParams, &planned); err != nil {
		return false, "", fmt.Errorf("decode the plan this execution applied: %w", err)
	}
	gvk, namespace, name, err := s.resolvePodTemplateTarget(ctx, exec.ClusterID, exec.TargetGVK, exec.TargetNamespace, exec.TargetName)
	if err != nil {
		return false, "", fmt.Errorf("resolve target: %w", err)
	}
	_, spec, err := s.fetchPrecondition(ctx, exec.ClusterID, gvk, namespace, name)
	if err != nil {
		return false, "", fmt.Errorf("read %s %s/%s: %w", gvk, namespace, name, err)
	}
	live, err := liveContainerResources(spec, planned.Container)
	if err != nil {
		return false, "", err
	}
	return compareResourceLimitsHeld(planned, live, gvk, namespace, name)
}

// compareResourceLimitsHeld is verifyResourceLimitsHeld's decision, as a pure
// function of the plan and the live values — split for the same reason
// interpretDeletionVerificationResult and interpretDryRunResult are, since a
// check the sweeper reopens incidents on should be directly unit-testable with
// no cluster behind it.
func compareResourceLimitsHeld(planned remediation.PatchResourceLimitsParams, live containerResources, gvk, namespace, name string) (bool, string, error) {
	fields := []struct {
		name    string
		planned string
		live    string
	}{
		{"memory limit", planned.MemoryLimit, live.MemoryLimit},
		{"memory request", planned.MemoryRequest, live.MemoryRequest},
		{"cpu limit", planned.CPULimit, live.CPULimit},
		{"cpu request", planned.CPURequest, live.CPURequest},
	}
	var held []string
	for _, f := range fields {
		if f.planned == "" {
			continue
		}
		want, err := resource.ParseQuantity(f.planned)
		if err != nil {
			return false, "", fmt.Errorf("the %s this plan applied (%q) is not a readable quantity", f.name, f.planned)
		}
		if f.live == "" {
			// The field the plan set is not there at all. That IS the change
			// not holding — something removed it — and it is the one absence
			// this function reports as false rather than as an error.
			return false, fmt.Sprintf("container %q on %s %s/%s no longer has a %s at all, and ARGUS set it to %s",
				planned.Container, gvk, namespace, name, f.name, f.planned), nil
		}
		got, err := resource.ParseQuantity(f.live)
		if err != nil {
			return false, "", fmt.Errorf("the container's live %s (%q) is not a readable quantity", f.name, f.live)
		}
		if got.Cmp(want) != 0 {
			return false, fmt.Sprintf("container %q on %s %s/%s: ARGUS set its %s to %s and it is now %s",
				planned.Container, gvk, namespace, name, f.name, f.planned, f.live), nil
		}
		held = append(held, fmt.Sprintf("%s %s", f.name, f.planned))
	}
	if len(held) == 0 {
		// Unreachable through the gate — PatchResourceLimitsParams.Validate
		// requires at least one field — but a "nothing to check" that returned
		// held=true would be a verification that verified nothing.
		return false, "", fmt.Errorf("the plan this execution applied names no resource value to re-check")
	}
	return true, fmt.Sprintf("container %q on %s %s/%s still has %s", planned.Container, gvk, namespace, name, strings.Join(held, " and ")), nil
}

// verifyDeletionHeld is VerifyAppliedValue's DeleteResource branch (PROJECT.md
// B140): does a real, live describe_resource call, then hands the result to
// interpretDeletionVerificationResult for the actual decision — split the
// same way interpretDryRunResult/interpretAbsenceCheckResult already are in
// this codebase, so the decision logic is directly unit-testable without a
// live gateway/cluster for a control this safety-relevant.
func (s *Executor) verifyDeletionHeld(ctx context.Context, exec UndoableExecution) (bool, string, error) {
	argsJSON, err := json.Marshal(map[string]any{"gvk": exec.TargetGVK, "namespace": exec.TargetNamespace, "name": exec.TargetName})
	if err != nil {
		return false, "", fmt.Errorf("build describe_resource args: %w", err)
	}
	_, callErr := s.gw.CallTool(ctx, exec.ClusterID, "describe_resource", argsJSON)
	return interpretDeletionVerificationResult(exec.TargetGVK, exec.TargetNamespace, exec.TargetName, callErr)
}

// interpretDeletionVerificationResult reads a describe_resource result the
// opposite way confirmTargetAbsentForCreate's interpretAbsenceCheckResult
// does: absence is the SUCCESS case here (the deletion held), not the
// precondition being confirmed before an action. Same three outcomes,
// different meaning for each:
//
//  1. describe_resource FAILS with the agent's own "resource not found" text
//     (remediation.ErrResourceNotFoundMessage) -> confirmed still gone:
//     held=true. This is VerifyAppliedValue's ordinary positive case for
//     every other action type inverted — there, "the field still holds the
//     value" is held=true; here, "the object still does not exist" is.
//  2. describe_resource SUCCEEDS -> the object exists again. A real
//     recurrence: held=false, which is what makes the sweeper REOPEN the
//     incident (VerifyAppliedValue's ordinary "the value changed back"
//     case), never an error — an error here would fall back to the old
//     grace-period behaviour and never notice the deletion did not hold.
//  3. describe_resource FAILS for any OTHER reason (RBAC denied, a
//     disconnected agent, a timeout) -> ambiguous, same as
//     interpretAbsenceCheckResult's case 3: an error, never held=false,
//     since manufacturing a recurrence out of "cannot tell" is exactly what
//     VerifyAppliedValue's own doc comment warns against.
//
// Same known brittleness as interpretAbsenceCheckResult: case 1 matches TEXT
// that crossed the tunnel as a plain error string, not a typed error code.
// If sanitizeK8sErr's wording ever changes without
// remediation.ErrResourceNotFoundMessage changing to match, this stops
// recognising "still gone" and falls into case 3 — refusing to assert rather
// than wrongly resolving, which is the safe direction for this particular
// brittleness to fail in.
func interpretDeletionVerificationResult(gvk, namespace, name string, callErr error) (held bool, detail string, err error) {
	if callErr == nil {
		return false, fmt.Sprintf("%s %s/%s exists again — the deletion did not hold", gvk, namespace, name), nil
	}
	if strings.Contains(callErr.Error(), remediation.ErrResourceNotFoundMessage) {
		return true, fmt.Sprintf("%s %s/%s is still gone", gvk, namespace, name), nil
	}
	return false, "", fmt.Errorf("could not confirm %s %s/%s is still deleted (%w) — the assertion was not made", gvk, namespace, name, callErr)
}

// UndoRefusal is one reason an undo may not be applied, already shaped as the
// RFC 9457 problem internal/api will write. The status codes live here rather
// than in the handler because the reasoning and the status are one decision —
// "already rolled back" is a 409 and "no compensating action was recorded" is a
// 422 — and splitting them would put half of it where nothing tests it.
type UndoRefusal struct {
	Status                     int
	ProblemType, Title, Detail string
}

// CheckUndoable is every refusal, in one pure function so the reasoning is
// testable without a database or a cluster. Order matters only in that the most
// specific and most alarming case (someone else moved the field) is checked last,
// so an operator sees the simpler explanations first when several apply.
func CheckUndoable(e UndoableExecution) *UndoRefusal {
	if e.Outcome != "succeeded" {
		return &UndoRefusal{http.StatusConflict, "https://argus.io/errors/invalid-state",
			"This execution did not succeed, so there is nothing to undo",
			fmt.Sprintf("execution %s has outcome %q. A failed execution may have applied part of its change, none of it, or all of it before failing to record — so \"put it back to what it was\" is not a statement anyone can make truthfully here. Re-analyse the incident so a fresh plan is derived from the cluster's actual current state.", e.ID, e.Outcome)}
	}
	if e.ActionType == "" {
		return &UndoRefusal{http.StatusUnprocessableEntity, "https://argus.io/errors/no-rollback-recorded",
			"This action has no undo",
			"No compensating action was recorded for this execution. That is expected for a workload restart — the pods it replaced are already gone, so there is nothing to restore — and it is why the undo control does not appear for one. For any other action type it means the execution predates rollback capture."}
	}
	if e.AlreadyUndone != nil && *e.AlreadyUndone != "" {
		return &UndoRefusal{http.StatusConflict, "https://argus.io/errors/already-rolled-back",
			"This execution has already been rolled back",
			fmt.Sprintf("execution %s was undone by execution %s. Applying the same compensating action twice would restore a value that is no longer the one this undo was derived from.", e.ID, *e.AlreadyUndone)}
	}
	// The incident is mid-execution: a signed plan is in flight over the
	// tunnel right now. This is the ONE state where an undo has no sensible
	// answer, so it is the one refused, and it is refused BEFORE anything
	// reads or writes a cluster.
	//
	// Two independent reasons, either sufficient. Concurrency: the in-flight
	// execution owns this incident's next state and will write Executing ->
	// Validating/Failed/ExecutionUnknown when it finishes, so an undo settling
	// in between produces two writers with different ideas of what happened.
	// Truth: the in-flight change has not resolved, so "put the field back to
	// what it was before the LAST change" is a claim about a world that is
	// still moving. Waiting costs seconds; being wrong costs a production
	// cluster.
	//
	// Every OTHER state is allowed through, deliberately. It is tempting to
	// extend the same "another writer owns the state" argument to
	// Investigating, and it does not hold: an analysis is a read, an undo does
	// not need to move the incident (see undoOutcomeStates — from every state
	// but Validating it changes nothing), and refusing would push an operator
	// who has just watched a change go wrong out of the audited path and into
	// kubectl, which is where undo refusals actually get resolved. A closed
	// incident is allowed through for the same reason: the undo is a fact
	// about the cluster, and closing an incident is not a statement that the
	// cluster may never be touched again.
	if e.IncidentState == orchestrator.StateExecuting {
		return &UndoRefusal{http.StatusConflict, "https://argus.io/errors/invalid-state",
			"Another change is being applied to this incident right now",
			fmt.Sprintf("incident %s is %s: a signed plan is in flight against the cluster. Undoing while that is unresolved would leave two changes racing to describe the same object, and the value this undo restores was captured before a change that has not finished. Nothing was changed. Wait for the in-flight execution to record its outcome, then undo whichever execution you meant.", e.IncidentID, e.IncidentState)}
	}
	return nil
}
