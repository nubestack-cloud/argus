// POST /api/v1/executions/{id}/rollback — the transport half of undoing one
// execution.
//
// Everything that decides whether the undo is safe or honest lives in
// internal/execution (undo.go): the refusals (execution.CheckUndoable), the
// plan the compensating action becomes (execution.UndoPlan), the live-value
// comparison that catches a field somebody else has moved, and the execution
// itself, which goes through the same execution.PreparePlan/sign/dry-run/record pipeline
// a forward change does. That file's header carries the full reasoning for why
// an undo gets every check a forward execution gets. What is left here is
// decoding the body, the per-cluster capability check, and turning each of
// those refusals into the RFC 9457 problem the UI renders.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"argus/internal/audit"
	"argus/internal/authz"
	"argus/internal/events"
	"argus/internal/execution"
	"argus/internal/logging"

	"github.com/jackc/pgx/v5"
)

// rollbackRequest carries the same two guardrail overrides an approval does,
// because an undo hits the same guardrails: putting a workload back to zero
// replicas is still scaling to zero, and undoing a patch on a GitOps-managed
// object is still a change the next sync reverts.
type rollbackRequest struct {
	ConfirmScaleFromZero bool   `json:"confirmScaleFromZero"`
	ConfirmGitOpsManaged bool   `json:"confirmGitOpsManaged"`
	ConfirmationToken    string `json:"confirmationToken"`
	// ConfirmValueChanged acknowledges that the field has moved since the forward
	// change. Deliberately a separate flag from the two above rather than folded
	// into them: it is not "I know this is a stop-gap", it is "I know I am about to
	// overwrite a value somebody else set", which is a different admission.
	ConfirmValueChanged bool `json:"confirmValueChanged"`
}

type rollbackResponse struct {
	ExecutionID   string `json:"executionId"`
	IncidentID    string `json:"incidentId"`
	IncidentState string `json:"incidentState"`
	Undid         string `json:"undid"`
	Message       string `json:"message"`
}

// handleRollbackExecution is POST /api/v1/executions/{id}/rollback. Requires
// remediation:rollback AND remediation:execute:inplace — the first because it is
// its own decision, the second because this writes to a live cluster and that is
// the capability naming that channel. A principal who may approve pull requests
// but never touch a cluster in place must not be able to reach this.
func (s *Server) handleRollbackExecution(w http.ResponseWriter, r *http.Request, rc *requestContext) {
	ctx := r.Context()
	executionID := r.PathValue("id")

	var req rollbackRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil && !errors.Is(err, jsonEOF) {
		writeProblem(w, http.StatusBadRequest, "https://argus.io/errors/malformed-request", "Malformed request body", err.Error())
		return
	}

	exec, err := execution.LoadUndoableExecution(ctx, rc.Tx, executionID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeProblem(w, http.StatusNotFound, "https://argus.io/errors/not-found", "No such execution", "")
			return
		}
		logger.ErrorContext(ctx, "loading the execution to roll back failed", slog.String("execution_id", executionID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up this execution", "")
		return
	}

	// Scope-aware capability check (BACKLOG S1). The route already required
	// remediation:rollback and remediation:execute:inplace, but scope-blind — so a
	// grant scoped to one cluster authorised an undo on any cluster. Checked here
	// rather than at the route because only the handler knows which cluster the
	// execution touched.
	for _, capability := range []string{authz.CapRemediationRollback, authz.CapRemediationExecInplace} {
		allowed, err := authz.HasCapabilityForCluster(ctx, rc.Tx, rc.Grants, capability, exec.ClusterID)
		if err != nil {
			logger.ErrorContext(ctx, "resolving cluster-scoped capability failed", logging.ClusterID(exec.ClusterID), logging.Err(err))
			writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not resolve the scope of your permissions", "")
			return
		}
		if !allowed {
			s.recordCapabilityDenial(ctx, rc, capability, clientIP(r))
			writeProblem(w, http.StatusForbidden, "https://argus.io/errors/scope-denied",
				"Missing required capability for this cluster",
				fmt.Sprintf("undoing this execution changes cluster %s, and you hold %q on a narrower scope than that", exec.ClusterID, capability))
			return
		}
	}

	// The incident's own state, read before anything else is decided. An undo
	// is a mutation of a production cluster, so the question "is this incident
	// in a state where undoing makes sense?" has to be answered here, on the
	// way in, and not discovered afterwards by a state transition that turns
	// out to be illegal once the cluster has already been changed.
	state, err := incidentState(ctx, rc.Tx, exec.IncidentID)
	if err != nil {
		logger.ErrorContext(ctx, "looking up the incident to roll back failed", logging.IncidentID(exec.IncidentID), logging.Err(err))
		writeProblem(w, http.StatusInternalServerError, "https://argus.io/errors/internal", "Could not look up this execution's incident", "")
		return
	}
	exec.IncidentState = state

	if problem := execution.CheckUndoable(exec); problem != nil {
		writeProblem(w, problem.Status, problem.ProblemType, problem.Title, problem.Detail)
		return
	}

	plan, err := execution.UndoPlan(exec)
	if err != nil {
		logger.ErrorContext(ctx, "building the undo plan failed", slog.String("execution_id", executionID), logging.Err(err))
		writeProblem(w, http.StatusUnprocessableEntity, "https://argus.io/errors/invalid-state",
			"This execution's recorded undo cannot be read",
			fmt.Sprintf("the compensating action stored with execution %s did not decode: %v. Nothing was changed. Re-analyse the incident so a fresh plan is derived from the current state.", executionID, err))
		return
	}

	// The refusal that the resourceVersion precondition does NOT cover.
	//
	// The precondition catches a concurrent write between this read and the patch.
	// It says nothing about a deliberate change made an hour ago. So before
	// applying an undo derived from state captured before the forward change, check
	// that the forward change is still what is running: if the field has moved,
	// restoring "our" old value would discard whatever replaced it.
	//
	// Only when a single scalar was applied — with two fields changed there is no
	// one value to compare, and the code says so rather than inventing a check.
	if exec.ForwardApplied != "" {
		live, err := s.exec().LiveValueForUndo(ctx, exec)
		switch {
		case err != nil:
			// Unreadable is not the same as unchanged, and this is an undo: fail
			// closed rather than apply a compensating action against a target whose
			// current state could not be established.
			logger.ErrorContext(ctx, "reading the live value for an undo failed", slog.String("execution_id", executionID), logging.Err(err))
			writeProblem(w, http.StatusServiceUnavailable, "https://argus.io/errors/cluster-unreachable",
				"Could not read the current value, so the undo was not applied",
				fmt.Sprintf("ARGUS could not confirm that what it changed is still what is running, and an undo derived from before that change must not be applied blind. Nothing was changed. %v", err))
			return
		case live == execution.UndoTargetValue(exec):
			// The undo would change nothing, because the field is already where the
			// undo wants it. Distinct from "somebody else moved this" and much the
			// more common case on a GitOps-managed object: the controller reverted
			// ARGUS's change before anyone reached for the undo. Saying "something
			// else changed this" here would be technically true and useless — the
			// operator wants to know there is nothing left to do.
			writeProblem(w, http.StatusConflict, "https://argus.io/errors/nothing-to-undo",
				"There is nothing to undo — the change is already gone",
				fmt.Sprintf("ARGUS set this to %q and it is %q now, which is what the undo would restore. Something has already reversed the change — on a GitOps-managed object that is usually the controller's next sync, which is exactly what the stop-gap warning at approval time meant. Nothing was changed.", exec.ForwardApplied, live))
			return
		case live != exec.ForwardApplied && !req.ConfirmValueChanged:
			writeProblem(w, http.StatusConflict, "https://argus.io/errors/undo-value-changed",
				"Something else has changed this since ARGUS did",
				fmt.Sprintf("ARGUS set this to %q, and it is now %q. Undoing would replace that with %s — discarding whatever made the later change rather than reversing ARGUS's. "+
					"Nothing was changed. If you have checked and still want the original value restored, send \"confirmValueChanged\": true; the acknowledgement is recorded in the audit trail.",
					exec.ForwardApplied, live, exec.Description))
			return
		}
	}

	if !s.gw.IsConnected(exec.ClusterID) {
		writeProblem(w, http.StatusServiceUnavailable, "https://argus.io/errors/cluster-unreachable",
			"Cluster not connected",
			"This cluster has no live agent connection, so the undo cannot be applied. Nothing has been changed — try again once it reconnects.")
		return
	}

	// The undo shares execution.PreparePlan — the resolved target, the fresh precondition,
	// every per-action bound, the GitOps refusal, the captured rollback-of-the-undo,
	// the signed plan and the server-side dry run — and then diverges, because an
	// undo is NOT an approval and the approval path's commit point encodes three
	// things that are false here:
	//
	//   - It requires the incident to be AwaitingApproval. After a forward
	//     execution the incident is Validating, so an undo routed through it fails
	//     with "no longer awaiting approval" — which is how this was found.
	//   - It writes a remediation_approval_decisions row. Nobody approved a plan;
	//     somebody reversed one. Recording an approval would make the approvals
	//     history claim a decision that was never made.
	//   - It lands the incident in Validating. There is nothing to validate: an
	//     undo removes a fix, so the incident is unfixed again by definition.
	//     Reopened is the honest destination from Validating, and where an undo
	//     leaves the incident from every OTHER starting state is
	//     undoOutcomeStates' decision — mostly "nowhere", deliberately.
	//
	// So this is a separate commit point, not a separate executor. Everything that
	// decides whether the write is safe is shared; only the bookkeeping differs.
	//
	// Detached from the request and bounded, exactly like the approve path: an
	// operator who closes the tab after asking for an undo must not be the reason
	// a cluster is changed with nothing written down. See
	// handleApproveIncident's own comment and execution.WorkLimit.
	workCtx, cancelWork := context.WithTimeout(context.WithoutCancel(ctx), execution.WorkLimit)
	defer cancelWork()

	resp, err := s.exec().ExecuteUndo(workCtx, scopeOf(rc), humanActor(rc, r), exec, plan, execution.Overrides{
		ScaleFromZero: req.ConfirmScaleFromZero,
		GitOpsManaged: req.ConfirmGitOpsManaged,
		Token:         req.ConfirmationToken,
	})
	if err != nil {
		// The same two guardrail refusals the forward path maps, with the same
		// distinct problem types — because an undo hits them for the same reasons
		// and the UI must offer the matching confirmation, not a generic retry.
		// Putting a workload back to zero replicas is still scaling to zero;
		// undoing a patch on a GitOps-managed object is still a change the next
		// sync reverts.
		if errors.Is(err, execution.ErrScaleFromZeroRefused) {
			s.writeGuardrailRefusal(ctx, w, exec.PlanID, execution.GuardrailScaleFromZero,
				"https://argus.io/errors/scale-from-zero-refused", "Refusing to scale this workload back down to zero", err.Error())
			return
		}
		if errors.Is(err, execution.ErrGitOpsManagedRefused) {
			s.writeGuardrailRefusal(ctx, w, exec.PlanID, execution.GuardrailGitOpsManaged,
				"https://argus.io/errors/gitops-managed-refused", "Refusing to patch an object whose source of truth is elsewhere", err.Error())
			return
		}
		// The incident stopped being a sensible place to undo into while this
		// request was doing its live cluster checks. A conflict, not a fault:
		// nothing was changed, and the operator's next move is to wait rather
		// than to investigate a broken cluster — which is what the generic 502
		// below would send them off to do.
		if errors.Is(err, execution.ErrUndoStateConflict) {
			writeProblem(w, http.StatusConflict, "https://argus.io/errors/invalid-state",
				"This incident changed while the undo was being checked", err.Error())
			return
		}
		logger.ErrorContext(ctx, "executing an undo failed", slog.String("execution_id", executionID), logging.Err(err))
		writeProblem(w, http.StatusBadGateway, "https://argus.io/errors/remediation-execution-failed",
			"Could not apply the undo", err.Error())
		return
	}

	// "Has this been rolled back, and by what?" is now written by
	// settleExecutionAttempt, in the same transaction as the undo's own
	// outcome — see that function for why. It used to be a separate,
	// best-effort transaction here that identified the undo as "the newest
	// execution on this incident", which is a guess: anything else executing
	// against the same incident in between made it name the wrong row.

	capability := authz.CapRemediationRollback
	if auditErr := audit.RecordEvent(ctx, rc.Tx, audit.Event{
		TenantID: rc.TenantID, ActorID: &rc.UserID, ActorAuthMethod: "jwt",
		SourceIP: clientIP(r), Capability: &capability, ClusterID: &exec.ClusterID,
		Outcome: audit.OutcomeSuccess,
		Details: map[string]any{
			"action":            "rollback_execution",
			"incidentId":        exec.IncidentID,
			"executionId":       executionID,
			"undoActionType":    exec.ActionType,
			"undoDescription":   exec.Description,
			"forwardApplied":    exec.ForwardApplied,
			"valueChangeOkayed": req.ConfirmValueChanged,
		},
	}); auditErr != nil {
		logger.ErrorContext(ctx, "recording a rollback in the audit log failed", slog.String("execution_id", executionID), logging.Err(auditErr))
	}

	if s.events != nil {
		s.events.Publish(events.IncidentUpdated(exec.IncidentID, exec.ClusterID))
	}

	// The state sentence is only made when there IS a state to report. An
	// empty one means recordExecutionOutcome could not commit — the undo
	// happened, the attempt row is still open, and the reconciler will finish
	// it — and rendering "this incident is now ." would turn that into
	// nonsense at exactly the moment an operator needs to be told plainly.
	stateSentence := "ARGUS could not record the incident's new state; the recovery sweep will finish that shortly"
	if resp.IncidentState != "" {
		stateSentence = "this incident is now " + resp.IncidentState
	}
	writeJSON(w, http.StatusOK, rollbackResponse{
		ExecutionID:   executionID,
		IncidentID:    exec.IncidentID,
		IncidentState: resp.IncidentState,
		Undid:         exec.Description,
		Message: fmt.Sprintf("Rolled back: %s. The cluster accepted the change, and %s. "+
			"Note this undoes what ARGUS changed — it does not re-diagnose the original problem, which is still there.",
			exec.Description, stateSentence),
	})
}

// jsonEOF is io.EOF, named so the empty-body case reads as intentional: this
// endpoint takes no required fields, so no body at all is a valid request.
var jsonEOF = io.EOF
