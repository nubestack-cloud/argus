package execution

// The thing that finishes what a dead request started.
//
// # What was missing
//
// `Executing` is the one incident state that means "the hub has committed to
// mutating a cluster and a signed plan is in flight". Every other long-lived
// state in this product has something watching it — ValidationSweeper for
// Validating, MergeSweeper for AwaitingMerge, ApprovalSweeper for
// AwaitingApproval, the stale-object sweeper for the rest. Executing had
// nothing, and the stale-object sweeper skips it deliberately, on the stated
// reasoning that "another writer owns the state". That is true while the
// writer is alive and false the moment it is not — which is exactly the case
// worth handling, because internal/orchestrator/state.go's own comment already
// records that an incident can survive a crash here "even though the cluster
// mutation may or may not have actually landed".
//
// The rollback path had the same hole with no state marker at all: it never
// entered Executing, so a hub that died mid-undo left a changed cluster and
// nothing pointing at it.
//
// # What this does
//
// One sweep, two candidate sources, one settlement:
//
//   - Attempts (migration 000093) that are still open past their own expiry.
//     The expiry is the dispatching request's bounded deadline plus a grace
//     margin, so passing it means no live owner can still be working —
//     regardless of how many hub replicas there are, which is why this is a
//     stored deadline rather than a heartbeat or a process id.
//   - Incidents sitting in Executing with no open attempt at all and an
//     approval decision old enough that nothing can still be running. These
//     are the rows that predate the attempt table; without this pass they stay
//     stuck forever, which is precisely the fault being fixed.
//
// # What it concludes, and what it refuses to conclude
//
// `ExecutionUnknown` already exists for "a mutating call happened and we
// cannot tell whether it landed" (BACKLOG.md C8 / BUGS.md 104), and that is
// what this records — never `failed`. A hub that died proves nothing about
// whether the patch reached the API server, and asserting a failure would
// repeat, in a new place, exactly the lie that state was created to stop
// telling.
//
// Where it can do better than a guess, it does: for a forward attempt whose
// cluster is connected, it re-reads the live target and compares it against
// what the plan intended, through the same verifyMutationApplied the
// indeterminate-tunnel-call path uses. A confident match records `succeeded`,
// and the incident validates like any other fix. Everything else is
// `unknown` — reported honestly, not resolved by assumption.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/data"
	"argus/internal/events"
	"argus/internal/logging"
	"argus/internal/metrics"
	"argus/internal/orchestrator"
	"argus/internal/remediation"
)

// DefaultExecutionReconcileInterval is how often cmd/hub sweeps. Short,
// because the whole point is that an incident does not sit in Executing any
// longer than it must; cheap, because a sweep with nothing to do is one
// indexed query against a partial index over open attempts.
const DefaultExecutionReconcileInterval = 30 * time.Second

// executionOrphanGrace is how long an incident must have been Executing, with
// no open attempt, before the orphan pass will conclude anything about it.
// Deliberately much longer than executionDispatchLimit: this pass is for rows
// with no attempt row to read a real deadline from, so it substitutes a
// generous fixed one rather than guessing at a tighter bound.
const executionOrphanGrace = 15 * time.Minute

// maxReconcilePerSweep bounds one pass, the same shape as the stale-object
// sweeper's own cap: each settlement may make a live cluster call, and a
// backlog is better worked through over several ticks than in one long one.
const maxReconcilePerSweep = 25

// RunExecutionReconciler sweeps once immediately and then on every tick until
// ctx is cancelled. Blocks — cmd/hub runs it in its own goroutine, the same
// shape as every other sweeper here.
//
// The immediate pass is not decoration: the case this exists for is a hub that
// died mid-execution, so the most likely moment for there to be work is the
// first seconds after one starts.
func (s *Executor) RunExecutionReconciler(ctx context.Context, interval time.Duration) {
	s.reconcileExecutionsOnce(ctx)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconcileExecutionsOnce(ctx)
		}
	}
}

// reconcileExecutionsOnce is one sweep plus its correlation id (PROJECT.md
// T23) and its duration/last-success metrics (T24). Factored out because
// Run calls it twice — once at startup, once per tick — and a startup sweep
// that reported differently from a ticked one would be its own small lie.
//
// This is the sweeper where a correlation id matters most: it settles
// executions whose dispatcher never came back, which is precisely the
// "what actually happened to my remediation?" question a support ticket
// asks.
func (s *Executor) reconcileExecutionsOnce(ctx context.Context) {
	sweepCtx, _ := logging.NewUnitOfWork(ctx)
	start := time.Now()
	err := s.reconcileExecutions(sweepCtx)
	metrics.ObserveSweeperRun("execution_reconcile", time.Since(start), err)
	if err != nil {
		logger.ErrorContext(sweepCtx, "execution-reconcile sweep failed", logging.Err(err))
	}
}

// abandonedAttempt is one open attempt past its expiry, plus everything
// needed to settle it without asking a cluster what it was doing.
type abandonedAttempt struct {
	ID              string
	TenantID        string
	ClusterID       string
	IncidentID      string
	PlanID          string
	Kind            string
	ActionType      string
	TargetGVK       string
	TargetNamespace string
	TargetName      string
	ForwardApplied  string
	ResourceVersion string
	Rollback        *remediation.CompensatingAction
	Actor           Actor
	SuccessState    string
	StartedAt       time.Time
}

// orphanExecuting is one incident stuck in Executing with no attempt row —
// an execution dispatched before the attempt table existed.
type orphanExecuting struct {
	TenantID   string
	ClusterID  string
	IncidentID string
	PlanID     string
	Actor      Actor
	DecidedAt  time.Time
}

// reconcileExecutions runs one pass.
func (s *Executor) reconcileExecutions(ctx context.Context) error {
	attempts, orphans, err := s.collectUnfinishedExecutions(ctx)
	if err != nil {
		return err
	}
	for _, a := range attempts {
		s.settleAbandonedAttempt(ctx, a)
	}
	for _, o := range orphans {
		s.settleOrphanExecuting(ctx, o)
	}
	return nil
}

// collectUnfinishedExecutions gathers both candidate sets in one short
// transaction, then releases it — the same shape as the stale-object sweeper's
// own collector, and for the same reason: nothing that follows may run inside
// a transaction held open across a tunnel call.
func (s *Executor) collectUnfinishedExecutions(ctx context.Context) ([]abandonedAttempt, []orphanExecuting, error) {
	var attempts []abandonedAttempt
	var orphans []orphanExecuting
	if err := data.InFleetScope(ctx, s.db.Pool, func(ctx context.Context, tx pgx.Tx, tenantID string) error {
		var err error
		if attempts, err = collectAbandonedAttempts(ctx, tx); err != nil {
			return err
		}
		if orphans, err = collectOrphanExecuting(ctx, tx, tenantID); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, nil, err
	}
	return attempts, orphans, nil
}

func collectAbandonedAttempts(ctx context.Context, tx pgx.Tx) ([]abandonedAttempt, error) {
	rows, err := tx.Query(ctx,
		`SELECT id, tenant_id, cluster_id, incident_id, recommendation_id, kind, action_type,
		        target_gvk, target_namespace, target_name,
		        COALESCE(forward_applied_value, ''), COALESCE(resource_version_precondition, ''),
		        rollback_action_type, rollback_params, rollback_description,
		        actor_id, actor_auth_method, COALESCE(actor_source_ip, ''), COALESCE(actor_reason, ''), unattended,
		        COALESCE(success_state, ''), started_at
		   FROM remediation_execution_attempts
		  WHERE settled_at IS NULL AND expires_at < now()
		  ORDER BY expires_at ASC
		  LIMIT $1`, maxReconcilePerSweep)
	if err != nil {
		return nil, fmt.Errorf("select abandoned execution attempts: %w", err)
	}
	defer rows.Close()

	var out []abandonedAttempt
	for rows.Next() {
		var a abandonedAttempt
		var rollbackActionType, rollbackDescription, actorID *string
		var rollbackParams []byte
		if err := rows.Scan(&a.ID, &a.TenantID, &a.ClusterID, &a.IncidentID, &a.PlanID, &a.Kind, &a.ActionType,
			&a.TargetGVK, &a.TargetNamespace, &a.TargetName, &a.ForwardApplied, &a.ResourceVersion,
			&rollbackActionType, &rollbackParams, &rollbackDescription,
			&actorID, &a.Actor.AuthMethod, &a.Actor.SourceIP, &a.Actor.Reason, &a.Actor.Unattended,
			&a.SuccessState, &a.StartedAt); err != nil {
			return nil, fmt.Errorf("scan abandoned execution attempt: %w", err)
		}
		a.Actor.UserID = deref(actorID)
		if rollbackActionType != nil {
			a.Rollback = &remediation.CompensatingAction{
				ActionType:  remediation.ActionType(*rollbackActionType),
				Params:      rollbackParams,
				Description: deref(rollbackDescription),
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// collectOrphanExecuting finds incidents in Executing that no open attempt
// explains and whose approval is old enough that nothing can still be running.
//
// The clock is the approval decision, not a state-change timestamp: incidents
// has no "when did it enter this state" column, and the approved decision row
// is written in the SAME transaction as AwaitingApproval -> Executing
// (recordExecutingTransition), so it is exactly that instant.
func collectOrphanExecuting(ctx context.Context, tx pgx.Tx, tenantID string) ([]orphanExecuting, error) {
	rows, err := tx.Query(ctx,
		`SELECT i.id, i.cluster_id, d.recommendation_id, d.actor_id, d.unattended, d.created_at
		   FROM incidents i
		   JOIN LATERAL (
		          SELECT recommendation_id, actor_id, unattended, created_at
		            FROM remediation_approval_decisions
		           WHERE incident_id = i.id AND verdict = 'approved'
		           ORDER BY created_at DESC
		           LIMIT 1
		        ) d ON true
		  WHERE i.state = $1
		    AND d.created_at < now() - ($2 * interval '1 second')
		    AND NOT EXISTS (
		          SELECT 1 FROM remediation_execution_attempts a
		           WHERE a.incident_id = i.id AND a.settled_at IS NULL)
		    -- No outcome was ever recorded for this approval. Stricter than
		    -- "no open attempt", and the condition that actually matters: it is
		    -- what stops a second, duplicate execution row being written for an
		    -- incident that did record an outcome but whose state transition
		    -- was refused for some other reason.
		    AND NOT EXISTS (
		          SELECT 1 FROM remediation_executions x
		           WHERE x.incident_id = i.id AND x.executed_at >= d.created_at)
		  ORDER BY d.created_at ASC
		  LIMIT $3`,
		orchestrator.StateExecuting, executionOrphanGrace.Seconds(), maxReconcilePerSweep)
	if err != nil {
		return nil, fmt.Errorf("select orphaned Executing incidents: %w", err)
	}
	defer rows.Close()

	var out []orphanExecuting
	for rows.Next() {
		o := orphanExecuting{TenantID: tenantID}
		var actorID *string
		if err := rows.Scan(&o.IncidentID, &o.ClusterID, &o.PlanID, &actorID, &o.Actor.Unattended, &o.DecidedAt); err != nil {
			return nil, fmt.Errorf("scan orphaned Executing incident: %w", err)
		}
		o.Actor.UserID = deref(actorID)
		// The authentication method is not recorded on the decision row, and
		// inventing "jwt" for a row that might have been the autonomy policy's
		// would be a fabricated fact in an audit trail. "recovered" says what
		// is actually true about how this outcome came to be written.
		o.Actor.AuthMethod = "recovered"
		out = append(out, o)
	}
	return out, rows.Err()
}

// settleAbandonedAttempt records the honest outcome of one attempt nobody came
// back for.
func (s *Executor) settleAbandonedAttempt(ctx context.Context, a abandonedAttempt) {
	outcome, execError := s.resolveAbandonedOutcome(ctx, a)

	// Where the incident goes. Succeeded uses the destination the dispatching
	// request decided and stored, so a reconciler cannot reach a different
	// conclusion about the same attempt than the request would have. The other
	// two are only meaningful for a forward execution: an undo leaves the
	// incident alone on anything but success (undoOutcomeStates), and this
	// path must not invent a transition that path deliberately declines.
	states := incidentOutcomeStates{Succeeded: a.SuccessState}
	if a.Kind == executionAttemptForward {
		states.Failed = orchestrator.StateFailed
		states.Unknown = orchestrator.StateExecutionUnknown
	}

	scope := Scope{TenantID: a.TenantID}
	// a.Kind is already exactly one of executionAttemptForward/
	// executionAttemptUndo ("forward"/"undo") — the same two values
	// metrics.RemediationExecutionTotal's "kind" label uses, so no mapping
	// is needed here.
	finalState, err := s.recordExecutionOutcome(ctx, scope, a.IncidentID, a.PlanID, a.ClusterID, a.Actor,
		outcome, execError, a.ResourceVersion, a.Rollback, a.ForwardApplied, states, a.ID, a.ActionType, a.Kind)
	if err != nil {
		if errors.Is(err, errAttemptAlreadySettled) {
			// The dispatching request came back to life and settled first.
			// Nothing to do and nothing wrong: the exactly-once guard did its
			// job, and the request's own answer is the better-informed one.
			logger.InfoContext(ctx, "attempt was settled by its own request while this sweep was running",
				logging.IncidentID(a.IncidentID), logging.ClusterID(a.ClusterID),
				slog.String("attempt_id", a.ID))
			return
		}
		logger.ErrorContext(ctx, "recording the outcome of an abandoned attempt failed",
			logging.IncidentID(a.IncidentID), logging.ClusterID(a.ClusterID),
			slog.String("attempt_id", a.ID), logging.Err(err))
		return
	}
	logger.WarnContext(ctx, "attempt was abandoned by its dispatcher and has been settled by the reconciler",
		logging.IncidentID(a.IncidentID), logging.ClusterID(a.ClusterID),
		slog.String("attempt_id", a.ID), slog.String("kind", a.Kind),
		slog.String("action_type", a.ActionType), slog.Time("started_at", a.StartedAt),
		slog.String("outcome", outcome), slog.String("incident_state", finalState))
	if s.events != nil {
		s.events.Publish(events.IncidentUpdated(a.IncidentID, a.ClusterID))
	}
}

// resolveAbandonedOutcome decides what to record, preferring evidence over
// assumption.
//
// Only a FORWARD attempt is verifiable here, and that limit is stated rather
// than worked around: verifyMutationApplied compares the live object against
// the plan the recommendation stores, which is the right plan for a forward
// execution and the wrong one for an undo (an undo applies a compensating
// action derived from pre-change state, which no recommendation row
// describes). Rather than reconstruct a second, subtly different comparison
// for the rarer case, an abandoned undo is recorded as unknown — the outcome
// that means what it says.
func (s *Executor) resolveAbandonedOutcome(ctx context.Context, a abandonedAttempt) (outcome, execError string) {
	abandoned := fmt.Sprintf("the hub that dispatched this %s did not record an outcome (attempt %s, started %s)",
		a.ActionType, a.ID, a.StartedAt.Format(time.RFC3339))

	if a.Kind != executionAttemptForward {
		return "unknown", abandoned + "; an undo's applied value cannot be re-derived from the stored plan, so whether it landed must be checked on the cluster directly"
	}
	if !s.gw.IsConnected(a.ClusterID) {
		return "unknown", abandoned + "; the cluster is not connected, so ARGUS could not check whether the change landed"
	}

	plan, err := s.loadPlanForReconcile(ctx, a.TenantID, a.PlanID)
	if err != nil {
		logger.ErrorContext(ctx, "re-reading the plan to verify an abandoned attempt failed",
			logging.IncidentID(a.IncidentID), logging.ClusterID(a.ClusterID),
			slog.String("attempt_id", a.ID), slog.String("plan_id", a.PlanID), logging.Err(err))
		return "unknown", abandoned + "; the plan could not be re-read to check whether the change landed"
	}

	_, liveSpec, _, err := s.FetchPreconditionWithObject(ctx, a.ClusterID, a.TargetGVK, a.TargetNamespace, a.TargetName)
	if err != nil {
		return "unknown", abandoned + fmt.Sprintf("; a follow-up read of %s %s/%s to check whether the change landed also failed: %v",
			a.TargetGVK, a.TargetNamespace, a.TargetName, err)
	}

	// prep is reconstructed from what the attempt row stored, which is exactly
	// the subset verifyMutationApplied reads for the three value-carrying
	// action types. LiveObject is deliberately absent: it is a whole
	// Kubernetes object and this table is not where one belongs, which means
	// RestartPod — the one type whose check compares against the pre-change
	// object — cannot be verified here and correctly falls through to unknown.
	matched, matchErr := verifyMutationApplied(plan, PlanPrep{
		TargetGVK: a.TargetGVK, TargetNamespace: a.TargetNamespace, TargetName: a.TargetName,
		ForwardApplied: a.ForwardApplied,
	}, liveSpec)
	if matchErr != nil {
		logger.WarnContext(ctx, "verification comparison errored; treated as inconclusive, never as failure",
			logging.IncidentID(a.IncidentID), logging.ClusterID(a.ClusterID),
			slog.String("attempt_id", a.ID), logging.Err(matchErr))
	}
	if matched {
		return "succeeded", ""
	}
	return "unknown", abandoned + "; a follow-up read could not confirm the change applied — check the cluster directly"
}

// loadPlanForReconcile re-reads a stored recommendation as a plan, in its own
// short transaction. The reconciler has no request transaction to borrow.
func (s *Executor) loadPlanForReconcile(ctx context.Context, tenantID, planID string) (remediation.RemediationPlan, error) {
	var plan remediation.RemediationPlan
	if err := data.InScope(ctx, s.db.Pool, tenantID, nil, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		plan, err = LoadRecommendationPlan(ctx, tx, planID)
		return err
	}); err != nil {
		return remediation.RemediationPlan{}, err
	}
	return plan, nil
}

// settleOrphanExecuting closes out an incident that entered Executing before
// attempts were recorded at all.
//
// It records unknown and nothing else. There is no attempt row, so there is
// no target, no applied value, and no precondition to verify against — the
// only truthful statement available is the one ExecutionUnknown exists to
// make.
func (s *Executor) settleOrphanExecuting(ctx context.Context, o orphanExecuting) {
	execError := fmt.Sprintf("this incident was left in %s with no record of how the execution ended; it was approved at %s and no hub recorded an outcome",
		orchestrator.StateExecuting, o.DecidedAt.Format(time.RFC3339))

	scope := Scope{TenantID: o.TenantID}
	// actionType is honestly "unknown" here, not a fabricated default —
	// see this function's own doc comment: there is no attempt row at all
	// for an orphaned Executing incident, so there is nothing to read a
	// real action type from. forwardOutcomeStates() (used just below)
	// pins this as shaped like a forward execution, never an undo.
	finalState, err := s.recordExecutionOutcome(ctx, scope, o.IncidentID, o.PlanID, o.ClusterID, o.Actor,
		"unknown", execError, "", nil, "", forwardOutcomeStates(), "", "unknown", "forward")
	if err != nil {
		logger.ErrorContext(ctx, "recording the outcome of an orphaned Executing incident failed",
			logging.IncidentID(o.IncidentID), logging.ClusterID(o.ClusterID), logging.Err(err))
		return
	}
	logger.WarnContext(ctx, "incident had been Executing with no attempt record; recorded as unknown",
		logging.IncidentID(o.IncidentID), logging.ClusterID(o.ClusterID),
		slog.Time("executing_since", o.DecidedAt), slog.String("incident_state", finalState))
	if s.events != nil {
		s.events.Publish(events.IncidentUpdated(o.IncidentID, o.ClusterID))
	}
}
