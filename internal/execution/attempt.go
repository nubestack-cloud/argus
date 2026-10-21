package execution

// The durable record that a cluster is about to be changed, and the rules for
// where an incident goes once it has been.
//
// # The gap this closes
//
// Both halves of the execution path used to make the same assumption: that the
// same in-process request that committed to a mutation would still be alive to
// record what happened. Neither is entitled to it.
//
//   - The approve path commits AwaitingApproval -> Executing in its own
//     transaction, calls the tunnel, and writes the outcome in a second one. A
//     client disconnect cancels r.Context() the instant the connection closes,
//     and an already-cancelled context makes every pgx operation fail
//     immediately (internal/api/analyze_detach_db_test.go proved exactly this
//     against a live Postgres for BUGS.md 89); a hub that dies has the same
//     effect with none of the warning. Either way nothing writes the outcome,
//     and the incident sits in Executing, which nothing reconciles — the
//     stale-object sweeper excludes it on the stated reasoning that "another
//     writer owns the state," which is true only while that writer exists.
//
//   - The rollback path never entered Executing at all, so it did not even
//     have that marker: its pre-mutation record was an audit event, which is
//     durable but is not a row anything queries for unfinished work.
//
// # The mechanism
//
// One attempt row, written in the same transaction that commits to the change
// and strictly before the tunnel call, and settled in the same transaction
// that records the outcome. Between those two points the row is the product's
// only honest statement about a cluster it may have changed, and after the
// second it is history.
//
// Settling is exactly-once by construction (the UPDATE carries
// `settled_at IS NULL`), so a request that comes back to life after the
// reconciler has already concluded cannot write a second execution row for the
// same attempt.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"argus/internal/orchestrator"
	"argus/internal/remediation"
)

const (
	// executionAttemptForward is an approved plan being applied.
	executionAttemptForward = "forward"
	// executionAttemptUndo is a compensating action being replayed by the
	// rollback endpoint. Settles differently — see undoOutcomeStates.
	executionAttemptUndo = "undo"
)

// WorkLimit bounds the whole detached execution once a request has
// been accepted: target resolution, the dry-run rehearsal and any bounded
// param correction, the tunnel call, and the outcome write. It is a safety
// net rather than the operative bound — every stage inside it already has its
// own, much shorter timeout — and exists so that "detached from the request"
// can never mean "unbounded", the same shape internal/api/analyze.go's
// detached investigation uses.
const WorkLimit = 10 * time.Minute

// executionDispatchLimit bounds the part that actually matters for recovery:
// everything from the commit-to-executing transaction, through the mutating
// tunnel call, to the outcome being written. The gateway's own budget for one
// mutating call is toolCallTimeout + resultGraceWindow (12s + 5s), and an
// indeterminate result buys one follow-up read of the same size, so this is
// roughly three times the worst case anything here can legitimately take.
//
// It is deliberately short: an attempt cannot be reconciled until it elapses,
// so it is also the floor on how long a crashed hub leaves an incident
// unresolved.
const executionDispatchLimit = 90 * time.Second

// executionAttemptGrace is added to the dispatching context's own deadline to
// get the instant past which no live owner can still be working on an
// attempt. It covers the gap between a context's deadline firing and the
// owner's outcome write actually committing.
const executionAttemptGrace = 60 * time.Second

// errAttemptAlreadySettled is returned when the exactly-once settle finds the
// attempt already closed — a reconciler concluded first. The caller must not
// write a second execution row for the same attempt; it reports what it
// observed instead.
var errAttemptAlreadySettled = errors.New("this execution attempt has already been settled")

// executionAttempt is one durable "a cluster is about to be changed" record.
// Field-for-field the subset of an execution that has to survive the process
// that started it — see migration 000093 for why each column is here.
type executionAttempt struct {
	ID         string
	TenantID   string
	ClusterID  string
	IncidentID string
	PlanID     string

	Kind       string
	ActionType string

	TargetGVK       string
	TargetNamespace string
	TargetName      string

	ForwardApplied  string
	ResourceVersion string
	Rollback        *remediation.CompensatingAction

	// UndoOfExecutionID is set only for Kind == executionAttemptUndo.
	UndoOfExecutionID string

	Actor Actor

	// SuccessState is where the incident goes if this attempt turns out to
	// have succeeded, or "" for "leave its state alone".
	SuccessState string

	ExpiresAt time.Time
}

// attemptExpiry is the instant past which no live owner can still be working
// on an attempt dispatched under ctx: ctx's own deadline plus the grace
// margin. A context with no deadline (the unattended sweeper runs on the hub's
// root context) falls back to the same bound a request would have had, so an
// attempt always carries a real expiry rather than a NULL a reader has to
// interpret.
func attemptExpiry(ctx context.Context) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline.Add(executionAttemptGrace)
	}
	return time.Now().Add(executionDispatchLimit + executionAttemptGrace)
}

// insertExecutionAttempt writes the attempt. Always called on a transaction
// the caller commits BEFORE the mutation it describes — that ordering is the
// whole property, and it is the caller's to keep.
func insertExecutionAttempt(ctx context.Context, tx pgx.Tx, a executionAttempt) error {
	var rollbackActionType, rollbackDescription *string
	var rollbackParams []byte
	if a.Rollback != nil {
		at := string(a.Rollback.ActionType)
		rollbackActionType = &at
		rollbackParams = a.Rollback.Params
		rollbackDescription = nullIfEmpty(a.Rollback.Description)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO remediation_execution_attempts
		   (id, tenant_id, cluster_id, incident_id, recommendation_id, kind, action_type,
		    target_gvk, target_namespace, target_name, forward_applied_value, resource_version_precondition,
		    rollback_action_type, rollback_params, rollback_description, undo_of_execution_id,
		    actor_id, actor_auth_method, actor_source_ip, actor_reason, unattended,
		    success_state, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23)`,
		a.ID, a.TenantID, a.ClusterID, a.IncidentID, a.PlanID, a.Kind, a.ActionType,
		a.TargetGVK, a.TargetNamespace, a.TargetName, nullIfEmpty(a.ForwardApplied), nullIfEmpty(a.ResourceVersion),
		rollbackActionType, rollbackParams, rollbackDescription, nullIfEmpty(a.UndoOfExecutionID),
		a.Actor.ActorIDOrNil(), a.Actor.AuthMethod, nullIfEmpty(a.Actor.SourceIP), nullIfEmpty(a.Actor.Reason), a.Actor.Unattended,
		nullIfEmpty(a.SuccessState), a.ExpiresAt); err != nil {
		return fmt.Errorf("record execution attempt: %w", err)
	}
	return nil
}

// settleExecutionAttempt closes one attempt, exactly once. Called inside
// recordExecutionOutcome's transaction, so an attempt and the execution row
// that explains it are committed together or not at all.
//
// It also carries the undo link. "Has this execution been rolled back, and by
// what?" is a fact that belongs on the row, and writing it here means both the
// request path and the reconciler record it identically, atomically with the
// undo's own outcome. The previous implementation matched the undo by "the
// newest execution on this incident", in a separate best-effort transaction —
// which is a guess, and one that names the wrong row as soon as anything else
// executes against the same incident in between.
//
// Linked ONLY on a succeeded undo. An undo whose result could not be confirmed
// has not undone anything that can be asserted, and claiming otherwise would
// make the next undo refuse with "already rolled back" on the strength of
// something nobody established.
func settleExecutionAttempt(ctx context.Context, tx pgx.Tx, attemptID, executionID, outcome string) error {
	var kind string
	var undoOf *string
	err := tx.QueryRow(ctx,
		`UPDATE remediation_execution_attempts
		    SET settled_at = now(), execution_id = $2
		  WHERE id = $1 AND settled_at IS NULL
		  RETURNING kind, undo_of_execution_id`, attemptID, executionID).Scan(&kind, &undoOf)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: attempt %s", errAttemptAlreadySettled, attemptID)
	}
	if err != nil {
		return fmt.Errorf("settle execution attempt %s: %w", attemptID, err)
	}
	if kind == executionAttemptUndo && outcome == "succeeded" && undoOf != nil && *undoOf != "" {
		if _, err := tx.Exec(ctx,
			`UPDATE remediation_executions SET rolled_back_by_execution_id = $2 WHERE id = $1`,
			*undoOf, executionID); err != nil {
			return fmt.Errorf("link undo of execution %s: %w", *undoOf, err)
		}
	}
	return nil
}

// incidentOutcomeStates says where an incident goes for each outcome
// recordExecutionOutcome can record. An empty destination means "leave the
// incident's state exactly where it is", which is a real answer and not a
// missing one — see undoOutcomeStates for the case that needs it.
//
// It replaced a single `successState string` parameter, which hardcoded
// Failed for every non-success. That was correct for a forward execution,
// where the incident is always Executing and Executing -> Failed is a legal
// edge, and wrong for every rollback, where it is not.
type incidentOutcomeStates struct {
	Succeeded string
	Failed    string
	Unknown   string
}

// forOutcome maps one of remediation_executions.outcome's three values to a
// destination. Anything other than "succeeded"/"unknown" is a failure, which
// matches the CHECK constraint's third value and fails toward the more
// alarming reading for any value that somehow is not one of the three.
func (p incidentOutcomeStates) forOutcome(outcome string) string {
	switch outcome {
	case "succeeded":
		return p.Succeeded
	case "unknown":
		return p.Unknown
	default:
		return p.Failed
	}
}

// forwardOutcomeStates is the approve/execute path's destinations, unchanged
// from what this codebase has always done: a successful patch is watched
// (Validating), a refused one is Failed with the real reason persisted, and an
// indeterminate one is ExecutionUnknown rather than a false Failed
// (StateExecutionUnknown's own doc comment).
func forwardOutcomeStates() incidentOutcomeStates {
	return incidentOutcomeStates{
		Succeeded: orchestrator.StateValidating,
		Failed:    orchestrator.StateFailed,
		Unknown:   orchestrator.StateExecutionUnknown,
	}
}

// undoOutcomeStates decides what a rollback does to the incident, from the
// state the incident is actually in when the undo settles.
//
// # Only one starting state gets a transition, and that is deliberate
//
// An undo is a statement about the CLUSTER — "the change ARGUS made has been
// taken back" — not about where the incident is in its investigation
// lifecycle. Reopening a Detected incident, or dragging a closed one back into
// the open set, would be inventing a lifecycle event nobody asked for.
//
// Validating is the exception, and it is the one that matters: it means "a fix
// was applied and ARGUS is watching whether the symptom stays away". Leaving
// an incident there after removing the fix would let the validation sweeper
// promote it to Resolved on the strength of a grace period that started when
// the fix was still in place — reporting a successful remediation for a change
// that is no longer on the cluster. Reopened is the honest destination and the
// one legal edge that means "still broken".
//
// # A failed or indeterminate undo changes nothing, ever
//
// The old code mapped every non-success to Failed. For a rollback that is two
// untruths at once: Validating -> Failed is not a legal edge, so the record
// was lost outright; and Failed asserts that the REMEDIATION failed, when in
// fact it succeeded and is still applied — it was the attempt to take it back
// that did not work. The incident is exactly where it was, so it stays there,
// and the failure is recorded where failures belong: on the execution row,
// the timeline, and the audit trail.
func undoOutcomeStates(current string) incidentOutcomeStates {
	if current == orchestrator.StateValidating {
		return incidentOutcomeStates{Succeeded: orchestrator.StateReopened}
	}
	return incidentOutcomeStates{}
}
